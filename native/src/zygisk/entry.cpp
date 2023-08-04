#include <libgen.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <android/log.h>
#include <android/dlext.h>
#include <resetprop.hpp>

#include <base.hpp>
#include <daemon.hpp>
#include <magisk.hpp>
#include <selinux.hpp>

#include "zygisk.hpp"
#include "module.hpp"
#include "deny/deny.hpp"
#include "native_bridge_callbacks.h"

using namespace std;

void *self_handle = nullptr;

[[gnu::destructor]] [[maybe_unused]]
static void zygisk_cleanup_wait() {
    if (self_handle) {
        // Wait 10us to make sure none of our code is executing
        timespec ts = { .tv_sec = 0, .tv_nsec = 10000L };
        nanosleep(&ts, nullptr);
    }
}

extern "C" __used void* zygisk_inject_entry(void *handle, void *callbacks) {
    zygisk_logging();
    ZLOGD("load success\n");
    self_handle = handle;
    void *orig_bridge = nullptr;

    do {
        int fd = zygisk_request(ZygiskRequest::SETUP);
        if (fd < 0 || read_int(fd)) {
            ZLOGE("failed to connect to daemon\n");
            exit(1);
            break;
        }

        MAGISKTMP = read_string(fd);
        ZLOGD("read magisktmp %s\n", MAGISKTMP.c_str());
        auto orig_bridge_name = read_string(fd);
        auto bak_bridge_name = read_string(fd);
        int sdk = read_int(fd);
        sulist_enabled = (bool)read_int(fd);
        close(fd);

        if (sulist_enabled) {
            LOGI("** Enable Zygisk SuList\n");
        }

        if (orig_bridge_name.empty()) {
            ZLOGE("failed to read orig bridge name\n");
            break;
        }

        if (bak_bridge_name != "0")
            orig_bridge_name = bak_bridge_name;

        if (orig_bridge_name == "0") {
            break;
        }
        ZLOGD("original native bridge: %s\n", orig_bridge_name.data());

        orig_bridge = dlopen(orig_bridge_name.data(), RTLD_NOW);
        if (orig_bridge == nullptr) {
            ZLOGE("dlopen failed: %s\n", dlerror());
            break;
        }
        auto *original_native_bridge_itf = dlsym(orig_bridge, "NativeBridgeItf");
        if (original_native_bridge_itf == nullptr) {
            ZLOGE("dlsym failed: %s\n", dlerror());
            break;
        }

        auto callbacks_size = 0;
        if (sdk >= __ANDROID_API_R__) {
            callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_R__>);
        } else if (sdk == __ANDROID_API_Q__) {
            callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_Q__>);
        } else if (sdk == __ANDROID_API_P__) {
            callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_P__>);
        } else if (sdk == __ANDROID_API_O_MR1__) {
            callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_O_MR1__>);
        } else if (sdk == __ANDROID_API_O__) {
            callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_O__>);
        } else if (sdk == __ANDROID_API_N_MR1__) {
            callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_N_MR1__>);
        } else if (sdk == __ANDROID_API_N__) {
            callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_N__>);
        } else if (sdk == __ANDROID_API_M__) {
            callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_M__>);
        }

        memcpy(callbacks, original_native_bridge_itf, callbacks_size);
    } while (false);

    hook_functions();
    return orig_bridge;
}

// The following code runs in zygote/app process

extern "C" void zygisk_log_write(int prio, const char *msg, int len) {
    // If we don't have the log pipe set, request magiskd for it. This could actually happen
    // multiple times in the zygote daemon (parent process) because we had to close this
    // file descriptor to prevent crashing.
    //
    // For some reason, zygote sanitizes and checks FDs *before* forking. This results in the fact
    // that *every* time before zygote forks, it has to close all logging related FDs in order
    // to pass FD checks, just to have it re-initialized immediately after any
    // logging happens ¯\_(?)_/¯.
    //
    // To be consistent with this behavior, we also have to close the log pipe to magiskd
    // to make zygote NOT crash if necessary. For nativeForkAndSpecialize, we can actually
    // add this FD into fds_to_ignore to pass the check. For other cases, we accomplish this by
    // hooking __android_log_close and closing it at the same time as the rest of logging FDs.

    if (logd_fd < 0) {
        android_logging();
        if (int fd = zygisk_request(ZygiskRequest::GET_LOG_PIPE); fd >= 0) {
            int log_pipe = -1;
            if (read_int(fd) == 0) {
                log_pipe = recv_fd(fd);
            }
            close(fd);
            if (log_pipe >= 0) {
                // Only re-enable zygisk logging if possible
                logd_fd = log_pipe;
                zygisk_logging();
            }
        } else {
            return;
        }
    }

    // Block SIGPIPE
    sigset_t mask;
    sigset_t orig_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &mask, &orig_mask);

    magisk_log_write(prio, msg, len);

    // Consume SIGPIPE if exists, then restore mask
    timespec ts{};
    sigtimedwait(&mask, nullptr, &ts);
    pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);
}

static inline bool should_load_modules(uint32_t flags) {
    return (flags & PROCESS_IS_MAGISK_APP) != PROCESS_IS_MAGISK_APP;
}

int remote_get_info(int uid, const char *process, uint32_t *flags, vector<int> &fds) {
    if (int fd = zygisk_request(ZygiskRequest::GET_INFO); fd >= 0) {
        write_int(fd, uid);
        write_string(fd, process);
        xxread(fd, flags, sizeof(*flags));
        if (should_load_modules(*flags)) {
            fds = recv_fds(fd);
        }
        return fd;
    }
    return -1;
}

// The following code runs in magiskd

static vector<int> get_module_fds(bool is_64_bit) {
    vector<int> fds;
    // All fds passed to send_fds have to be valid file descriptors.
    // To workaround this issue, send over STDOUT_FILENO as an indicator of an
    // invalid fd as it will always be /dev/null in magiskd
    if (is_64_bit) {
#if defined(__LP64__)
        std::transform(module_list->begin(), module_list->end(), std::back_inserter(fds),
            [](const module_info &info) { return info.z64 < 0 ? STDOUT_FILENO : info.z64; });
#endif
    } else {
        std::transform(module_list->begin(), module_list->end(), std::back_inserter(fds),
            [](const module_info &info) { return info.z32 < 0 ? STDOUT_FILENO : info.z32; });
    }
    return fds;
}

static bool get_exe(int pid, char *buf, size_t sz) {
    char exe[128];
    if (ssprintf(exe, sizeof(exe), "/proc/%d/exe", pid) < 0)
        return false;
    return xreadlink(exe, buf, sz) > 0;
}

static pthread_mutex_t zygiskd_lock = PTHREAD_MUTEX_INITIALIZER;
static int zygiskd_sockets[] = { -1, -1 };
#define zygiskd_socket zygiskd_sockets[is_64_bit]

static void connect_companion(int client, bool is_64_bit) {
    mutex_guard g(zygiskd_lock);

    if (zygiskd_socket >= 0) {
        // Make sure the socket is still valid
        pollfd pfd = { zygiskd_socket, 0, 0 };
        poll(&pfd, 1, 0);
        if (pfd.revents) {
            // Any revent means error
            close(zygiskd_socket);
            zygiskd_socket = -1;
        }
    }
    if (zygiskd_socket < 0) {
        int fds[2];
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds);
        zygiskd_socket = fds[0];
        if (fork_dont_care() == 0) {
            string exe = MAGISKTMP + "/magisk" + (is_64_bit ? "64" : "32");
            // This fd has to survive exec
            fcntl(fds[1], F_SETFD, 0);
            char buf[16];
            ssprintf(buf, sizeof(buf), "%d", fds[1]);
            execl(exe.data(), "", "zygisk", "companion", buf, (char *) nullptr);
            exit(-1);
        }
        close(fds[1]);
        vector<int> module_fds = get_module_fds(is_64_bit);
        send_fds(zygiskd_socket, module_fds.data(), module_fds.size());
        // Wait for ack
        if (read_int(zygiskd_socket) != 0) {
            LOGE("zygiskd startup error\n");
            return;
        }
    }
    send_fd(zygiskd_socket, client);
}

static timespec last_zygote_start;
static int zygote_start_counts[] = { 0, 0 };
#define zygote_start_count zygote_start_counts[is_64_bit]
#define zygote_started (zygote_start_counts[0] + zygote_start_counts[1])
#define zygote_start_reset(val) { zygote_start_counts[0] = val; zygote_start_counts[1] = val; }

static void set_native_bridge() {
    if (!nb_replace_lib.empty() && nb_replace_lib != "0"){
        setprop(NATIVE_BRIDGE_PROP, nb_replace_lib.data(), false);
    } else {
        setprop(NATIVE_BRIDGE_PROP, LOADER_LIB, false);
    }
    ZLOGD("native bridge has been set\n");
}

static void reset_native_bridge() {
    setprop(NATIVE_BRIDGE_PROP, orig_native_bridge.data(), false);
    ZLOGD("native bridge has been reset\n");
}

void on_zygote_restart() {
    if (zygote_start_counts[0] >= 5 || zygote_start_counts[1] >= 5) {
        // Bootloop prevention
        timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if (ts.tv_sec - last_zygote_start.tv_sec > 60) {
            // This is very likely manual soft reboot
            memcpy(&last_zygote_start, &ts, sizeof(ts));
            zygote_start_reset(0);
        } else {
            // If any zygote relaunched more than 5 times within a minute,
            // don't do any setups further to prevent bootloop.
            zygote_start_reset(999);
            LOGW("Zygote has restarted too much times, temporary disable zygisk\n");
            return;
        }
    }
    set_native_bridge();
}

static void setup(int client, const sock_cred *cred) {
    LOGD("zygisk: setup for pid=[%d]\n", cred->pid);

    char buf[4096];
    if (!get_exe(cred->pid, buf, sizeof(buf))) {
        write_int(client, 1);
        return;
    }

    bool is_64_bit = str_ends(buf, "64");

    if (!zygote_started) {
        // First zygote launch, record time
        clock_gettime(CLOCK_MONOTONIC, &last_zygote_start);
    }

    if (zygote_start_count) {
        // This zygote ABI had started before, kill existing zygiskd
        close(zygiskd_sockets[0]);
        close(zygiskd_sockets[1]);
        zygiskd_sockets[0] = -1;
        zygiskd_sockets[1] = -1;
    }
    ++zygote_start_count;

    write_int(client, 0);
    write_string(client, MAGISKTMP);
    write_string(client, orig_native_bridge);
    write_string(client, nb_replace_bak);
    write_int(client, SDK_INT);
    write_int(client, (sulist_enabled)? 1 : 0);
}

extern bool uid_granted_root(int uid);
static void get_process_info(int client, const sock_cred *cred) {
    int uid = read_int(client);
    string process = read_string(client);

    uint32_t flags = 0;

    check_pkg_refresh();
    if (is_deny_target(uid, process)) {
        flags |= (sulist_enabled)? PROCESS_ON_ALLOWLIST : PROCESS_ON_DENYLIST;
    }
    int manager_app_id = get_manager();
    if (to_app_id(uid) == manager_app_id) {
        flags |= PROCESS_IS_MAGISK_APP;
    }
    if (!sulist_enabled && denylist_enforced) {
        flags |= MAGISKHIDE_ENABLED;
    }
    if (uid_granted_root(uid)) {
        flags |= PROCESS_GRANTED_ROOT;
    }

    xwrite(client, &flags, sizeof(flags));

    if (should_load_modules(flags)) {
        char buf[256];
        if (!get_exe(cred->pid, buf, sizeof(buf))) {
            LOGW("zygisk: remote process %d probably died, abort\n", cred->pid);
            send_fd(client, -1);
            return;
        }
        vector<int> fds = get_module_fds(str_ends(buf, "64"));
        send_fds(client, fds.data(), fds.size());
    }

    if (uid != 1000 || process != "system_server")
        return;

    // Collect module status from system_server
    int slots = read_int(client);
    dynamic_bitset bits;
    for (int i = 0; i < slots; ++i) {
        dynamic_bitset::slot_type l = 0;
        xxread(client, &l, sizeof(l));
        bits.emplace_back(l);
    }
    for (int id = 0; id < module_list->size(); ++id) {
        if (!as_const(bits)[id]) {
            // Either not a zygisk module, or incompatible
            char buf[4096];
            ssprintf(buf, sizeof(buf), MODULEROOT "/%s/zygisk",
                module_list->operator[](id).name.data());
            if (int dirfd = open(buf, O_RDONLY | O_CLOEXEC); dirfd >= 0) {
                close(xopenat(dirfd, "unloaded", O_CREAT | O_RDONLY, 0644));
                close(dirfd);
            }
        }
    }
}

static void send_log_pipe(int fd) {
    // There is race condition here, but we can't really do much about it...
    if (logd_fd >= 0) {
        write_int(fd, 0);
        send_fd(fd, logd_fd);
    } else {
        write_int(fd, 1);
    }
}

static void get_moddir(int client) {
    int id = read_int(client);
    char buf[4096];
    ssprintf(buf, sizeof(buf), MODULEROOT "/%s", module_list->operator[](id).name.data());
    int dfd = xopen(buf, O_RDONLY | O_CLOEXEC);
    send_fd(client, dfd);
    close(dfd);
}

static void system_server_listener(int pid) {
    char buf1[128];
    char buf2[128];
    ssprintf(buf1, sizeof(buf1), "/proc/%d/cmdline", pid);
    for (int i = 0; i < 60; i++) {
        sleep(1);
        int fd = xopen(buf1, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            ZLOGE("system server %d maybe died\n", pid);
            return;
        }
        xread(fd, buf2, sizeof(buf2));
        close(fd);
        if (strncmp(buf2, "system_server", sizeof("system_server")) == 0) {
            ZLOGD("system server %d started\n", pid);
            reset_native_bridge();
            return;
        }
    }
    LOGW("zygisk: cannot detect system server %d start\n", pid);
}

static void zygote_listener(int fd) {
    nice(18);
    struct flock lock {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };
    while (fcntl(fd, F_SETLKW, &lock) < 0) {
        if (errno == EINTR) continue;
        else {
            PLOGE("get wr lock %d\n", fd);
            close(fd);
            return;
        }
    }
    on_zygote_restart();
    close(fd);
    LOGW("zygisk: zygote maybe died\n");
}

static void on_system_server_forked(int client, int pid) {
    if (sulist_enabled) {
        unmount_zygote();
    }
    char buf[4096];
    ssprintf(buf, sizeof(buf), "%s/%s/%d", MAGISKTMP.data(), ZYGISKBIN, pid);

    int ss_pid = read_int(client);
    new_daemon_thread(reinterpret_cast<thread_entry>(system_server_listener), reinterpret_cast<void*>(ss_pid));

    int fd1 = xopen(buf, O_CREAT | O_RDONLY | O_CLOEXEC);
    send_fd(client, fd1);
    close(fd1);
    // wait remote set read lock
    if (read_int(client)) {
        ZLOGE("remote failed to get lock\n");
        return;
    }

    int fd2 = xopen(buf, O_WRONLY | O_CLOEXEC);
    unlink(buf);
    new_daemon_thread(reinterpret_cast<thread_entry>(zygote_listener), reinterpret_cast<void*>(fd2));
}

void zygisk_handler(int client, const sock_cred *cred) {
    int code = read_int(client);
    char buf[256];
    switch (code) {
    case ZygiskRequest::GET_INFO:
        get_process_info(client, cred);
        break;
    case ZygiskRequest::GET_LOG_PIPE:
        send_log_pipe(client);
        break;
    case ZygiskRequest::CONNECT_COMPANION:
        if (get_exe(cred->pid, buf, sizeof(buf))) {
            connect_companion(client, str_ends(buf, "64"));
        } else {
            LOGW("zygisk: remote process %d probably died, abort\n", cred->pid);
        }
        break;
    case ZygiskRequest::GET_MODDIR:
        get_moddir(client);
        break;
    case ZygiskRequest::SETUP:
        setup(client, cred);
        break;
    case ZygiskRequest::SYSTEM_SERVER_FORKED:
        on_system_server_forked(client, cred->pid);
        break;
    default:
        // Unknown code
        break;
    }
    close(client);
}
