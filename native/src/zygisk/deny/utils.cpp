#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <set>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <vector>
#include <bitset>
#include <string>
#include <cinttypes>
#include <poll.h>
#include <sys/syscall.h>

#include <daemon.hpp>
#include <magisk.hpp>
#include <base.hpp>
#include <db.hpp>
#include <resetprop.hpp>
#include <selinux.hpp>

#include "deny.hpp"
#include <sys/ptrace.h>


#define SNET_PROC    "com.google.android.gms.unstable"
#define GMS_PKG      "com.google.android.gms"

using namespace std;

atomic_flag skip_pkg_rescan;

atomic_flag *p_skip_pkg_rescan = &skip_pkg_rescan;

// For the following data structures:
// If package name == ISOLATED_MAGIC, or app ID == -1, it means isolated service

// Package name -> list of process names
static unique_ptr<map<string, set<string, StringCmp>, StringCmp>> pkg_to_procs_;
#define pkg_to_procs (*pkg_to_procs_)

// app ID -> list of pkg names (string_view points to a pkg_to_procs key)
static unique_ptr<map<int, set<string_view>>> app_id_to_pkgs_;
#define app_id_to_pkgs (*app_id_to_pkgs_)

// Locks the data structures above
static pthread_mutex_t data_lock = PTHREAD_MUTEX_INITIALIZER;

atomic<bool> denylist_enforced = false;

static const char *table_name = "hidelist";

// Process monitoring
pthread_t monitor_thread;
void proc_monitor();
static bool monitoring = false;
static int fork_pid = 0;
static void do_scan_zygote();
static int parse_ppid(int pid);
static bool check_process(int pid, const char *process = 0, const char *context = 0, const char *exe = 0);
#define do_kill (denylist_enforced)

static void rescan_apps() {
    LOGD("hide: rescanning apps\n");

    app_id_to_pkgs.clear();

    struct stat st{};

    auto data_dir = xopen_dir(APP_DATA_DIR);
    if (!data_dir)
        return;
    dirent *entry;
    while ((entry = xreaddir(data_dir.get()))) {
        // For each user
        int dfd = xopenat(dirfd(data_dir.get()), entry->d_name, O_RDONLY);
        if (auto dir = xopen_dir(dfd)) {
            while ((entry = xreaddir(dir.get()))) {
                // For each package
                struct stat st{};
                xfstatat(dfd, entry->d_name, &st, 0);
                int app_id = to_app_id(st.st_uid);
                if (auto it = pkg_to_procs.find(entry->d_name); it != pkg_to_procs.end()) {
                    app_id_to_pkgs[app_id].insert(it->first);
                }
            }
        } else {
            close(dfd);
        }
    }
}

static void update_pkg_uid(const string &pkg, bool remove) {
    auto data_dir = xopen_dir(APP_DATA_DIR);
    if (!data_dir)
        return;
    dirent *entry;
    struct stat st{};
    char buf[PATH_MAX] = {0};
    // For each user
    while ((entry = xreaddir(data_dir.get()))) {
        ssprintf(buf, sizeof(buf), "%s/%s", entry->d_name, pkg.data());
        if (fstatat(dirfd(data_dir.get()), buf, &st, 0) == 0) {
            int app_id = to_app_id(st.st_uid);
            if (remove) {
                if (auto it = app_id_to_pkgs.find(app_id); it != app_id_to_pkgs.end()) {
                    it->second.erase(pkg);
                    if (it->second.empty()) {
                        app_id_to_pkgs.erase(it);
                    }
                }
            } else {
                app_id_to_pkgs[app_id].insert(pkg);
            }
            break;
        }
    }
}

// Leave /proc fd opened as we're going to read from it repeatedly
static DIR *procfp;

void crawl_procfs(const std::function<bool(int)> &fn) {
    rewinddir(procfp);
    dirent *dp;
    int pid;
    while ((dp = readdir(procfp))) {
        pid = parse_int(dp->d_name);
        if (pid > 0 && !fn(pid))
            break;
    }
}

static inline bool str_eql(string_view a, string_view b) { return a == b; }

template<bool str_op(string_view, string_view) = &str_eql>
static bool proc_name_match(int pid, string_view name) {
    char buf[4019];
    sprintf(buf, "/proc/%d/cmdline", pid);
    if (auto fp = open_file(buf, "re")) {
        fgets(buf, sizeof(buf), fp.get());
        if (str_op(buf, name)) {
            LOGD("hide_daemon: kill PID=[%d] (%s)\n", pid, buf);
            return true;
        }
    }
    return false;
}

static bool proc_context_match(int pid, string_view context) {
    char buf[PATH_MAX];
    sprintf(buf, "/proc/%d/attr/current", pid);
    if (auto fp = open_file(buf, "re")) {
        fgets(buf, sizeof(buf), fp.get());
        if (str_starts(buf, context)) {
            return true;
        }
    }
    return false;
}

template<bool matcher(int, string_view) = &proc_name_match>
static void kill_process(const char *name, bool multi = false) {
    crawl_procfs([=](int pid) -> bool {
        if (matcher(pid, name)) {
            kill(pid, SIGKILL);
            LOGD("hide_daemon: kill PID=[%d] (%s)\n", pid, name);
            return multi;
        }
        return true;
    });
}

static bool validate(const char *pkg, const char *proc) {
    bool pkg_valid = false;
    bool proc_valid = true;

    if (str_eql(pkg, ISOLATED_MAGIC)) {
        pkg_valid = true;
        for (char c; (c = *proc); ++proc) {
            if (isalnum(c) || c == '_' || c == '.')
                continue;
            if (c == ':')
                break;
            proc_valid = false;
            break;
        }
    } else {
        for (char c; (c = *pkg); ++pkg) {
            if (isalnum(c) || c == '_')
                continue;
            if (c == '.') {
                pkg_valid = true;
                continue;
            }
            pkg_valid = false;
            break;
        }

        for (char c; (c = *proc); ++proc) {
            if (isalnum(c) || c == '_' || c == ':' || c == '.')
                continue;
            proc_valid = false;
            break;
        }
    }
    return pkg_valid && proc_valid;
}

static bool add_hide_set(const char *pkg, const char *proc) {
    auto p = pkg_to_procs[pkg].emplace(proc);
    if (!p.second)
        return false;
    LOGI("%s add: [%s/%s]\n", table_name, pkg, proc);
    if (!do_kill)
        return true;
    if (str_eql(pkg, ISOLATED_MAGIC)) {
        // Kill all matching isolated processes
        kill_process<&proc_name_match<str_starts>>(proc, true);
    } else {
        kill_process(proc);
    }
    return true;
}

static void clear_data() {
    pkg_to_procs_.reset(nullptr);
    app_id_to_pkgs_.reset(nullptr);
}

static bool ensure_data() {
    if (pkg_to_procs_)
        return true;

    LOGI("%s: initializing internal data structures\n", table_name);

    char sqlcmd[30];
    ssprintf(sqlcmd, sizeof(sqlcmd), "SELECT * FROM %s", table_name);

    default_new(pkg_to_procs_);
    char *err = db_exec(sqlcmd, [](db_row &row) -> bool {
        add_hide_set(row["package_name"].data(), row["process"].data());
        return true;
    });
    db_err_cmd(err, goto error)

    default_new(app_id_to_pkgs_);
    rescan_apps();

    
    return true;

error:
    clear_data();
    return false;
}

static int add_list(const char *pkg, const char *proc) {
    if (proc[0] == '\0')
        proc = pkg;

    if (!validate(pkg, proc))
        return DenyResponse::INVALID_PKG;

    {
        mutex_guard lock(data_lock);
        if (!ensure_data())
            return DenyResponse::ERROR;
        if (!add_hide_set(pkg, proc))
            return DenyResponse::ITEM_EXIST;
        auto it = pkg_to_procs.find(pkg);
        update_pkg_uid(it->first, false);
    }

    // Add to database
    char sql[4096];
    ssprintf(sql, sizeof(sql),
            "INSERT INTO %s (package_name, process) VALUES('%s', '%s')", table_name, pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DenyResponse::ERROR)
    return DenyResponse::OK;
}

int add_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return add_list(pkg.data(), proc.data());
}

static int rm_list(const char *pkg, const char *proc) {
    {
        mutex_guard lock(data_lock);
        if (!ensure_data())
            return DenyResponse::ERROR;

        bool remove = false;

        auto it = pkg_to_procs.find(pkg);
        if (it != pkg_to_procs.end()) {
            if (proc[0] == '\0') {
                update_pkg_uid(it->first, true);
                pkg_to_procs.erase(it);
                remove = true;
                LOGI("%s rm: [%s]\n", table_name, pkg);
            } else if (it->second.erase(proc) != 0) {
                remove = true;
                LOGI("%s rm: [%s/%s]\n", table_name, pkg, proc);
                if (it->second.empty()) {
                    update_pkg_uid(it->first, true);
                    pkg_to_procs.erase(it);
                }
            }
        }

        if (!remove)
            return DenyResponse::ITEM_NOT_EXIST;
    }

    char sql[4096];
    if (proc[0] == '\0')
        ssprintf(sql, sizeof(sql), "DELETE FROM %s WHERE package_name='%s'", table_name, pkg);
    else
        ssprintf(sql, sizeof(sql),
                "DELETE FROM %s WHERE package_name='%s' AND process='%s'", table_name, pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DenyResponse::ERROR)
    return DenyResponse::OK;
}

int rm_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return rm_list(pkg.data(), proc.data());
}

void ls_list(int client) {
    {
        mutex_guard lock(data_lock);
        if (!ensure_data()) {
            write_int(client, static_cast<int>(DenyResponse::ERROR));
            return;
        }

        write_int(client,static_cast<int>(DenyResponse::OK));

        for (const auto &[pkg, procs] : pkg_to_procs) {
            for (const auto &proc : procs) {
                write_int(client, pkg.size() + proc.size() + 1);
                xwrite(client, pkg.data(), pkg.size());
                xwrite(client, "|", 1);
                xwrite(client, proc.data(), proc.size());
            }
        }
    }
    write_int(client, 0);
    close(client);
}

static void update_deny_config() {
    char sql[64];
    sprintf(sql, "REPLACE INTO settings (key,value) VALUES('%s',%d)",
        DB_SETTING_KEYS[DENYLIST_CONFIG], denylist_enforced.load());
    char *err = db_exec(sql);
    db_err(err);
}

void update_sulist_config(bool enable) {
    char sql[64];
    sprintf(sql, "REPLACE INTO settings (key,value) VALUES('%s',%d)",
        DB_SETTING_KEYS[WHITELIST_CONFIG], enable? 1 : 0);
    char *err = db_exec(sql);
    db_err(err);
}

static int new_daemon_thread(void(*entry)()) {
    thread_entry proxy = [](void *entry) -> void * {
        reinterpret_cast<void(*)()>(entry)();
        return nullptr;
    };
    return new_daemon_thread(proxy, (void *) entry);
}


int enable_deny() {
    if (denylist_enforced) {
        return DenyResponse::OK;
    } else {
        mutex_guard lock(data_lock);

        if (access("/proc/self/ns/mnt", F_OK) != 0) {
            LOGW("The kernel does not support mount namespace\n");
            sulist_enabled = false;
            table_name = "hidelist";
            update_sulist_config(false);
            return DenyResponse::NO_NS;
        }

        if (procfp == nullptr && (procfp = opendir("/proc")) == nullptr)
            goto daemon_error;

        if (sulist_enabled) {
            LOGI("* Enable SuList\n");
        } else {
            LOGI("* Enable MagiskHide\n");
        }

        denylist_enforced = true;

        if (!ensure_data()) {
            denylist_enforced = false;
            goto daemon_error;
        }
        if (!zygisk_enabled) {
            auto do_proc_monitor = new_daemon_thread(&proc_monitor);
            if (do_proc_monitor){
                // cannot start monitor_proc, return daemon error
                return DenyResponse::ERROR;
            }
            monitoring = true;
        }

        if (sulist_enabled) {
            // Add SystemUI and Settings to sulist because modules might need to modify it
            add_hide_set("com.android.systemui", "com.android.systemui");
            add_hide_set("com.android.settings", "com.android.settings");
            add_hide_set(JAVA_PACKAGE_NAME, JAVA_PACKAGE_NAME);
        }
    }

    update_deny_config();

    return DenyResponse::OK;
    
    daemon_error:
    sulist_enabled = false;
    table_name = "hidelist";
    update_sulist_config(false);
    return DenyResponse::ERROR;
}

int disable_deny() {
    // sulist mode cannot be turn off without reboot
    if (sulist_enabled)
        return DenyResponse::SULIST_NO_DISABLE;

    if (denylist_enforced) {
        denylist_enforced = false;
        LOGI("* Disable MagiskHide\n");
    }
    if (!zygisk_enabled && monitoring) {
        pthread_kill(monitor_thread, SIGTERMTHRD);
        monitoring = false;
    }
    update_deny_config();

    return DenyResponse::OK;
}

void initialize_denylist() {
    if (sulist_enabled) table_name = "sulist";
    if (!denylist_enforced) {
        db_settings dbs;
        get_db_settings(dbs, DENYLIST_CONFIG);
        if (dbs[DENYLIST_CONFIG])
            enable_deny();
    }
}

bool is_deny_target(int uid, string_view process, int max_len) {
    mutex_guard lock(data_lock);
    if (!ensure_data())
        return false;

    if (!p_skip_pkg_rescan->test_and_set())
        rescan_apps();

    int app_id = to_app_id(uid);
    int manager_app_id = get_manager();
    string process_name = {process.begin(), process.end()};

    if (app_id == manager_app_id) {
        // allow manager to access Magisk
        return (sulist_enabled)? true : false;
    }

    if (app_id >= 90000) {
        if (auto it = pkg_to_procs.find(ISOLATED_MAGIC); it != pkg_to_procs.end()) {
            for (const auto &s : it->second) {
                if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                    return true;
                if (str_starts(process, s))
                    return true;
            }
        }
        return false;
    } else {
        auto it = app_id_to_pkgs.find(app_id);
        if (it == app_id_to_pkgs.end())
            return false;
        for (const auto &pkg : it->second) {
            if (pkg_to_procs.find(pkg)->second.count(process))
                return true;
        }
        for (const auto &s : it->second) {
            if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                return true;
            if (s == process)
                return true;
        }
    }
    return false;
}

// PROCESS MONITOR


static int inotify_fd = -1;
static int data_system_wd = -1;
static int system_server_pid = -1;
static bool is_process(int pid);

static void new_zygote(int pid);
void do_check_fork();

/******************
 * Data structures
 ******************/

#define PID_MAX 32768
struct pid_set {
    bitset<PID_MAX>::const_reference operator[](size_t pos) const { return set[pos - 1]; }
    bitset<PID_MAX>::reference operator[](size_t pos) { return set[pos - 1]; }
    void reset() { set.reset(); }
private:
    bitset<PID_MAX> set;
};

// zygote pid -> mnt ns
static map<int, struct stat> zygote_map;

// process stat
static map<int, struct stat> pid_map;

// attaches set
static pid_set attaches;

// handle list
static vector<int> pid_list;

/********
 * Utils
 ********/
 
// #define PTRACE_LOG(fmt, args...) LOGD("PID=[%d] " fmt, pid, ##args)
#define PTRACE_LOG(...)

static void detach_pid(int pid, int signal = 0) {
    attaches[pid] = false;
    ptrace(PTRACE_DETACH, pid, 0, signal);
    PTRACE_LOG("detach\n");
}

static inline int read_ns(const int pid, struct stat *st) {
    char path[32];
    sprintf(path, "/proc/%d/ns/mnt", pid);
    return stat(path, st);
}

static int parse_ppid(int pid) {
    char path[32];
    int ppid;
    sprintf(path, "/proc/%d/stat", pid);
    auto stat = open_file(path, "re");
    if (!stat)
        return -1;
    // PID COMM STATE PPID .....
    fscanf(stat.get(), "%*d %*s %*c %d", &ppid);

    return ppid;
}

static bool is_zygote_done() {
#ifdef __LP64__
    int zygote_count = (HAVE_32)? 2:1;
    if (zygote_map.size() >= zygote_count)
        return true;
#else
    if (zygote_map.size() >= 1)
        return true;
#endif

    return false;
}

static inline bool read_file(const char *file, char *buf, int count){
    FILE *fp = fopen(file, "re");
    if (!fp) return false;
    fread(buf, count, 1, fp);
    fclose(fp);
    return true;
}

static bool check_process(int pid, const char *process, const char *context, const char *exe) {
    char path[128];
    char buf[1024];
    ssize_t len;

    if (!process) goto check_context;
    sprintf(path, "/proc/%d/cmdline", pid);
    if (!read_file(path,buf,sizeof(buf)) ||
        strcmp(buf, process) != 0)
        return false;

    check_context:
    if (!context) goto check_exe;
    sprintf(path, "/proc/%d/attr/current", pid);
    if (!read_file(path,buf,sizeof(buf)) || 
        !str_contains(buf, context))
        return false;
    
    check_exe:
    if (!exe) goto final;
    sprintf(path, "/proc/%d/exe", pid);
    len = readlink(path, buf, sizeof(buf)-1);
    if (len != -1) {
      buf[len] = '\0';
    }
    if (strcmp(buf, exe) != 0)
        return false;

    final:
    return true;
}

static bool check_process2(int pid, const char *process, const char *context, const char *exe) {
    return check_process(pid, process, (selinux_enabled())? context : nullptr, exe);
}

static bool is_zygote(int pid){
    return (check_process(pid, nullptr, nullptr, "/system/bin/app_process")
            || check_process(pid,  nullptr, nullptr, "/system/bin/app_process32")
            || check_process(pid, nullptr, nullptr, "/system/bin/app_process64"))
            && (check_process2(pid, "zygote", "u:r:zygote:s0", nullptr)  
            || check_process2(pid, "zygote64", "u:r:zygote:s0", nullptr)
            || check_process2(pid, "zygote32", "u:r:zygote:s0", nullptr));
}

void unmount_zygote(){
    crawl_procfs([](int pid) -> bool {
        if (is_process(pid) && is_zygote(pid) && parse_ppid(pid) == 1) {
            LOGI("zygote pid=[%d]\n", pid); 
            revert_daemon(pid, -2);
        }
        return true;
    });
}

static bool check_map(int pid) {
    auto it = pid_map.find(pid);
    char path[128];
    struct stat st;
    sprintf(path, "/proc/%d", pid);
    if (stat(path, &st))
        return false;
    if (it != pid_map.end()) {
        if (it->second.st_dev == st.st_dev &&
            it->second.st_ino == st.st_ino)
            return false;
        it->second = st;
    } else {
        pid_map[pid] = st;
    }
    return true;
}

static void check_zygote(){
    crawl_procfs([](int pid) -> bool {
        // Only care about process
        if (!is_process(pid))
            goto not_zygote;

        if (is_zygote(pid) && parse_ppid(pid) == 1 && system_server_pid > 0) {
            new_zygote(pid);
            return true;
        }
        if (check_process2(pid, "system_server", "u:r:system_server:s0", nullptr)
            && is_zygote(parse_ppid(pid)) && check_map(pid)) {
            system_server_pid = pid;
        }

        not_zygote:
        zygote_map.erase(pid);
        return true;
    });
    if (is_zygote_done()) {
        // Stop periodic scanning
        timeval val { .tv_sec = 0, .tv_usec = 0 };
        itimerval interval { .it_interval = val, .it_value = val };
        setitimer(ITIMER_REAL, &interval, nullptr);
    }
}

#define APP_PROC "/system/bin/app_process"

static void setup_inotify() {
    inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd < 0)
        return;

    // Setup inotify asynchronous I/O
    fcntl(inotify_fd, F_SETFL, O_ASYNC);
    struct f_owner_ex ex = {
        .type = F_OWNER_TID,
        .pid = gettid()
    };
    fcntl(inotify_fd, F_SETOWN_EX, &ex);

    // Monitor packages.xml
    data_system_wd = inotify_add_watch(inotify_fd, "/data/system", IN_CLOSE_WRITE);

    // Monitor app installation
    inotify_add_watch(inotify_fd, APP_DATA_DIR, IN_CREATE);
    DIR *dirfp = opendir(APP_DATA_DIR);
    if (dirfp) {
   	    char buf[4098];
        struct dirent *dp;
        while ((dp = readdir(dirfp)) != nullptr) {
            ssprintf(buf, sizeof(buf) - 1, "%s/%s", APP_DATA_DIR, dp->d_name);
            if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
                continue;
            LOGD("proc_monitor: monitor userspace ID=[%s]\n", dp->d_name);
            inotify_add_watch(inotify_fd, buf, IN_ATTRIB);
        }
        closedir(dirfp);
    }

    // Monitor app_process
    if (access(APP_PROC "32", F_OK) == 0) {
        inotify_add_watch(inotify_fd, APP_PROC "32", IN_ACCESS);
        if (access(APP_PROC "64", F_OK) == 0)
            inotify_add_watch(inotify_fd, APP_PROC "64", IN_ACCESS);
    } else {
        inotify_add_watch(inotify_fd, APP_PROC, IN_ACCESS);
    }
}

static bool is_process(int pid) {
    char buf[128];
    char key[32];
    int tgid;
    sprintf(buf, "/proc/%d/status", pid);
    auto fp = open_file(buf, "re");
    // PID is dead
    if (!fp)
        return false;
    while (fgets(buf, sizeof(buf), fp.get())) {
        sscanf(buf, "%s", key);
        if (key == "Tgid:"sv) {
            sscanf(buf, "%*s %d", &tgid);
            return tgid == pid;
        }
    }
    return false;
}

static bool is_proc_alive(int pid) {
    auto it = pid_map.find(pid);
    char path[128];
    struct stat st;
    sprintf(path, "/proc/%d", pid);
    if (stat(path, &st))
        return false;
    if (it != pid_map.end() &&
        it->second.st_dev == st.st_dev &&
        it->second.st_ino == st.st_ino)
        return true;
    return false;
}

/************************
 * Async signal handlers
 ************************/

#define USAP_ENABLED "persist.device_config.runtime_native.usap_pool_enabled" 

// Make sure we can actually read stuffs 
// or else the whole thread will be blocked. 
#define POLL_EVENT \
    struct pollfd pfd = { \
        .fd = inotify_fd, \
        .events = POLLIN, \
        .revents = 0 \
    }; \
    if (poll(&pfd, 1, 0) <= 0) \
        return;

#define PROCESS_EVENT \
    do { \
        char buf[512]; \
        auto event = reinterpret_cast<struct inotify_event *>(buf); \
        read(inotify_fd, buf, sizeof(buf)); \
        if (event->mask & IN_CREATE) { \
            std::string path = std::string(APP_DATA_DIR) + "/" + event->name; \
            LOGD("proc_monitor: monitor userspace ID=[%s]\n", event->name); \
            inotify_add_watch(inotify_fd, path.data(), IN_ATTRIB); \
            break; \
        } \
        if ((event->wd == data_system_wd && event->name == "packages.xml"sv) || (event->mask & IN_ATTRIB)) \
            rescan_apps(); \
        check_zygote(); \
    } while (false);



static void inotify_event(int) {
    POLL_EVENT
    PROCESS_EVENT
}

static void term_thread(int) {
    LOGD("proc_monitor: cleaning up\n");
    zygote_map.clear();
    pid_map.clear();
    attaches.reset();
    close(inotify_fd);
    system_server_pid = -1;
    inotify_fd = -1;
    fork_pid = 0;
    monitor_thread = -1;
    for (int i = 0; i < pid_list.size(); i++) {
        LOGD("proc_monitor: kill PID=[%d]\n", pid_list[i]);
        kill(pid_list[i], SIGKILL);
    }
    pid_list.clear();
    // Restore all signal handlers that was set
    sigset_t set;
    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
    struct sigaction act{};
    act.sa_handler = SIG_DFL;
    sigaction(SIGTERMTHRD, &act, nullptr);
    sigaction(SIGIO, &act, nullptr);
    sigaction(SIGALRM, &act, nullptr);
    LOGD("proc_monitor: terminate\n");
    pthread_exit(nullptr);
}

static bool ino_equal(struct stat st, struct stat st2){
    return st.st_dev == st2.st_dev &&
        st.st_ino == st2.st_ino;
}

static std::string get_process_name(int pid) {
    char path[256];
    char *substr = path;
    sprintf(path, "/proc/%d/stat", pid);
    auto stat = open_file(path, "re");
    if (!stat)
        return std::string("");
    // PID COMM.....
    fscanf(stat.get(), "%*d %s", path);
    int length = strlen(path);
    if (length > 2) {
        path[length-1] = '\0';
        substr++;
    }
    return std::string(substr);
}

static int check_pid(int pid) {
    char path[128];
    char cmdline[1024];
    int ppid = -1;
    struct stat st;
    sprintf(path, "/proc/%d", pid);
    if (stat(path, &st)) {
        // Process died unexpectedly, ignore
        return 1;
    }
    int uid = st.st_uid;
    if (uid == 0) {
        return 0;
    }

    // check cmdline
    ssprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    if (!read_file(path, cmdline, sizeof(cmdline)))
        // Process died unexpectedly, ignore
        return 1;

    // still zygote
    if (cmdline == "zygote"sv || cmdline == "zygote32"sv || cmdline == "zygote64"sv ||
        cmdline == "usap32"sv || cmdline == "usap64"sv || cmdline == "<pre-initialized>"sv)
        return 0;

    detach_pid(pid);

    // stop app process as soon as possible and do check if this process is target or not
    kill(pid, SIGSTOP);

    if (!is_deny_target(uid, cmdline, 95)) {
        goto not_target;
    }

    // Ensure ns is separated
    struct stat ppid_st;
    ppid = parse_ppid(pid);
    read_ns(pid, &st);
    read_ns(ppid, &ppid_st);

    if (ino_equal(st, ppid_st)) {
        LOGW("proc_monitor: skip [%s] PID=[%d] PPID=[%d] UID=[%d]\n", cmdline, pid, ppid, uid);
        goto not_target;
    }

    // Finally this is our target
    // We stop target process and do all unmounts
    // The hide daemon will resume the process after hiding it
    LOGI("proc_monitor: [%s] PID=[%d] PPID=[%d] UID=[%d]\n", cmdline, pid, ppid, uid);

    if (sulist_enabled) {
        // mount magisk in sulist mode
        su_daemon(pid);
        return 1;
    }
    // hide magisk in normal mode
    revert_daemon(pid);
    return 1;

not_target:
    kill(pid, SIGCONT);
    return 1;
}

static void new_zygote(int pid) {
    struct stat st;
    if (read_ns(pid, &st))
        return;

    auto it = zygote_map.find(pid);
    if (it != zygote_map.end()) {
        it->second = st;
        return;
    }

    if (!check_map(pid))
        return;

    LOGI("proc_monitor: zygote PID=[%d]\n", pid);
    if (sulist_enabled) revert_daemon(pid, -2);
    zygote_map[pid] = st;
    attach_zygote:
    LOGI("proc_monitor: ptrace zygote PID=[%d]\n", pid);
    xptrace(PTRACE_ATTACH, pid);
    waitpid(pid, nullptr, __WALL | __WNOTHREAD);
    xptrace(PTRACE_SETOPTIONS, pid, nullptr,
            PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT);
    xptrace(PTRACE_CONT, pid);
}

#define DETACH_AND_CONT { detach_pid(pid); continue; }

int wait_for_syscall(pid_t pid) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        PTRACE_LOG("wait for syscall\n");
        int child = waitpid(pid, &status, 0);
        if (child < 0)
            return 1;
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
            PTRACE_LOG("make a syscall\n");
            return 0;
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV) {
            // google chrome?
            PTRACE_LOG("SIGSEGV from child\n");
            return 1;
        }
        if (WIFEXITED(status)) {
            PTRACE_LOG("exited\n");
            return 1;
        }
    }
}

static std::string get_content(int pid, const char *file) {
    char buf[1024];
    sprintf(buf, "/proc/%d/%s", pid, file);
    FILE *fp = fopen(buf, "re");
    if (fp) {
        fgets(buf, sizeof(buf), fp);
        fclose(fp);
        return std::string(buf);
    }
    return std::string("");
}

void do_check_fork() {
    int pid = fork_pid;
    fork_pid = 0;
    if (pid == 0)
        return;
    // wait until thread detach this pid
    for (int i = 0; i < 10000 && ptrace(PTRACE_ATTACH, pid) < 0; i++)
        usleep(100);
    bool allow = false;
    bool checked = false;
    pid_list.emplace_back(pid);
    waitpid(pid, 0, 0);
    xptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD);
    struct stat st{};
    char path[128];
    for (int syscall_num = -1;;) {
        if (wait_for_syscall(pid) != 0)
            break;
        {
            if (checked) goto CHECK_PROC;
            sprintf(path, "/proc/%d", pid);
            stat(path, &st);
            PTRACE_LOG("UID=[%d]\n", st.st_uid);
            if (st.st_uid == 0)
                continue;
            //LOGD("proc_monitor: PID=[%d] UID=[%d]\n", pid, st.st_uid);
            if ((st.st_uid % 100000) >= 90000) {
                PTRACE_LOG("is isolated process\n");
           	    if (sulist_enabled)
           	        break;
                goto CHECK_PROC;
            }

            // check if UID is on list
            {
                auto it = app_id_to_pkgs.find(st.st_uid % 100000);
                // double check
                if (it == app_id_to_pkgs.end())
                    break;
                int found = false;
                for (const auto &pkg : it->second) {
                    if (pkg_to_procs.find(pkg)->second.size() > 0) {
                        found = true;
                        break;
                    }
                }
                if (!found) break;
            }

            CHECK_PROC:
            checked = true;
            if (!allow && (
                 // app zygote
                 strstr(get_content(pid, "attr/current").data(), "u:r:app_zygote:s0") ||
                 // until pre-initialized
                 get_content(pid, "cmdline") == "<pre-initialized>"))
                 allow = true;
            if (allow && check_pid(pid))
                break;
        }
    }
    PTRACE_LOG("detach\n");
    ptrace(PTRACE_DETACH, pid);
    auto it = find(pid_list.begin(), pid_list.end(), pid);
    if (it != pid_list.end())
        pid_list.erase(it);
}

void proc_monitor() {
    monitor_thread = pthread_self();

    // Backup original mask
    sigset_t orig_mask;
    pthread_sigmask(SIG_SETMASK, nullptr, &orig_mask);

    sigset_t unblock_set;
    sigemptyset(&unblock_set);
    sigaddset(&unblock_set, SIGTERMTHRD);
    sigaddset(&unblock_set, SIGIO);
    sigaddset(&unblock_set, SIGALRM);

    struct sigaction act{};
    sigfillset(&act.sa_mask);
    act.sa_handler = SIG_IGN;
    sigaction(SIGTERMTHRD, &act, nullptr);
    sigaction(SIGIO, &act, nullptr);
    sigaction(SIGALRM, &act, nullptr);

    // Temporary unblock to clear pending signals
    pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);
    pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);

    act.sa_handler = term_thread;
    sigaction(SIGTERMTHRD, &act, nullptr);
    act.sa_handler = inotify_event;
    sigaction(SIGIO, &act, nullptr);
    act.sa_handler = [](int){ check_zygote(); };
    sigaction(SIGALRM, &act, nullptr);

    zygote_map.clear();
    pid_map.clear();
    setup_inotify();
    attaches.reset();

    // First try find existing system server
    check_zygote();

    start_monitor:
    pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);
    // wait until system_server start
    while (system_server_pid == -1)
        sleep(1);
    if (!is_proc_alive(system_server_pid)) {
        system_server_pid = -1;
        pid_map.clear();
        goto start_monitor;
    }
    // now ptrace zygote
    pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);
    // First try find existing zygotes
    check_zygote();
    if (!is_zygote_done()) {
        // Periodic scan every 250ms
        timeval val { .tv_sec = 0, .tv_usec = 250000 };
        itimerval interval { .it_interval = val, .it_value = val };
        setitimer(ITIMER_REAL, &interval, nullptr);
    }
    rescan_apps();

    // On Android Q+, also kill blastula pool and all app zygotes
    if (SDK_INT >= 29) {
        kill_process("usap32", true);
        kill_process("usap64", true);
        kill_process<&proc_context_match>("u:r:app_zygote:s0", true);
    }

    for (int status;;) {
        pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);
        const int pid = waitpid(-1, &status, __WALL | __WNOTHREAD);
        if (pid < 0) {
            if (errno == ECHILD) {
                // Nothing to wait yet, sleep and wait till signal interruption
                LOGD("proc_monitor: nothing to monitor, wait for signal\n");
                struct timespec ts = {
                    .tv_sec = INT_MAX,
                    .tv_nsec = 0
                };
                nanosleep(&ts, nullptr);
                zygote_map.clear();
                goto start_monitor;
            }
            continue;
        }

        pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);

        if (!WIFSTOPPED(status) /* Ignore if not ptrace-stop */)
            DETACH_AND_CONT;

        int event = WEVENT(status);
        int signal = WSTOPSIG(status);

        if (signal == SIGTRAP && event) {
            unsigned long msg;
            xptrace(PTRACE_GETEVENTMSG, pid, nullptr, &msg);
            if (zygote_map.count(pid)) {
                // Zygote event
                switch (event) {
                    case PTRACE_EVENT_FORK:
                    case PTRACE_EVENT_VFORK:
                        PTRACE_LOG("zygote forked: [%lu]\n", msg);
                        attaches[msg] = true;
                        break;
                    case PTRACE_EVENT_EXIT:
                        PTRACE_LOG("zygote exited with status: [%lu]\n", msg);
                        [[fallthrough]];
                    default:
                        zygote_map.erase(pid);
                        DETACH_AND_CONT;
                }
            } else {
                DETACH_AND_CONT;
            }
            xptrace(PTRACE_CONT, pid);
        } else if (signal == SIGSTOP) {
            if (!attaches[pid]) {
                // Double check if this is actually a process
                attaches[pid] = is_process(pid);
            }
            if (attaches[pid]) {
                // This is a process, continue monitoring
                //LOGD("proc_monitor: SIGSTOP from child PID=[%d]\n", pid);
                attaches[pid] = false;
                detach_pid(pid);
                fork_pid = pid;
                new_daemon_thread(&do_check_fork);
            } else {
                // This is a thread, do NOT monitor
                PTRACE_LOG("SIGSTOP from thread\n");
                DETACH_AND_CONT;
            }

        } else {
            // Not caused by us, resend signal
            xptrace(PTRACE_CONT, pid, nullptr, signal);
            PTRACE_LOG("signal [%d]\n", signal);
        }
    }
}

