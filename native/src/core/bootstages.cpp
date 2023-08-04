#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <linux/input.h>
#include <libgen.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/vfs.h>

#include <magisk.hpp>
#include <db.hpp>
#include <base.hpp>
#include <daemon.hpp>
#include <resetprop.hpp>
#include <selinux.hpp>

#include "core.hpp"

#define COUNT_FAILBOOT "/cache/.magisk_checkboot"

#define VLOGD(tag, from, to) LOGD("%-8s: %s <- %s\n", tag, to, from)

using namespace std;

#define FIX_MIRRORS 1

#define TST_RAMFS_MAGIC    0x858458f6
#define TST_TMPFS_MAGIC    0x01021994
#define TST_OVERLAYFS_MAGIC 0x794c7630

bool is_rootfs()
{
    const char *path= "/";
    struct statfs s;
    statfs(path, &s);
    
    switch (s.f_type) {
    case TST_TMPFS_MAGIC:
    case TST_RAMFS_MAGIC:
    case TST_OVERLAYFS_MAGIC:
        return true;
    default:
        return false;
    }
}

int ztrigger_count = 0;
static bool bootloop_protect = false;


static const char *preinit_part[]={
        PREINIT_PARTS,
        "/mnt/vendor/persist",
        nullptr
    };


static bool is_persist_access(const char *file){
    for (int i=0;preinit_part[i];i++) {
        string sfile = string(preinit_part[i]) + "/" + file;
        if (access(sfile.data(), F_OK) == 0) {
            LOGD("daemon: found trigger file [%s]\n", sfile.data());
            return true;
        }
    }
    return false;
}

static void create_persist_file(const char *file){
    for (int i=0;preinit_part[i];i++) {
        string sfile = string(preinit_part[i]) + "/" + file;
        LOGD("daemon: create trigger file [%s]\n", sfile.data());
        close(xopen(sfile.data(), O_RDONLY | O_CREAT, 0));
    }
}

static void remove_persist_access(const char *file){
    for (int i=0;preinit_part[i];i++) {
        string sfile = string(preinit_part[i]) + "/" + file;
        if (access(sfile.data(), F_OK) == 0) {
            LOGD("daemon: remove trigger file [%s]\n", sfile.data());
            rm_rf(sfile.data());
        }
    }
}

void reboot_coreonly(){
    create_persist_file(".disable_all");
    LOGI("** Reboot to recovery");
    exec_command_sync("/system/bin/reboot", "recovery");
}

bool check_bootloop(const char *name, const char *filename, int max)
{
    int n=1;
    if (access(filename, F_OK) != 0) {
        // not exist, we need create file with initial value
        FILE *ztrigger=fopen(filename, "wb");
        if (ztrigger == NULL) return false; // failed
        fwrite(&n,1,sizeof(int),ztrigger);
        fclose(ztrigger);
    }
    FILE *ztrigger=fopen(filename, "rb");
    if (ztrigger == NULL) return false; // failed
    fread(&n, 1, sizeof(int), ztrigger);
    fclose(ztrigger);
    // current number here
        if (n >= max) {
            LOGI("anti_bootloop: %s reachs %d times, restart!\n", name, max);
            reboot_coreonly();
        } else LOGI("%s count = %d\n", name, n);
    
    ztrigger=fopen(filename, "wb");
    if (ztrigger == NULL) return false; // failed
    n++; // increase the number
    fwrite(&n, 1, sizeof(int), ztrigger);
    fclose(ztrigger);
    return true;
}


// Boot stage state
enum : int {
    FLAG_NONE = 0,
    FLAG_POST_FS_DATA_DONE = (1 << 0),
    FLAG_LATE_START_DONE = (1 << 1),
    FLAG_BOOT_COMPLETE = (1 << 2),
    FLAG_SAFE_MODE = (1 << 3),
};

static int boot_state = FLAG_NONE;

bool zygisk_enabled = false;
bool sulist_enabled = false;

static const char *F2FS_SYSFS_PATH = nullptr;

/*********
 * Setup *
 *********/
 
 
void recreate_sbin_v2(const char *mirror, bool use_bind_mount) {
    auto dp = xopen_dir(mirror);
    int src = dirfd(dp.get());
    char buf[4096];
    char mbuf[4096];
    for (dirent *entry; (entry = xreaddir(dp.get()));) {
        string sbin_path = "/sbin/"s + entry->d_name;
        struct stat st;
        fstatat(src, entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
        sprintf(buf, "%s/%s", mirror, entry->d_name);
        sprintf(mbuf, "%s/%s", MAGISKTMP.data(), entry->d_name);
        if (access(mbuf, F_OK) == 0) continue;
        if (S_ISLNK(st.st_mode)) {
            xreadlinkat(src, entry->d_name, buf, sizeof(buf));
            xsymlink(buf, sbin_path.data());
            VLOGD("create", buf, sbin_path.data());
        } else {
            if (use_bind_mount) {
                auto mode = st.st_mode & 0777;
                // Create dummy
                if (S_ISDIR(st.st_mode))
                    xmkdir(sbin_path.data(), mode);
                else
                    close(xopen(sbin_path.data(), O_CREAT | O_WRONLY | O_CLOEXEC, mode));

                bind_mount_(buf, sbin_path.data());
            } else {
                xsymlink(buf, sbin_path.data());
                VLOGD("create", buf, sbin_path.data());
            }
        }
    }
}

bool mount_recreate(const std::string_view from, const std::string_view to){
    return !xmount(from.data(), to.data(), nullptr, MS_BIND, nullptr) &&
           !xmount("", to.data(), nullptr, MS_PRIVATE, nullptr);
}

void mount_mirrors() {
    string mirror_dir = MAGISKTMP + "/" MIRRDIR;
    string system_mirror = mirror_dir + "/system";
    string worker_dir = MAGISKTMP + "/" WORKERDIR;
    mkdirs(worker_dir.data(), 0755);
    xmount(worker_dir.data(), worker_dir.data(), nullptr, MS_BIND, nullptr);
    xmount("", worker_dir.data(), nullptr, MS_PRIVATE, nullptr);
    const char *include_parts[] = { MIRRORS, "/mnt/vendor/persist", nullptr };

    std::vector<string> mounted_dirs;
    std::vector<mount_info> mount_info;
    // trim mountinfo
    do {
        auto current_mount_info = parse_mount_info("self");
        std::vector<string> mountpoint;
        for (auto &info : reversed(current_mount_info)){
            if (info.target != "/") {
                for (auto &s : mountpoint)
                    if (s == info.target)
                        goto next_mountpoint;
                for (int i = 0; include_parts[i] != nullptr; i++){
                    if (info.target == include_parts[i] || 
                        info.target.starts_with(std::string(include_parts[i]) + "/")){
                        goto add_mountpoint;
                    }
                }
                continue;
            }
            add_mountpoint:
            mount_info.emplace_back(info);
            mountpoint.emplace_back(info.target);
            next_mountpoint:
            continue;
        }
    } while(false);

    bool rootdir_mounted = false;
    for (auto &info : reversed(mount_info)) {
        const char *mnt_dir = info.target.data();
        const char *mnt_type = info.type.data();
        const char *mnt_root = info.root.data();
        struct stat st{};
        string dest = mirror_dir + mnt_dir;
            if (lstat(mnt_dir, &st) != 0 ||
                // skip underlying mount
                st.st_dev != info.device ||
                // only mount /data, skip any mountpoint under /data
                string(mnt_dir).starts_with("/data/") ||
                // skip mount vfat
                mnt_type == "vfat"sv)
                continue;
#if FIX_MIRRORS
            if (rootdir_mounted && info.target.starts_with("/system/")){
                if (major(st.st_dev) > 0)
                    goto setup_mount_dev;
                goto recreate_mnt;
            }
#endif
            for (const auto &dir : mounted_dirs) {
#if FIX_MIRRORS
                if (info.target.starts_with(dir + "/")){
                    if (major(st.st_dev) > 0)
                        goto setup_mount_dev;
                    goto recreate_mnt;
                }
#endif
                if (string_view(mnt_dir) == dir) {
                    // Already mounted
                    goto next;
                }
            }
            // handle nodev partitions like overlayfs /system
            if (major(st.st_dev) == 0){
                if (mnt_dir == "/"sv) {
                    if (mnt_type == "rootfs"sv || mnt_type == "tmpfs"sv)
                        continue;
                    // overlayfs root directory ?
                    dest = mirror_dir + "/system_root";
                    xmkdir(dest.data(), 0755);
                    if (mount_recreate(mnt_dir, dest)){
                        LOGD("mount: %s (%s)\n", dest.data(), mnt_type);
                        if (!symlink("./system_root/system", system_mirror.data()))
                            LOGD("symlink: %s\n", system_mirror.data());
                        rootdir_mounted = true;
                        goto add_mounted_dir;
                    } else {
                        rm_rf(dest.data());
                    }
                } else {
                    dest = mirror_dir + mnt_dir;
                    xmkdir(dest.data(), 0755);
                    if (mount_recreate(mnt_dir, dest)) {
                        LOGD("mount: %s (%s)\n", dest.data(), mnt_type);
                    }
                }
                continue;
            }

            // setup mirror partitions as usual
            if (mnt_dir == "/mnt/vendor/persist"sv) {
                dest = mirror_dir + "/persist";
                xmkdir(dest.data(), 0755);
                if (mount_recreate(mnt_dir, dest)) {
                    mounted_dirs.emplace_back("/mnt/vendor/persist");
                    mounted_dirs.emplace_back("/persist");
                }
                goto on_success;
            }
            if (mnt_dir == "/"sv) {
                dest = mirror_dir + "/system_root";
                xmkdir(dest.data(), 0755);
                if (mount_recreate(mnt_dir, dest)) {
                    if (!symlink("./system_root/system", system_mirror.data()))
                        LOGD("symlink: %s\n", system_mirror.data());
                    rootdir_mounted = true;
                    goto add_mounted_dir;
                }
                goto on_success;
            }
            xmkdir(dest.data(), 0755);
            setup_mount_dev:
            if (mount_recreate(mnt_dir, dest)) {
                goto add_mounted_dir;
            }

            recreate_mnt:
            if (mount_recreate(mnt_dir, dest))
                LOGD("mount: %s (%s)\n", dest.data(), mnt_type);
            continue;

        add_mounted_dir:
            mounted_dirs.emplace_back(mnt_dir);
        on_success:
        next:
            continue;
    }
    for (const char *part : { SPEC_PARTS }){
        string dest = mirror_dir + part;
        string src = string("./system") + part;
        if (access(dest.data(), F_OK) != 0 && access(part, F_OK) == 0 && !symlink(src.data(), dest.data())) {
            LOGD("symlink: %s\n", dest.data());
        }
    }

    //LOGI("* Mounting module root\n");
    if (access(SECURE_DIR, F_OK) == 0 || (SDK_INT < 24 && xmkdir(SECURE_DIR, 0700))) {
        auto src = MAGISKTMP + "/" MIRRDIR "/" MODULEROOT;
        auto dest = MAGISKTMP + "/" MODULEMNT; xmkdir(dest.data(), 0700); 
        if (mount_recreate(src, dest)) {
            restorecon();
            chmod(SECURE_DIR, 0700);
        }
    }
}

static bool magisk_env() {
    char buf[4096];

    LOGI("* Initializing Magisk environment\n");

    preserve_stub_apk();
    string pkg;
    get_manager(0, &pkg);

    ssprintf(buf, sizeof(buf), "%s/0/%s/install", APP_DATA_DIR,
            pkg.empty() ? "xxx" /* Ensure non-exist path */ : pkg.data());

    // Alternative binaries paths
    const char *alt_bin[] = { "/cache/data_adb/magisk", "/data/magisk", buf };
    struct stat st{};
    for (auto alt : alt_bin) {
        if (lstat(alt, &st) == 0) {
            if (S_ISLNK(st.st_mode)) {
                unlink(alt);
                continue;
            }
            rm_rf(DATABIN);
            cp_afc(alt, DATABIN);
            rm_rf(alt);
            break;
        }
    }
    rm_rf("/cache/data_adb");

    // Directories in /data/adb
    if (!is_dir_exist(MODULEROOT)) rm_rf(MODULEROOT);
    xmkdir(DATABIN, 0755);
    xmkdir(MODULEROOT, 0755);
    xmkdir(SECURE_DIR "/post-fs-data.d", 0755);
    xmkdir(SECURE_DIR "/service.d", 0755);

    restore_databincon();

    if (access(DATABIN "/busybox", X_OK))
        return false;

    sprintf(buf, "%s/" BBPATH "/busybox", MAGISKTMP.data());
    mkdir(dirname(buf), 0755);
    cp_afc(DATABIN "/busybox", buf);
    exec_command_async(buf, "--install", "-s", dirname(buf));

    if (access(DATABIN "/magiskpolicy", X_OK) == 0) {
        sprintf(buf, "%s/magiskpolicy", MAGISKTMP.data());
        cp_afc(DATABIN "/magiskpolicy", buf);
    }

    return true;
}

void reboot() {
    if (RECOVERY_MODE)
        exec_command_sync("/system/bin/reboot", "recovery");
    else
        exec_command_sync("/system/bin/reboot");
}

static bool core_only(bool rm_trigger = false){
    if (is_persist_access(".disable_magisk")){
        if (rm_trigger){
            remove_persist_access(".disable_magisk");
        }
        return true;
    }
    return false;
}


static bool should_skip_all(){
    if (is_persist_access(".disable_all")){
        remove_persist_access(".disable_all");
        rm_rf(COUNT_FAILBOOT);
        return true;
    }
    return false;
}
    

static bool check_data() {
    bool mnt = false;
    file_readline("/proc/mounts", [&](string_view s) {
        if (str_contains(s, " /data ") && !str_contains(s, "tmpfs")) {
            mnt = true;
            return false;
        }
        return true;
    });
    if (!mnt)
        return false;
    auto crypto = getprop("ro.crypto.state");
    if (!crypto.empty()) {
        if (crypto != "encrypted") {
            // Unencrypted, we can directly access data
            return true;
        } else {
            // Encrypted, check whether vold is started
            return !getprop("init.svc.vold").empty();
        }
    }
    // ro.crypto.state is not set, assume it's unencrypted
    return true;
}

static bool system_lnk(const char *path){
    char buff[4098];
    ssize_t len = readlink(path, buff, sizeof(buff)-1);
    if (len != -1) {
        return true;
    }
    return false;
}

static void simple_mount(const string &sdir, const string &ddir = "") {
    auto dir = xopen_dir(sdir.data());
    if (!dir) return;
    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        string src = sdir + "/" + entry->d_name;
        string dest = ddir + "/" + entry->d_name;
        if (access(dest.data(), F_OK) == 0 && !system_lnk(dest.data())) {
            if (entry->d_type == DT_LNK) continue;
            else if (entry->d_type == DT_DIR) {
                // Recursive
                simple_mount(src, dest);
            } else {
                LOGD("bind_mnt: %s <- %s\n", dest.data(), src.data());
                xmount(src.data(), dest.data(), nullptr, MS_BIND, nullptr);
            }
        }
    }
}

void unlock_blocks() {
    int fd, dev, OFF = 0;

    auto dir = xopen_dir("/dev/block");
    if (!dir)
        return;
    dev = dirfd(dir.get());

    for (dirent *entry; (entry = readdir(dir.get()));) {
        if (entry->d_type == DT_BLK) {
            if ((fd = openat(dev, entry->d_name, O_RDONLY | O_CLOEXEC)) < 0)
                continue;
            if (ioctl(fd, BLKROSET, &OFF) < 0)
                PLOGE("unlock %s", entry->d_name);
            close(fd);
        }
    }
}


int mount_sbin(){
    if (is_rootfs()){
        if (xmount(nullptr, "/", nullptr, MS_REMOUNT, nullptr) != 0) return -1;
        mkdir("/sbin", 0750);
        rm_rf("/root");
        mkdir("/root", 0750);
        clone_attr("/sbin", "/root");
        link_path("/sbin", "/root");
        if (tmpfs_mount("tmpfs", "/sbin") != 0) return -1;
        setfilecon("/sbin", "u:object_r:rootfs:s0");
        recreate_sbin_v2("/root", false);
        xmount(nullptr, "/", nullptr, MS_REMOUNT | MS_RDONLY, nullptr);
    } else {
        if (tmpfs_mount("tmpfs", "/sbin") != 0) return -1;
        setfilecon("/sbin", "u:object_r:rootfs:s0");
        xmkdir("/sbin/" INTLROOT, 0755);
        xmkdir("/sbin/" MIRRDIR, 0755);
        xmkdir("/sbin/" MIRRDIR "/system_root", 0755);
        xmount("/", "/sbin/" MIRRDIR "/system_root", nullptr, MS_BIND, nullptr);
        recreate_sbin_v2("/sbin/" MIRRDIR "/system_root/sbin", true);
        umount2("/sbin/" MIRRDIR "/system_root", MNT_DETACH);
    }
    return 0;
}

#define test_bit(bit, array) (array[bit / 8] & (1 << (bit % 8)))

static bool check_key_combo() {
    uint8_t bitmask[(KEY_MAX + 1) / 8];
    vector<int> events;
    constexpr char name[] = "/dev/.ev";

    // First collect candidate events that accepts volume down
    for (int minor = 64; minor < 96; ++minor) {
        if (xmknod(name, S_IFCHR | 0444, makedev(13, minor)))
            continue;
        int fd = open(name, O_RDONLY | O_CLOEXEC);
        unlink(name);
        if (fd < 0)
            continue;
        memset(bitmask, 0, sizeof(bitmask));
        ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(bitmask)), bitmask);
        if (test_bit(KEY_VOLUMEDOWN, bitmask))
            events.push_back(fd);
        else
            close(fd);
    }
    if (events.empty())
        return false;

    run_finally fin([&]{ std::for_each(events.begin(), events.end(), close); });

    // Check if volume down key is held continuously for more than 3 seconds
    for (int i = 0; i < 300; ++i) {
        bool pressed = false;
        for (const int &fd : events) {
            memset(bitmask, 0, sizeof(bitmask));
            ioctl(fd, EVIOCGKEY(sizeof(bitmask)), bitmask);
            if (test_bit(KEY_VOLUMEDOWN, bitmask)) {
                pressed = true;
                break;
            }
        }
        if (!pressed)
            return false;
        // Check every 10ms
        usleep(10000);
    }
    LOGD("KEY_VOLUMEDOWN detected: enter safe mode\n");
    return true;
}

#define F2FS_DEF_CP_INTERVAL "60"
#define F2FS_TUNE_CP_INTERVAL "200"
#define F2FS_DEF_GC_THREAD_URGENT_SLEEP_TIME "500"
#define F2FS_TUNE_GC_THREAD_URGENT_SLEEP_TIME "50"
#define BLOCK_SYSFS_PATH "/sys/block"
#define TUNE_DISCARD_MAX_BYTES "134217728"

static inline bool tune_f2fs_target(const char *device) {
    // Tune only SCSI (UFS), eMMC, NVMe and virtual devices
    return !strncmp(device, "sd", 2) ||
           !strncmp(device, "mmcblk", 6) ||
           !strncmp(device, "nvme", 4) ||
           !strncmp(device, "vd", 2) ||
           !strncmp(device, "xvd", 3);
}

static void __tune_f2fs(const char *dir, const char *device, const char *node,
                        const char *def, const char *val, bool wr_only) {
    char path[128], buf[32];
    int flags = F_OK | R_OK | W_OK;

    sprintf(path, "%s/%s/%s", dir, device, node);
    chmod(path, 0644);

    if (wr_only)
        flags &= ~R_OK;
    if (access(path, flags) != 0)
        return;

    int fd = xopen(path, wr_only ? O_WRONLY : O_RDWR);
    if (fd < 0)
        return;

    if (!wr_only) {
        ssize_t len;
        len = xread(fd, buf, sizeof(buf));
        if (buf[len - 1] == '\n')
            buf[len - 1] = '\0';
        if (strncmp(buf, def, len)) {
            // Something else changed this node from the kernel's default.
            // Pass.
            LOGD("tune_f2fs: skip node %s\n", node);
            close(fd);
            return;
        }
    }

    xwrite(fd, val, strlen(val));
    close(fd);

    LOGD("tune_f2fs: %s -> %s\n", path, val);
}

static void tune_f2fs() {
    // Check f2fs sys path
    if (access("/sys/fs/f2fs", F_OK) == 0)
        F2FS_SYSFS_PATH = "/sys/fs/f2fs";
    else if (access("/sys/fs/f2fs_dev", F_OK) == 0)
        F2FS_SYSFS_PATH = "/sys/fs/f2fs_dev";
    else {
        LOGD("tune_f2fs: /sys/fs/f2fs is not found, skip tuning!\n");
        return;
    }
    LOGI("tune_f2fs: %s\n", F2FS_SYSFS_PATH);
    // Tune f2fs sysfs node
    if (auto dir = xopen_dir(F2FS_SYSFS_PATH); dir) {
        for (dirent *entry; (entry = readdir(dir.get()));) {
            if (entry->d_name == "."sv || entry->d_name == ".."sv || !tune_f2fs_target(entry->d_name))
                continue;

            __tune_f2fs(F2FS_SYSFS_PATH, entry->d_name, "cp_interval",
                F2FS_DEF_CP_INTERVAL, F2FS_TUNE_CP_INTERVAL, false);
            __tune_f2fs(F2FS_SYSFS_PATH, entry->d_name, "gc_urgent_sleep_time",
                F2FS_DEF_GC_THREAD_URGENT_SLEEP_TIME, F2FS_TUNE_GC_THREAD_URGENT_SLEEP_TIME, false);
        }
    }

    // Tune block discard limit
    if (auto dir = xopen_dir(BLOCK_SYSFS_PATH); dir) {
        for (dirent *entry; (entry = readdir(dir.get()));) {
            if (entry->d_name == "."sv || entry->d_name == ".."sv || !tune_f2fs_target(entry->d_name))
                continue;

            __tune_f2fs(BLOCK_SYSFS_PATH, entry->d_name, "queue/discard_max_bytes",
                nullptr, TUNE_DISCARD_MAX_BYTES, true);
        }
    }
}


/***********************
 * Boot Stage Handlers *
 ***********************/

extern int disable_deny();

static void post_fs_data() {
    if (!check_data())
        return;

    setup_logfile(true);

    LOGI("** post-fs-data mode running\n");

    db_settings dbs;
    get_db_settings(dbs, ANTI_BOOTLOOP);
    bool coreonly_mode = core_only(false);
    bootloop_protect = dbs[ANTI_BOOTLOOP];

    LOGI("* Unlock device blocks\n");
    unlock_blocks();
    LOGI("* Mount mirrors\n");
    mount_mirrors();
    prune_su_access();

    LOGI("PATH=[%s]\n", getenv("PATH"));

    if (access(SECURE_DIR, F_OK) != 0) {
        LOGE(SECURE_DIR " is not present, abort\n");
        goto early_abort;
    }

    if (!magisk_env()) {
        LOGE("* Magisk environment incomplete, abort\n");
        goto early_abort;
    }

    if (getprop("persist.sys.safemode", true) == "1" ||
        getprop("ro.sys.safemode") == "1" || check_key_combo() || should_skip_all()) {
        boot_state |= FLAG_SAFE_MODE;
        LOGI("** Safe mode triggered\n");
        // Disable all modules and denylist so next boot will be clean
        disable_modules();
        disable_deny();
        prepare_modules();
    } else {
        get_db_settings(dbs, ZYGISK_CONFIG);
        get_db_settings(dbs, WHITELIST_CONFIG);
        get_db_settings(dbs, DENYLIST_CONFIG);

        if(coreonly_mode){
            LOGI("** Core-only mode, ignore modules\n");
            // Core-only mode only disable modules
            boot_state |= FLAG_SAFE_MODE;
            disable_modules();
            // we still allow zygisk
            zygisk_enabled = dbs[ZYGISK_CONFIG];
            sulist_enabled = dbs[DENYLIST_CONFIG] && dbs[WHITELIST_CONFIG];
            initialize_denylist();
            prepare_modules();
            goto early_abort;
        }
        if (bootloop_protect) {
            if (!check_bootloop("boot_record", COUNT_FAILBOOT,3))
                LOGE("cannot record boot\n");
        }
        exec_common_scripts("post-fs-data");

        zygisk_enabled = dbs[ZYGISK_CONFIG];
        sulist_enabled = dbs[DENYLIST_CONFIG] && dbs[WHITELIST_CONFIG];
        initialize_denylist();
        handle_modules();
    }

early_abort:
    // We still do magic mount because root itself might need it
    load_modules();
    boot_state |= FLAG_POST_FS_DATA_DONE;
}

static void late_start() {
    setup_logfile(false);

    LOGI("** late_start service mode running\n");

    exec_common_scripts("service");
    exec_module_scripts("service");

    boot_state |= FLAG_LATE_START_DONE;
}

static void boot_complete() {
    boot_state |= FLAG_BOOT_COMPLETE;
    setup_logfile(false);

    LOGI("** boot-complete triggered\n");
    rm_rf(COUNT_FAILBOOT);
    tune_f2fs();

    // At this point it's safe to create the folder
    if (access(SECURE_DIR, F_OK) != 0)
        xmkdir(SECURE_DIR, 0700);

    // Ensure manager exists
    check_pkg_refresh();
    get_manager(0, nullptr, true);
}

void boot_stage_handler(int code) {
    // Make sure boot stage execution is always serialized
    static pthread_mutex_t stage_lock = PTHREAD_MUTEX_INITIALIZER;
    mutex_guard lock(stage_lock);

    switch (code) {
    case MainRequest::POST_FS_DATA:
        if ((boot_state & FLAG_POST_FS_DATA_DONE) == 0)
            post_fs_data();
        close(xopen(UNBLOCKFILE, O_RDONLY | O_CREAT, 0));
        break;
    case MainRequest::LATE_START:
        if ((boot_state & FLAG_POST_FS_DATA_DONE) && (boot_state & FLAG_SAFE_MODE) == 0)
            late_start();
        break;
    case MainRequest::BOOT_COMPLETE:
        if ((boot_state & FLAG_SAFE_MODE) == 0)
            boot_complete();
        break;
    default:
        __builtin_unreachable();
    }
}

void perform_check_bootloop() {
    db_settings dbs;
    get_db_settings(dbs, ANTI_BOOTLOOP);
    if (((boot_state & FLAG_BOOT_COMPLETE) == 0 && bootloop_protect)){
        ztrigger_count++;
        if (ztrigger_count >= 8){
            reboot_coreonly();
        }
    }
}
