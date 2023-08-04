#include <set>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <libgen.h>
#include <unistd.h>

#include <base.hpp>
#include <selinux.hpp>
#include <magisk.hpp>

#include "init.hpp"

using namespace std;

struct devinfo {
    int major;
    int minor;
    char devname[32];
    char partname[32];
    char dmname[32];
};


static const char *preinit_part[]={
        PREINIT_PARTS ,
        nullptr
    };
static const char *mirror_part[]={
        PREINIT_MIRRORS ,
        nullptr
    };

static vector<devinfo> dev_list;

static void parse_device(devinfo *dev, const char *uevent) {
    dev->partname[0] = '\0';
    parse_prop_file(uevent, [=](string_view key, string_view value) -> bool {
        if (key == "MAJOR")
            dev->major = parse_int(value.data());
        else if (key == "MINOR")
            dev->minor = parse_int(value.data());
        else if (key == "DEVNAME")
            strcpy(dev->devname, value.data());
        else if (key == "PARTNAME")
            strcpy(dev->partname, value.data());

        return true;
    });
}

static void collect_devices() {
    char path[128];
    devinfo dev{};
    if (auto dir = xopen_dir("/sys/dev/block"); dir) {
        for (dirent *entry; (entry = readdir(dir.get()));) {
            if (entry->d_name == "."sv || entry->d_name == ".."sv)
                continue;
            sprintf(path, "/sys/dev/block/%s/uevent", entry->d_name);
            parse_device(&dev, path);
            sprintf(path, "/sys/dev/block/%s/dm/name", entry->d_name);
            if (access(path, F_OK) == 0) {
                auto name = rtrim(full_read(path));
                strcpy(dev.dmname, name.data());
            }
            dev_list.push_back(dev);
        }
    }
}

static struct {
    char partname[32];
    char block_dev[64];
} blk_info;

static int64_t setup_block() {
    if (dev_list.empty())
        collect_devices();

    for (int tries = 0; tries < 3; ++tries) {
        for (auto &dev : dev_list) {
            if (strcasecmp(dev.partname, blk_info.partname) == 0)
                LOGD("Setup %s: [%s] (%d, %d)\n", dev.partname, dev.devname, dev.major, dev.minor);
            else if (strcasecmp(dev.dmname, blk_info.partname) == 0)
                LOGD("Setup %s: [%s] (%d, %d)\n", dev.dmname, dev.devname, dev.major, dev.minor);
            else
                continue;

            dev_t rdev = makedev(dev.major, dev.minor);
            xmknod(blk_info.block_dev, S_IFBLK | 0600, rdev);
            return rdev;
        }
        // Wait 10ms and try again
        usleep(10000);
        dev_list.clear();
        collect_devices();
    }

    // The requested partname does not exist
    return -1;
}

static void switch_root(const string &path) {
    LOGD("Switch root to %s\n", path.data());
    int root = xopen("/", O_RDONLY);
    for (set<string, greater<>> mounts; auto &info : parse_mount_info("self")) {
        if (info.target == "/" || info.target == path)
            continue;
        if (auto last_mount = mounts.upper_bound(info.target);
                last_mount != mounts.end() && info.target.starts_with(*last_mount + '/')) {
            continue;
        }
        mounts.emplace(info.target);
        auto new_path = path + info.target;
        xmkdir(new_path.data(), 0755);
        xmount(info.target.data(), new_path.data(), nullptr, MS_MOVE, nullptr);
    }
    chdir(path.data());
    xmount(path.data(), "/", nullptr, MS_MOVE, nullptr);
    chroot(".");

    LOGD("Cleaning rootfs\n");
    frm_rf(root);
}

void MagiskInit::mount_rules_dir() {
    char path[128];
    char mirrpath[1024];
    char current[20];
    char currentblk[20];
    bool success=false;
    xrealpath(BLOCKDIR, blk_info.block_dev, sizeof(blk_info.block_dev));
    xrealpath(MIRRDIR, path, sizeof(path));
    xrealpath(MIRRDIR, mirrpath, sizeof(mirrpath));
    string custom_early_dir = "/data/unencrypted/early-mount.d"s;
    string full_early_dir;
    string tmpdir_;

    char *b = blk_info.block_dev + strlen(blk_info.block_dev);
    char *p = path + strlen(path);

    auto do_mount = [&](const char *type) -> bool {
        xmkdir(path, 0755);
        bool success = xmount(blk_info.block_dev, path, type, 0, nullptr) == 0;
        if (success)
            mount_list.emplace_back(path);
        return success;
    };

    // First try userdata
    strcpy(blk_info.partname, "userdata");
    strcpy(b, "/data");
    strcpy(p, "/data");
    if (setup_block() < 0) {
        // Try NVIDIA naming scheme
        strcpy(blk_info.partname, "UDA");
        if (setup_block() < 0)
            goto cache;
    }
    // WARNING: DO NOT ATTEMPT TO MOUNT F2FS AS IT MAY CRASH THE KERNEL
    // Failure means either f2fs, FDE, or metadata encryption
    if (!do_mount("ext4"))
        goto cache;

    strcpy(p, "/data/unencrypted");
    if (xaccess(path, F_OK) == 0) {
        // FBE, need to use an unencrypted path
        custom_rules_dir = path + "/magisk"s;
    } else {
        // Skip if /data/adb does not exist
        strcpy(p, SECURE_DIR);
        if (xaccess(path, F_OK) != 0)
            return;
        strcpy(p, MODULEROOT);
        if (xaccess(path, F_OK) != 0) {
            goto cache;
        }
        // Unencrypted, directly use module paths
        custom_rules_dir = string(path);
        custom_early_dir = "/data/adb/early-mount.d"s;
    }
    success=true;
    strcpy(currentblk, blk_info.partname);
    strcpy(current, p);

cache:
    // Fallback to cache
    strcpy(blk_info.partname, "cache");
    strcpy(b, "/cache");
    strcpy(p, "/cache");
    if (setup_block() < 0) {
        // Try NVIDIA naming scheme
        strcpy(blk_info.partname, "CAC");
        if (setup_block() < 0)
            goto metadata;
    }
    if (!do_mount("ext4"))
        goto metadata;
    if (!success){
        success=true;
        custom_rules_dir = path + "/magisk"s;
        custom_early_dir = "/cache/early-mount.d"s;
        strcpy(currentblk, blk_info.partname);
        strcpy(current, p);
    }

metadata:
    // Fallback to metadata
    strcpy(blk_info.partname, "metadata");
    strcpy(b, "/metadata");
    strcpy(p, "/metadata");
    if (setup_block() < 0 || !do_mount("ext4"))
        goto persist;
    if (!success){
        success=true;
        custom_rules_dir = path + "/magisk"s;
        custom_early_dir = "/metadata/early-mount.d"s;
        strcpy(currentblk, blk_info.partname);
        strcpy(current, p);
    }

persist:
    // Fallback to persist
    strcpy(blk_info.partname, "persist");
    strcpy(b, "/persist");
    strcpy(p, "/persist");
    if (setup_block() < 0 || !do_mount("ext4"))
        return;
    if (!success){
        success=true;
        custom_rules_dir = path + "/magisk"s;
        custom_early_dir = "/persist/early-mount.d"s;
        strcpy(currentblk, blk_info.partname);
        strcpy(current, p);
    }

success:
    // restore path
    strcpy(blk_info.partname, currentblk);
    strcpy(p, current);
    // Create symlinks so we don't need to go through this logic again
    strcpy(p, "/sepolicy.rules");
    if (char *rel = strstr(custom_rules_dir.data(), MIRRDIR)) {
        // Create symlink with relative path
        char s[128];
        s[0] = '.';
        strscpy(s + 1, rel + sizeof(MIRRDIR) - 1, sizeof(s) - 1);
        xsymlink(s, path);
    } else {
        xsymlink(custom_rules_dir.data(), path);
    }
    
    strcpy(p, "/early-mount");
    full_early_dir = mirrpath + custom_early_dir;
    xmkdir(full_early_dir.data(), 0755);
    xmkdir(custom_rules_dir.data(), 0755);
    xmkdir(string(full_early_dir + "/initrc.d").data(), 0755);
    custom_early_dir = "."s + custom_early_dir;
    xsymlink(custom_early_dir.data(), path);
    cp_afc(full_early_dir.data(), INTLROOT "/early-mount.d");

    char buf[4098];
    for (int i = 0; preinit_part[i]; i++) {
        ssprintf(buf, sizeof(buf), "%s%s/.disable_magisk",
                 mirrpath, preinit_part[i]);
        if (access(buf, F_OK) == 0) {
            for (int i = 0; mirror_part[i]; i++) {
                ssprintf(buf, sizeof(buf), "%s%s", mirrpath, mirror_part[i]);
                umount2(buf, MNT_DETACH);
            }
            return;
        }
    }
}

bool LegacySARInit::mount_system_root() {
    LOGD("Mounting system_root\n");

    // there's no /dev in stub cpio
    xmkdir("/dev", 0777);

    strcpy(blk_info.block_dev, "/dev/root");

    do {
        // Try legacy SAR dm-verity
        strcpy(blk_info.partname, "vroot");
        auto dev = setup_block();
        if (dev >= 0)
            goto mount_root;

        // Try NVIDIA naming scheme
        strcpy(blk_info.partname, "APP");
        dev = setup_block();
        if (dev >= 0)
            goto mount_root;

        sprintf(blk_info.partname, "system%s", config->slot);
        dev = setup_block();
        if (dev >= 0)
            goto mount_root;

        // Poll forever if rootwait was given in cmdline
    } while (config->rootwait);

    // We don't really know what to do at this point...
    LOGE("Cannot find root partition, abort\n");
    exit(1);

mount_root:
    xmkdir("/system_root", 0755);

    if (xmount("/dev/root", "/system_root", "ext4", MS_RDONLY, nullptr)) {
        if (xmount("/dev/root", "/system_root", "erofs", MS_RDONLY, nullptr)) {
            // We don't really know what to do at this point...
            LOGE("Cannot mount root partition, abort\n");
            exit(1);
        }
    }

    switch_root("/system_root");

    // Make dev writable
    xmount("tmpfs", "/dev", "tmpfs", 0, "mode=755");
    mount_list.emplace_back("/dev");

    // Use the apex folder to determine whether 2SI (Android 10+)
    bool is_two_stage = access("/apex", F_OK) == 0;
    LOGD("is_two_stage: [%d]\n", is_two_stage);

#if ENABLE_AVD_HACK
    if (!is_two_stage) {
        if (config->emulator) {
            avd_hack = true;
            // These values are hardcoded for API 28 AVD
            xmkdir("/dev/block", 0755);
            strcpy(blk_info.block_dev, "/dev/block/vde1");
            strcpy(blk_info.partname, "vendor");
            setup_block();
            xmount(blk_info.block_dev, "/vendor", "ext4", MS_RDONLY, nullptr);
        }
    }
#endif

    return is_two_stage;
}

void BaseInit::exec_init() {
    // Unmount in reverse order
    for (auto &p : reversed(mount_list)) {
        if (xumount2(p.data(), MNT_DETACH) == 0)
            LOGD("Unmount [%s]\n", p.data());
    }
    execv("/init", argv);
    exit(1);
}

void BaseInit::prepare_data() {
    LOGD("Setup data tmp\n");
    xmkdir("/data", 0755);
    xmount("tmpfs", "/data", "tmpfs", 0, "mode=755");

    cp_afc("/init", "/data/magiskinit");
    cp_afc("/.backup", "/data/.backup");
    cp_afc("/overlay.d", "/data/overlay.d");
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


void early_mount(const char *magisk_tmp){
    LOGI("** early-mount start\n");
    char buf[4098];
    const char *part[]={
        SPEC_PARTS ,
        nullptr
    };

    for (int i = 0; preinit_part[i]; i++) {
        ssprintf(buf, sizeof(buf), "%s/" MIRRDIR "%s/.disable_magisk",
                 magisk_tmp, preinit_part[i]);
        if (access(buf, F_OK) == 0) return;
    }

    ssprintf(buf, sizeof(buf), "%s/" MIRRDIR "/early-mount", magisk_tmp);
    fsetfilecon(xopen(buf, O_RDONLY | O_CLOEXEC), "u:object_r:system_file:s0");
    sprintf(buf, "%s/" MIRRDIR "/early-mount/skip_mount", magisk_tmp);
    if (access(buf, F_OK) == 0) return;

    // SYSTEM
    ssprintf(buf, sizeof(buf), "%s/" INTLROOT "/early-mount.d/system", magisk_tmp);
    if (access(buf, F_OK) == 0)
    	simple_mount(buf, "/system");

    // VENDOR, PRODUCT, SYSTEM_EXT
    for (int i=0; part[i];i++) {
        ssprintf(buf, sizeof(buf), "%s/" INTLROOT "/early-mount.d/system%s",
                 magisk_tmp, part[i]);
        if (access(buf, F_OK) == 0 && !system_lnk(part[i]))
            simple_mount(buf, part[i]);
    }
}

void MagiskInit::setup_tmp(const char *path) {
    LOGD("Setup Magisk tmp at %s\n", path);
    chdir("/data");

    xmkdir(INTLROOT, 0755);
    xmkdir(MIRRDIR, 0);
    xmkdir(BLOCKDIR, 0);
    xmkdir(WORKERDIR, 0);

    mount_rules_dir();
    early_mount("/data");

    cp_afc(".backup/.magisk", INTLROOT "/config");
    rm_rf(".backup");

    // Create applet symlinks
    for (int i = 0; applet_names[i]; ++i)
        xsymlink("./magisk", applet_names[i]);
    xsymlink("./magiskpolicy", "supolicy");

    xmount(".", path, nullptr, MS_BIND, nullptr);

    chdir("/");
}
