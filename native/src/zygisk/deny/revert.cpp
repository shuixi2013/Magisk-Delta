#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#include <magisk.hpp>
#include <daemon.hpp>
#include <base.hpp>
#include <selinux.hpp>

#include "deny.hpp"

#include <link.h>

using namespace std;

static void lazy_unmount(const char* mountpoint) {
    if (umount2(mountpoint, MNT_DETACH) != -1)
        LOGD("hide_daemon: Unmounted (%s)\n", mountpoint);
}

void mount_mirrors();

void root_mount(int pid) {
    if (switch_mnt_ns(pid))
        return;

    LOGD("su_policy: handling PID=[%d]\n", pid);

    xmount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr);

    if (MAGISKTMP == "/sbin") {
        if (is_rootfs()) {
            tmpfs_mount("tmpfs", "/sbin");
            setfilecon("/sbin", "u:object_r:rootfs:s0");
            recreate_sbin_v2("/root", false);
        } else {
            mount_sbin();
        }
    } else {
        mkdir(MAGISKTMP.data(),0755);
        tmpfs_mount("tmpfs", MAGISKTMP.data());
    }

    for (auto file : {"magisk32", "magisk64", "magisk", "magiskpolicy"}) {
        auto src = "/proc/1/root"s + MAGISKTMP + "/"s + file;
        auto dest = MAGISKTMP + "/"s + file;
        if (access(src.data(),F_OK) == 0){
            cp_afc(src.data(), dest.data());
            setfilecon(dest.data(), "u:object_r:" SEPOL_EXEC_TYPE ":s0");
        }
    }
    
    for (int i = 0; applet_names[i]; ++i) {
        string dest = MAGISKTMP + "/" + applet_names[i];
        xsymlink("./magisk", dest.data());
    }
    string dest = MAGISKTMP + "/supolicy";
    xsymlink("./magiskpolicy", dest.data());

    chdir(MAGISKTMP.data());

    xmkdir(INTLROOT, 0755);
    xmkdir(MIRRDIR, 0);
    xmkdir(BLOCKDIR, 0);
    xmkdir(MODULEMNT, 0);

    // in case some apps need to access to some internal files
    string bb_dir = "/proc/1/root/" + MAGISKTMP + "/" BBPATH;
    xsymlink(bb_dir.data(), BBPATH);

    string src = "/proc/1/root/" + MAGISKTMP + "/" INTLROOT "/config";
    cp_afc(src.data(), INTLROOT "/config");

    mount_mirrors();

    xmount(MIRRDIR "/" MODULEROOT, MODULEMNT, nullptr, MS_BIND, nullptr);

    chdir("/");

    su_mount();
}

void su_daemon(int pid) {
    if (fork_dont_care() == 0) {
        root_mount(pid);
        // Send resume signal
        kill(pid, SIGCONT);
        _exit(0);
    }
}

void revert_daemon(int pid, int client) {
    if (fork_dont_care() == 0) {
        revert_unmount(pid);
        if (client >= 0) {
            write_int(client, DenyResponse::OK);
        } else if (client == -1) {
            // send resume signal
            kill(pid, SIGCONT);
        }
        _exit(0);
    }
}

void revert_unmount(int pid) {
    vector<string> targets;
    if (pid > 0) {
        if (switch_mnt_ns(pid))
            return;
        LOGD("magiskhide: handling PID=[%d]\n", pid);
    }
    // unmount sekeleton node
    lazy_unmount(MAGISKTMP.data());
    for (auto &info : parse_mount_info("self")) {
        if (info.root.starts_with("/" INTLROOT "/")) {
            targets.emplace_back(info.target);
        }
    }
    for (auto &s : reversed(targets))
        lazy_unmount(s.data());
    targets.clear();

    // unmount module node
    for (auto &info : parse_mount_info("self")) {
        if (strstr(info.root.data(), "/adb/modules/")) {
            targets.emplace_back(info.target);
        }
    }
    for (auto &s : reversed(targets))
        lazy_unmount(s.data());
    targets.clear();

    // unmount early-mount node
    for (auto &info : parse_mount_info("self")) {
        if (info.root.starts_with("/" INTLROOT "/")) {
            targets.emplace_back(info.target);
        }
    }
    for (auto &s : reversed(targets))
        lazy_unmount(s.data());
}

