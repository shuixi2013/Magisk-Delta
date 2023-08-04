#pragma once

#include <string>

// magiskinit will hex patch this constant,
// appending \0 to prevent the compiler from reusing the string for "1"
#define MAIN_SOCKET  "d30138f2310a9fb9c54a3e0c21f58591\0"
#define JAVA_PACKAGE_NAME "io.github.huskydg.magisk"
#define LOGFILE         "/cache/magisk.log"
#define UNBLOCKFILE     "/dev/.magisk_unblock"
#define SECURE_DIR      "/data/adb"
#define MODULEROOT      SECURE_DIR "/modules"
#define MODULEUPGRADE   SECURE_DIR "/modules_update"
#define DATABIN         SECURE_DIR "/magisk"
#define MAGISKDB        SECURE_DIR "/magisk.db"

// tmpfs paths
extern std::string  MAGISKTMP;
#define INTLROOT    ".magisk"
#define MIRRDIR     INTLROOT "/mirror"
#define RULESDIR    MIRRDIR "/sepolicy.rules"
#define BLOCKDIR    INTLROOT "/block"
#define WORKERDIR   INTLROOT "/worker"
#define MODULEMNT   INTLROOT "/modules"
#define BBPATH      INTLROOT "/busybox"
#define ROOTOVL     INTLROOT "/rootdir"
#define WORKERDIR   INTLROOT "/worker"
#define SHELLPTS    INTLROOT "/pts"
#define ROOTMNT     ROOTOVL  "/.mount_list"
#define ZYGISKBIN   INTLROOT "/zygisk"
#define SELINUXMOCK INTLROOT "/selinux"

constexpr const char *applet_names[] = { "su", "resetprop", "magiskhide", nullptr };

#define SPEC_PARTS \
    "/vendor", \
    "/system_ext", \
    "/product"

#define OTHER_PARTS \
    "/my_carrier", \
    "/my_company", \
    "/my_engineering", \
    "/my_heytap", \
    "/my_preload", \
    "/my_product", \
    "/my_region", \
    "/my_stock", \
    "/prism", \
    "/optics", \
    "/odm", \
    "/my_manifest", \
    "/system_dlkm", \
    "/odm_dlkm", \
    "/vendor_dlkm"

#define RO_PARTS "/system", SPEC_PARTS, OTHER_PARTS

#define MIRRORS "/cache", "/data", "/metadata", "/persist", RO_PARTS

#define PREINIT_MIRRORS "/data", "/persist", "/metadata", "/cache"
#define PREINIT_PARTS "/data/unencrypted", "/data/adb", "/persist", "/metadata", "/cache"

#define POST_FS_DATA_WAIT_TIME       40
#define POST_FS_DATA_SCRIPT_MAX_TIME 35

#define SYSTEMDIR    "/system"
#define LIBDIR       SYSTEMDIR "/lib"
#define LIB64DIR     LIBDIR "64"
#define LIBRUNTIME32 LIBDIR "/libandroid_runtime.so"
#define LIBRUNTIME64 LIB64DIR "/libandroid_runtime.so"

extern int SDK_INT;
extern bool HAVE_32;
#define APP_DATA_DIR (SDK_INT >= 24 ? "/data/user_de" : "/data/user")

// Multi-call entrypoints
int magisk_main(int argc, char *argv[]);
int denylist_cli(int argc, char *argv[]);
int su_client_main(int argc, char *argv[]);
int resetprop_main(int argc, char *argv[]);
int zygisk_main(int argc, char *argv[]);
bool check_envpath(const char* path);
void recreate_sbin_v2(const char *mirror, bool use_bind_mount);
bool is_rootfs();
