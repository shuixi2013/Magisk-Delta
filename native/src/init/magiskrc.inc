#include <magisk.hpp>
#include <selinux.hpp>

#define quote(s) #s
#define str(s) quote(s)

constexpr char MAGISK_RC[] =
"\n"

"on post-fs-data\n"
"    start logd\n"
"    rm " UNBLOCKFILE "\n"
"    exec u:r:" SEPOL_PROC_DOMAIN ":s0 root root -- %1$s/magisk --post-fs-data\n"
"    wait " UNBLOCKFILE " " str(POST_FS_DATA_WAIT_TIME) "\n"
"    rm " UNBLOCKFILE "\n"
"\n"

"on nonencrypted\n"
"    exec u:r:" SEPOL_PROC_DOMAIN ":s0 root root -- %1$s/magisk --service\n"
"\n"

"on property:sys.boot_completed=1\n"
"    exec u:r:" SEPOL_PROC_DOMAIN ":s0 root root -- %1$s/magisk --boot-complete\n"
"\n"

"on property:init.svc.zygote=restarting\n"
"    exec u:r:" SEPOL_PROC_DOMAIN ":s0 root root -- %1$s/magisk --zygote-restart\n"
"\n"

"on property:init.svc.zygote=stopped\n"
"    exec u:r:" SEPOL_PROC_DOMAIN ":s0 root root -- %1$s/magisk --zygote-restart\n"
"\n"
;
