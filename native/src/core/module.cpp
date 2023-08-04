#include <sys/mount.h>
#include <map>
#include <utility>
#include <unistd.h>
#include <limits.h>
#include <string>

#include <base.hpp>
#include <magisk.hpp>
#include <daemon.hpp>
#include <selinux.hpp>
#include <resetprop.hpp>

#include <libgen.h>

#include "core.hpp"
#include "node.hpp"
#include "zygisk/zygisk.hpp"

using namespace std;

static bool log_enabled = true;

#define VLOGD(tag, from, to) if (log_enabled) LOGD("%-8s: %s <- %s\n", tag, to, from)

#define DVLOGD(tag, target) if (log_enabled) LOGD("%-8s: %s\n", tag, target)

static int bind_mount(const char *reason, const char *from, const char *to) {
    int ret = xmount(from, to, nullptr, MS_BIND | MS_REC, nullptr);
    if (ret == 0)
        VLOGD(reason, from, to);
    return ret;
}

string node_entry::module_mnt;
string node_entry::mirror_dir;

/*************************
 * Node Tree Construction
 *************************/

tmpfs_node::tmpfs_node(node_entry *node) : dir_node(node, this) {
    if (!skip_mirror()) {
        string mirror = mirror_path();
        if (auto dir = open_dir(mirror.data())) {
            set_exist(true);
            for (dirent *entry; (entry = xreaddir(dir.get()));) {
                if (entry->d_type == DT_DIR) {
                    // create a dummy inter_node to upgrade later
                    emplace<inter_node>(entry->d_name, entry->d_name);
                } else {
                    // Insert mirror nodes
                    emplace<mirror_node>(entry->d_name, entry);
                }
            }
        }
    }

    for (auto it = children.begin(); it != children.end(); ++it) {
        // Need to upgrade all inter_node children to tmpfs_node
        if (isa<inter_node>(it->second))
            it = upgrade<tmpfs_node>(it);
    }
}

bool dir_node::prepare() {
    // If direct replace or not exist, mount ourselves as tmpfs
    bool upgrade_to_tmpfs = skip_mirror() || !exist();

    for (auto it = children.begin(); it != children.end();) {
        // We also need to upgrade to tmpfs node if any child:
        // - Target does not exist
        // - Source or target is a symlink (since we cannot bind mount symlink)
        bool cannot_mnt;
        if (struct stat st{}; lstat(it->second->node_path().data(), &st) != 0) {
            cannot_mnt = true;
        } else {
            it->second->set_exist(true);
            cannot_mnt = it->second->is_lnk() || S_ISLNK(st.st_mode);
        }

        if (cannot_mnt) {
            if (_node_type > type_id<tmpfs_node>()) {
                // Upgrade will fail, remove the unsupported child node
                DVLOGD("skip", it->second->node_path().data());
                delete it->second;
                it = children.erase(it);
                continue;
            }
            upgrade_to_tmpfs = true;
        }
        if (auto dn = dyn_cast<dir_node>(it->second)) {
            if (skip_mirror()) {
                // Propagate skip mirror state to all children
                dn->set_skip_mirror(true);
            }
            if (dn->prepare()) {
                // Upgrade child to tmpfs
                it = upgrade<tmpfs_node>(it);
            }
        }
        ++it;
    }
    return upgrade_to_tmpfs;
}

void dir_node::collect_module_files(const char *module, int dfd) {
    auto dir = xopen_dir(xopenat(dfd, name().data(), O_RDONLY | O_CLOEXEC));
    if (!dir)
        return;

    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        if (entry->d_name == ".replace"sv) {
            set_skip_mirror(true);
            continue;
        }

        if (entry->d_type == DT_DIR) {
            inter_node *node;
            if (auto it = children.find(entry->d_name); it == children.end()) {
                node = emplace<inter_node>(entry->d_name, entry->d_name);
            } else {
                node = dyn_cast<inter_node>(it->second);
            }
            if (node) {
                node->collect_module_files(module, dirfd(dir.get()));
            }
        } else {
            emplace<module_node>(entry->d_name, module, entry);
        }
    }
}

/************************
 * Mount Implementations
 ************************/

static std::string do_readlink(std::string const& path) {
    char buff[PATH_MAX];
    ssize_t len = ::readlink(path.c_str(), buff, sizeof(buff)-1);
    if (len != -1) {
      buff[len] = '\0';
      return std::string(buff);
    }
}

void node_entry::create_and_mount(const char *reason, const string &src) {
    const string &dest = node_path();
    if (is_lnk()) {
        if (strcmp(do_readlink(src).data(), "/xxxxx") != 0){
            VLOGD("cp_link", src.data(), dest.data());
            cp_afc(src.data(), dest.data());
        } else DVLOGD("remove", dest.data());
    } else {
        if (is_dir())
            xmkdir(dest.data(), 0);
        else if (is_reg())
            close(xopen(dest.data(), O_RDONLY | O_CREAT | O_CLOEXEC, 0));
        else
            return;
        bind_mount(reason, src.data(), dest.data());
    }
}

void mirror_node::mount() {
    create_and_mount("mirror", mirror_path());
}

void module_node::mount() {
    string src = module_mnt + module + parent()->root()->prefix + node_path();
    if (exist())
        clone_attr(mirror_path().data(), src.data());
    if (isa<tmpfs_node>(parent()))
        create_and_mount("module", src);
    else
        bind_mount("module", src.data(), node_path().data());
}

void tmpfs_node::mount() {
    string src = mirror_path();
    const string &dest = node_path();
    file_attr a{};
    if (access(src.data(), F_OK) == 0)
        getattr(src.data(), &a);
    else
        getattr(parent()->node_path().data(), &a);
    if (!isa<tmpfs_node>(parent())) {
        auto worker_dir = MAGISKTMP + "/" WORKERDIR + dest;
        mkdirs(worker_dir.data(), 0);
        create_and_mount(skip_mirror() ? "replace" : "tmpfs", worker_dir);
    } else {
        // We don't need another layer of tmpfs if parent is tmpfs
        mkdir(dest.data(), 0);
    }
    setattr(dest.data(), &a);
    dir_node::mount();
}

/****************
 * Magisk Stuffs
 ****************/

class magisk_node : public node_entry {
public:
    explicit magisk_node(const char *name) : node_entry(name, DT_REG, this) {}

    void mount() override {
        const string src = MAGISKTMP + "/" + name();
        if (access(src.data(), F_OK))
            return;

        const string &dir_name = parent()->node_path();
        if (name() == "magisk") {
            for (int i = 0; applet_names[i]; ++i) {
                string dest = dir_name + "/" + applet_names[i];
                VLOGD("create", "./magisk", dest.data());
                xsymlink("./magisk", dest.data());
            }
        } else {
            string dest = dir_name + "/supolicy";
            VLOGD("create", "./magiskpolicy", dest.data());
            xsymlink("./magiskpolicy", dest.data());
        }
        create_and_mount("magisk", src);
    }
};

static void inject_magisk_bins(root_node *system) {
    auto bin = system->get_child<inter_node>("bin");
    if (!bin) {
        bin = new inter_node("bin");
        system->insert(bin);
    }

    // Insert binaries
    bin->insert(new magisk_node("magisk"));
    bin->insert(new magisk_node("magiskpolicy"));

    // Also delete all applets to make sure no modules can override it
    for (int i = 0; applet_names[i]; ++i)
        delete bin->extract(applet_names[i]);
    delete bin->extract("supolicy");
}

#include <embed.hpp>
#include <wait.h>

std::string orig_native_bridge = "0";
std::string nb_replace_lib = "0";
std::string nb_replace_bak = "0";
std::string zygotemode;
static bool nb_replace = false;

static int extract_bin(const char *prog, const char *dst) {
    int pid = xfork();
    int status;
    if (pid == 0) {
        execl(prog, "", "zygisk", "extract", dst, nullptr);
        PLOGE("execl");
        exit(-2);
    } else if (pid > 0) {
        waitpid(pid, &status, 0);
        return WEXITSTATUS(status);
    } else {
        return -1;
    }
}

class zygisk_node : public node_entry {
public:
    explicit zygisk_node(const char *name) : node_entry(name, DT_REG, this) {}

    void mount() override {
        string src = MAGISKTMP + "/" ZYGISKBIN "/" + name();
        const string &dir_name = parent()->node_path();
        bool is_64bit = dir_name == "/system/lib64";
        src += is_64bit ? ".64" : ".32";
        string mbin = MAGISKTMP + "/magisk" + (is_64bit ? "64" : "32");
        if (name() == LOADER_LIB || name() == nb_replace_lib) {
            int r = extract_bin(mbin.data(), src.data());
            if (r) {
                LOGE("failed to extract zygisk-ld (%d)\n", r);
                return;
            }
            if (chmod(src.data(), 0644) < 0) PLOGE("chmod");
            if (setfilecon(src.data(), "u:object_r:system_file:s0") < 0) PLOGE("setfilecon");
            string replace_new = dir_name + "/" + zygotemode;
            symlink(name().data(), replace_new.data());
        } else if (name() == ZYGISK_LIB) {
            int f = xopen(mbin.data(), O_RDONLY | O_CLOEXEC);
            int out = xopen(src.data(), O_CREAT | O_WRONLY | O_CLOEXEC, 0);
            xsendfile(out, f, nullptr, INT_MAX);
            close(f);
            close(out);
            if (chmod(src.data(), 0644) < 0) PLOGE("chmod");
            if (setfilecon(src.data(), "u:object_r:system_file:s0") < 0) PLOGE("setfilecon");
        } else if (name() == nb_replace_bak) {
            src = MAGISKTMP + "/" MIRRDIR + dir_name + "/" + nb_replace_lib;
        }
        create_and_mount("zygisk", src);
    }
};

vector<module_info> *module_list;

static void inject_zygisk_libs(root_node *system) {
#define INJECT(bit, lib_path) \
    if (access("/system/bin/app_process" #bit , F_OK) == 0) { \
        auto lib =  system->get_child<inter_node>(lib_path); \
        if (!lib) { \
            lib = new inter_node(lib_path); \
            system->insert(lib); \
        } \
        if (nb_replace) { \
            lib->insert(new zygisk_node(nb_replace_lib.data())); \
            lib->insert(new zygisk_node(nb_replace_bak.data())); \
        } else { \
            lib->insert(new zygisk_node(LOADER_LIB)); \
        } \
        lib->insert(new zygisk_node(ZYGISK_LIB)); \
        delete lib->extract(zygotemode.data()); \
    }
    zygotemode = getprop("ro.zygote");
    INJECT(64, "lib64")
    INJECT(32, "lib")
    
}

static bool find_lib(const char *lib){
    string lib32 = "/system/lib/"s + lib;
    string lib64 = "/system/lib64/"s + lib;
    return access(lib32.data(), F_OK) == 0 ||
           access(lib64.data(), F_OK) == 0;
}

static void prepare_replace_nb(){
    LOGD("zygisk: replace native bridge [%s]\n", nb_replace_lib.data());
    nb_replace = true;
    char *ranc;
    do {
        ranc = random_strc(get_random(5,16));
        nb_replace_bak = "lib"s + ranc + ".so";
        delete ranc;
    } while (find_lib(nb_replace_bak.data()));
    LOGD("zygisk: backup native bridge [%s]\n", nb_replace_bak.data());
}

static void zygisk_patch_props() {
    if (!nb_replace_lib.empty() && nb_replace_lib != "0"){
        setprop(NATIVE_BRIDGE_PROP, nb_replace_lib.data(), false);
    } else {
        setprop(NATIVE_BRIDGE_PROP, LOADER_LIB, false);
    }
}

void load_modules() {
    node_entry::mirror_dir = MAGISKTMP + "/" MIRRDIR;
    node_entry::module_mnt = MAGISKTMP + "/" MODULEMNT "/";

    auto root = make_unique<root_node>("");
    auto system = new root_node("system");
    root->insert(system);

    char buf[4096];
    LOGI("* Loading modules\n");
    for (const auto &m : *module_list) {
        const char *module = m.name.data();
        string module_mnt_dir = MAGISKTMP + "/" MODULEMNT "/" + module;
        char *b = buf + sprintf(buf, "%s/", module_mnt_dir.data());
        // Read props
        strcpy(b, "system.prop");
        if (access(buf, F_OK) == 0) {
            LOGI("%s: loading [system.prop]\n", module);
            load_prop_file(buf, false);
        }

        // Check whether skip mounting
        strcpy(b, "skip_mount");
        if (access(buf, F_OK) == 0)
            continue;

        // Double check whether the system folder exists
        strcpy(b, "system");
        if (access(buf, F_OK) != 0)
            continue;

        LOGI("%s: loading mount files\n", module);
        b[-1] = '\0';
        int fd = xopen(buf, O_RDONLY | O_CLOEXEC);
        system->collect_module_files(module, fd);
        close(fd);
    }
    if (MAGISKTMP != "/sbin" || !check_envpath("/sbin")) {
        // Need to inject our binaries into /system/bin
        LOGD("su_mount: load magisk files\n");
        inject_magisk_bins(system);
    }

    // Mount on top of modules to enable zygisk
    if (zygisk_enabled) {
        orig_native_bridge = getprop(NATIVE_BRIDGE_PROP);

        // NoxPlayer Android 9 hardcoded native bridge name
        // But NATIVE_BRIDGE_PROP is "0"
        if (orig_native_bridge == "0" && find_lib("libnb.so")) {
            // directly replace libnb.so
            nb_replace_lib = "libnb.so";
            prepare_replace_nb();
        }

        string zygisk_bin = MAGISKTMP + "/" ZYGISKBIN;
        mkdir(zygisk_bin.data(), 0);
        inject_zygisk_libs(system);
    }

    if (!system->is_empty()) {
        // Handle special read-only partitions
        for (const char *part : { SPEC_PARTS, OTHER_PARTS }) {
            struct stat st{};
            if (lstat(part, &st) == 0 && S_ISDIR(st.st_mode)) {
                if (auto old = system->extract(part + 1)) {
                    auto new_node = new root_node(old);
                    root->insert(new_node);
                }
            }
        }
        root->prepare();
        root->mount();
    }

    if (zygisk_enabled) {
        zygisk_patch_props();
    }

    log_enabled = false;
}

void su_mount() {
    log_enabled = false;
    node_entry::mirror_dir = MAGISKTMP + "/" MIRRDIR;
    node_entry::module_mnt = MAGISKTMP + "/" MODULEMNT "/";

    auto root = make_unique<root_node>("");
    auto system = new root_node("system");
    root->insert(system);

    char buf[4096];
    for (const auto &m : *module_list) {
        const char *module = m.name.data();
        string module_mnt_dir = MAGISKTMP + "/" MODULEMNT "/" + module;
        char *b = buf + sprintf(buf, "%s/", module_mnt_dir.data());
        // Check whether skip mounting
        strcpy(b, "skip_mount");
        if (access(buf, F_OK) == 0)
            continue;

        // Double check whether the system folder exists
        strcpy(b, "system");
        if (access(buf, F_OK) != 0)
            continue;

        LOGD("%s: loading mount files\n", module);
        b[-1] = '\0';
        int fd = xopen(buf, O_RDONLY | O_CLOEXEC);
        system->collect_module_files(module, fd);
        close(fd);
    }
    if (MAGISKTMP != "/sbin" || !check_envpath("/sbin")) {
        // Need to inject our binaries into /system/bin
        LOGD("su_mount: load magisk files\n");
        inject_magisk_bins(system);
    }

    if (!system->is_empty()) {
        // Handle special read-only partitions
        for (const char *part : { SPEC_PARTS, OTHER_PARTS }) {
            struct stat st{};
            if (lstat(part, &st) == 0 && S_ISDIR(st.st_mode)) {
                if (auto old = system->extract(part + 1)) {
                    auto new_node = new root_node(old);
                    root->insert(new_node);
                }
            }
        }
        root->prepare();
        root->mount();
    }
}

/************************
 * Filesystem operations
 ************************/

void prepare_modules() {
    // Upgrade modules
    if (auto dir = open_dir(MODULEUPGRADE); dir) {
        int ufd = dirfd(dir.get());
        int mfd = xopen(MODULEROOT, O_RDONLY | O_CLOEXEC);
        for (dirent *entry; (entry = xreaddir(dir.get()));) {
            if (entry->d_type == DT_DIR) {
                // Cleanup old module if exists
                if (faccessat(mfd, entry->d_name, F_OK, 0) == 0) {
                    int modfd = xopenat(mfd, entry->d_name, O_RDONLY | O_CLOEXEC);
                    if (faccessat(modfd, "disable", F_OK, 0) == 0) {
                        auto disable = entry->d_name + "/disable"s;
                        close(xopenat(ufd, disable.data(), O_RDONLY | O_CREAT | O_CLOEXEC, 0));
                    }
                    frm_rf(modfd);
                    unlinkat(mfd, entry->d_name, AT_REMOVEDIR);
                }
                LOGI("Upgrade / New module: %s\n", entry->d_name);
                renameat(ufd, entry->d_name, mfd, entry->d_name);
            }
        }
        close(mfd);
        rm_rf(MODULEUPGRADE);
    }
}

template<typename Func>
static void foreach_module(Func fn) {
    auto dir = open_dir(MODULEROOT);
    if (!dir)
        return;

    int dfd = dirfd(dir.get());
    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        if (entry->d_type == DT_DIR && entry->d_name != ".core"sv) {
            int modfd = xopenat(dfd, entry->d_name, O_RDONLY | O_CLOEXEC);
            fn(dfd, entry, modfd);
            close(modfd);
        }
    }
}

static void collect_modules(bool open_zygisk) {
    foreach_module([=](int dfd, dirent *entry, int modfd) {
        if (faccessat(modfd, "remove", F_OK, 0) == 0) {
        	
            LOGI("%s: remove\n", entry->d_name);
            auto uninstaller = MODULEROOT + "/"s + entry->d_name + "/uninstall.sh";
            if (access(uninstaller.data(), F_OK) == 0)
                exec_script(uninstaller.data());
            frm_rf(xdup(modfd));
            unlinkat(dfd, entry->d_name, AT_REMOVEDIR);
            return;
        }
        unlinkat(modfd, "update", 0);
        if (faccessat(modfd, "disable", F_OK, 0) == 0)
            return;

        module_info info;
        if (zygisk_enabled) {
            // Riru and its modules are not compatible with zygisk
            if (entry->d_name == "riru-core"sv || faccessat(modfd, "riru", F_OK, 0) == 0) {
                LOGI("%s: ignore\n", entry->d_name);
                return;
            }
            if (open_zygisk) {
#if defined(__arm__)
                info.z32 = openat(modfd, "zygisk/armeabi-v7a.so", O_RDONLY | O_CLOEXEC);
#elif defined(__aarch64__)
                info.z32 = openat(modfd, "zygisk/armeabi-v7a.so", O_RDONLY | O_CLOEXEC);
                info.z64 = openat(modfd, "zygisk/arm64-v8a.so", O_RDONLY | O_CLOEXEC);
#elif defined(__i386__)
                info.z32 = openat(modfd, "zygisk/x86.so", O_RDONLY | O_CLOEXEC);
#elif defined(__x86_64__)
                info.z32 = openat(modfd, "zygisk/x86.so", O_RDONLY | O_CLOEXEC);
                info.z64 = openat(modfd, "zygisk/x86_64.so", O_RDONLY | O_CLOEXEC);
#else
#error Unsupported ABI
#endif
                unlinkat(modfd, "zygisk/unloaded", 0);
            }
        } else {
            // Ignore zygisk modules when zygisk is not enabled
            if (faccessat(modfd, "zygisk", F_OK, 0) == 0) {
                LOGI("%s: ignore\n", entry->d_name);
                return;
            }
        }
        // Load sepolicy.rule if possible
        string module_mnt_dir = MAGISKTMP + "/" MODULEMNT "/" + entry->d_name;
        string module_rule = MAGISKTMP + "/" MIRRDIR "/sepolicy.rules/" + entry->d_name;
        string module_rulefile = module_mnt_dir + "/sepolicy.rule";
        if (!open_zygisk && access(module_rulefile.data(), F_OK) == 0){
            struct stat st_modulemnt;
            struct stat st_modulerule;
            // if rule file is not found
            if (access(string(module_rule + "/sepolicy.rule").data(), F_OK) != 0) {
                LOGI("%s: applying [sepolicy.rule]\n", entry->d_name);
                char MAGISKPOLICY[PATH_MAX];
                sprintf(MAGISKPOLICY, "%s/magiskpolicy", MAGISKTMP.data());
                auto ret = exec_command_sync(MAGISKPOLICY, "--live", "--apply", module_rulefile.data());
                if (ret != 0) LOGW("%s: failed to apply [sepolicy.rule]\n", entry->d_name);
            }
            if (stat(module_mnt_dir.data(), &st_modulemnt) == 0 &&
                (stat(module_rule.data(), &st_modulerule) != 0 ||
                 st_modulemnt.st_dev != st_modulerule.st_dev ||
                 st_modulemnt.st_ino != st_modulerule.st_ino)) {
                     // refresh rule file
                     LOGI("%s: refresh [sepolicy.rule]\n", entry->d_name);
                     rm_rf(module_rule.data());
                     mkdirs(module_rule.data(), 0755);
                     cp_afc(module_rulefile.data(), string(module_rule + "/sepolicy.rule").data());
            }
        }
        info.name = entry->d_name;
        module_list->push_back(info);
    });
    if (zygisk_enabled) {
        bool use_memfd = true;
        auto convert_to_memfd = [&](int fd) -> int {
            if (fd < 0)
                return -1;
            if (use_memfd) {
                int memfd = syscall(__NR_memfd_create, "jit-cache", MFD_CLOEXEC);
                if (memfd >= 0) {
                    xsendfile(memfd, fd, nullptr, INT_MAX);
                    close(fd);
                    return memfd;
                } else {
                    // memfd_create failed, just use what we had
                    use_memfd = false;
                }
            }
            return fd;
        };
        std::for_each(module_list->begin(), module_list->end(), [&](module_info &info) {
            info.z32 = convert_to_memfd(info.z32);
#if defined(__LP64__)
            info.z64 = convert_to_memfd(info.z64);
#endif
        });
    }
}

void handle_modules() {
    prepare_modules();
    collect_modules(false);
    exec_module_scripts("post-fs-data");

    // Recollect modules (module scripts could remove itself)
    module_list->clear();
    collect_modules(true);
}

static int check_rules_dir(char *buf, size_t sz) {
    int off = ssprintf(buf, sz, "%s/%s", MAGISKTMP.data(), RULESDIR);
    struct stat st1{};
    struct stat st2{};
    if (xstat(buf, &st1) < 0 || xstat(MODULEROOT, &st2) < 0)
        return 0;
    if (st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino)
        return 0;
    return off;
}

void disable_modules() {
    char buf[4096];
    int off = check_rules_dir(buf, sizeof(buf));
    foreach_module([&](int, dirent *entry, int modfd) {
        close(xopenat(modfd, "disable", O_RDONLY | O_CREAT | O_CLOEXEC, 0));
        if (off) {
            ssprintf(buf + off, sizeof(buf) - off, "/%s/sepolicy.rule", entry->d_name);
            unlink(buf);
        }
    });
}

void remove_modules() {
    char buf[4096];
    int off = check_rules_dir(buf, sizeof(buf));
    foreach_module([&](int, dirent *entry, int) {
        auto uninstaller = MODULEROOT + "/"s + entry->d_name + "/uninstall.sh";
        if (access(uninstaller.data(), F_OK) == 0)
            exec_script(uninstaller.data());
        if (off) {
            ssprintf(buf + off, sizeof(buf) - off, "/%s/sepolicy.rule", entry->d_name);
            unlink(buf);
        }
    });
    rm_rf(MODULEROOT);
}

void exec_module_scripts(const char *stage) {
    vector<string_view> module_names;
    std::transform(module_list->begin(), module_list->end(), std::back_inserter(module_names),
        [](const module_info &info) -> string_view { return info.name; });
    exec_module_scripts(stage, module_names);
}

