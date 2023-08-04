#include <dlfcn.h>
#include <unistd.h>
#include <string_view>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <android/log.h>

#include "zygisk.hpp"
#include "native_bridge_callbacks.h"

#define LOG_TAG "zygisk-ld"

#define LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))

extern "C" [[gnu::visibility("default")]] uint8_t NativeBridgeItf[
        sizeof(NativeBridgeCallbacks<__ANDROID_API_R__>) * 2]{0};

static void *original_bridge = nullptr;

__used __attribute__((destructor)) void Destructor() {
    if (original_bridge) dlclose(original_bridge);
}

__used __attribute__((constructor))

static void zygisk_loader() {
    if (getuid() != 0) {
        return;
    }

    std::string_view cmdline = getprogname();

    if (cmdline != "zygote" &&
        cmdline != "zygote32" &&
        cmdline != "zygote64" &&
        cmdline != "usap32" &&
        cmdline != "usap64") {
        LOGW("zygisk: not zygote (cmdline=%s)\n", cmdline.data());
        return;
    }

    void *handle = dlopen(ZYGISK_LIB, RTLD_LAZY);
    if (handle) {
        auto *entry = reinterpret_cast<void* (*)(void *, void *)>(
                dlsym(handle, "zygisk_inject_entry"));
        if (entry) {
            original_bridge = entry(handle, (void*) &NativeBridgeItf);
        }
    }
}
