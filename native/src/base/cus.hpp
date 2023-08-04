#pragma once
#include <sys/wait.h>
#include <signal.h>

bool is_dir_exist(const char *s);

int bind_mount_(const char *from, const char *to);
int tmpfs_mount(const char *from, const char *to);
char *random_strc(int n = 8);
int get_random(int from=0, int to=9999);
long xptrace(int request, pid_t pid, void *addr = nullptr, void *data = nullptr);
static inline long xptrace(int request, pid_t pid, void *addr, uintptr_t data) {
    return xptrace(request, pid, addr, reinterpret_cast<void *>(data));
}
#define WEVENT(s) (((s) & 0xffff0000) >> 16)
int setcurrent(const char *con);
std::string getcurrent();
