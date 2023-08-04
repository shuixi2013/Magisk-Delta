#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <iostream>

#include <base.hpp>

#define GET_CURRENT_FAILED "null"
#define SET_CURRENT_FAILED -1
#define SET_CURRENT_SUCCESS 0
#define READ 0
#define WRITE 1

#define VLOGDG(tag, from, to) LOGD("%-8s: %s <- %s\n", tag, to, from)

using namespace std;

std::string getcurrent() {
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd < 0) return GET_CURRENT_FAILED;
    char buf[1024] = {};
    read(fd, buf, sizeof(buf));
    return std::string(buf);
}

int setcurrent(const char *con) {
    int fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd < 0) return SET_CURRENT_FAILED;
    return (write(fd, con, strlen(con)+1) > 0)? SET_CURRENT_SUCCESS : SET_CURRENT_FAILED;
}



bool is_dir_exist(const char *s){
    struct stat st;
    if(stat(s,&st) == 0)
        if((st.st_mode & S_IFDIR) != 0)
            return true;
    return false;
}

int bind_mount_(const char *from, const char *to) {
    int ret = xmount(from, to, nullptr, MS_BIND, nullptr);
    if (ret == 0)
        VLOGDG("bind_mnt", from, to);
    return ret;
}

int tmpfs_mount(const char *from, const char *to){
    int ret = xmount(from, to, "tmpfs", 0, "mode=755");
    if (ret == 0)
        VLOGDG("mnt_tmp", "tmpfs", to);
    return ret;
}

// implement my own method to get only lowercase string
char *random_strc(int n){
    FILE *urandom = fopen("/dev/urandom", "re");
    if (urandom == nullptr) return nullptr;
    char *str = new char[n+1];
    if (str == nullptr) {
        fclose(urandom);
        return nullptr;
    }
    for (int i=0;i<n;i++){
        str[i] = 'a' + (fgetc(urandom) % ('z'-'a'+1));
    }
    fclose(urandom);
    return str;
}

int get_random(int from, int to){
    FILE *urandom = fopen("/dev/urandom", "re");
    if (urandom == nullptr) return from;
    int tmp, s=0, n = to-from+1;
    while (n!=0){
        do {
            tmp = fgetc(urandom);
        } while ( !(tmp >= '0' && tmp <= '9') );
        s = s*10 + tmp - '0';
        n/=10;
    }
    return from + s % (to-from+1);
}

long xptrace(int request, pid_t pid, void *addr, void *data) {
    long ret = ptrace(request, pid, addr, data);
    if (ret < 0)
        PLOGE("ptrace %d", pid);
    return ret;
}

