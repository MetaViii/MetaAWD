// Based on pwn_waf by i0gan: https://github.com/i0gan/pwn_waf
// MIT License. See the bundled LICENSE file.

#include "waf.h"

static const char logo_str[] = "// CTF AWD PWN WAF\n// Deved By I0gan\n";
static const char read_str[] = "\n<-------------------- read ------------------>\n";
static const char write_str[] = "\n<-------------------- write ----------------->\n";
static const char dangerous_str[] = "\n<-------------- dangerous syscall------------>\n";
static enum log_state waf_log_state = LOG_NONE_;
static int waf_write_times = 0;
static int waf_read_times = 0;

int write_all(int fd, const void *buffer, size_t length) {
    const char *cursor = buffer;
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, cursor + written, length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        written += (size_t)count;
    }
    return 0;
}

void waf_write_logo(void) {
#if LOG_METHOD == CLOSE
    return;
#else
    char time_str[128] = {0};
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t now = tv.tv_sec;
    struct tm *local = localtime(&now);
    strftime(time_str, sizeof(time_str), "// Date: %Y-%m-%d %H:%M:%S\n", local);
    logger_write(time_str, strlen(time_str));
#if RUN_MODE == CATCH
    logger_write(MODE_CATCH_STR, strlen(MODE_CATCH_STR));
#elif RUN_MODE == I0GAN
    logger_write(MODE_I0GAN_STR, strlen(MODE_I0GAN_STR));
#elif RUN_MODE == FORWARD
    logger_write(MODE_FORWARD_STR, strlen(MODE_FORWARD_STR));
#else
    logger_write(MODE_FORWARD_MULTI_STR, strlen(MODE_FORWARD_MULTI_STR));
#endif
    logger_write(logo_str, sizeof(logo_str) - 1);
#endif
}

void waf_write_hex_log(void) {
#if LOG_METHOD == CLOSE
    return;
#else
    if (logger_size() == 0) return;
    char label[64] = {0};
    if (waf_log_state == LOG_WRITE_) {
        snprintf(label, sizeof(label), "\nw_%d = \"", waf_write_times++);
    } else {
        snprintf(label, sizeof(label), "\nr_%d = \"", waf_read_times++);
    }
    logger_write(label, strlen(label));
    logger_write_buf();
    logger_write("\"\n", 2);
#endif
}

void waf_log_open(void) {
#if LOG_METHOD == CLOSE
    return;
#else
    char time_str[32] = {0};
    char file_name[512] = {0};
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t now = tv.tv_sec;
    struct tm *local = localtime(&now);
    strftime(time_str, sizeof(time_str), "%H_%M_%S", local);
    snprintf(file_name, sizeof(file_name), "%s/%s_%lx_%ld.log", LOG_PATH, time_str,
             (unsigned long)tv.tv_usec, (long)getpid());
    if (!logger_open(file_name)) exit(EXIT_FAILURE);
#endif
}

static void log_bytes(const char *buffer, size_t length, enum log_state state) {
#if LOG_METHOD == OPEN
    if (length == 0) return;
    if (waf_log_state != state) {
        waf_write_hex_log();
        logger_write(state == LOG_READ_ ? read_str : write_str,
                     state == LOG_READ_ ? sizeof(read_str) - 1 : sizeof(write_str) - 1);
        waf_log_state = state;
    }
    logger_append_hex(buffer, (int)length);
    logger_write(buffer, (int)length);
#else
    (void)buffer;
    (void)length;
    (void)state;
#endif
}

void waf_interactive_log(pid_t pid, uintptr_t address, size_t size, enum log_state state) {
#if LOG_METHOD == OPEN
    if (size == 0 || size > (size_t)INT32_MAX) return;
    char *buffer = malloc(size);
    if (!buffer) return;
    size_t copied = 0;
    while (copied < size) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(address + copied), NULL);
        if (word == -1 && errno != 0) break;
        size_t chunk = size - copied < sizeof(word) ? size - copied : sizeof(word);
        memcpy(buffer + copied, &word, chunk);
        copied += chunk;
    }
    log_bytes(buffer, copied, state);
    free(buffer);
#else
    (void)pid;
    (void)address;
    (void)size;
    (void)state;
#endif
}

static int dangerous_syscall(long number) {
    return number == __NR_open || number == __NR_clone || number == __NR_execve;
}

void bin_waf_run(int argc, char *argv[]) {
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return;
    }
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        size_t count = (size_t)argc + 1;
        char **child_argv = calloc(count, sizeof(char *));
        if (!child_argv) _exit(127);
        child_argv[0] = (char *)LISTEN_ELF;
        for (int i = 1; i < argc; i++) child_argv[i] = argv[i];
        execv(LISTEN_ELF, child_argv);
        perror("exec");
        _exit(127);
    }

    int status = 0;
    int entering = 1;
    int dangerous_count = 1;  // The initial execve completed at the first trace stop.
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) return;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) < 0
            || ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return;
    }
    while (1) {
        if (waitpid(child, &status, 0) < 0) break;
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        if (!WIFSTOPPED(status)) continue;
        int stop_signal = WSTOPSIG(status);
        if (stop_signal != (SIGTRAP | 0x80)) {
            int delivered_signal = stop_signal == SIGTRAP ? 0 : stop_signal;
            if (ptrace(PTRACE_SYSCALL, child, NULL, (void *)(long)delivered_signal) < 0) break;
            continue;
        }
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) break;
#if ARCH == 64
        long syscall_number = (long)regs.orig_rax;
        long result = (long)regs.rax;
        int fd = (int)regs.rdi;
        uintptr_t address = (uintptr_t)regs.rsi;
#else
        long syscall_number = (long)regs.orig_eax;
        long result = (long)regs.eax;
        int fd = (int)regs.ebx;
        uintptr_t address = (uintptr_t)regs.ecx;
#endif
        if (entering && dangerous_syscall(syscall_number) && ++dangerous_count > 1) {
            logger_write(dangerous_str, sizeof(dangerous_str) - 1);
#if RUN_MODE == I0GAN
            logger_write("AVOID\n", 6);
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            break;
#endif
        }
        if (!entering && result > 0 && (syscall_number == SYS_read || syscall_number == SYS_write)
                && (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO)) {
            waf_interactive_log(child, address, (size_t)result,
                                syscall_number == SYS_read ? LOG_READ_ : LOG_WRITE_);
        }
        entering = !entering;
        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) break;
    }
}

int connect_server(const char *ip, unsigned short port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) {
        fprintf(stderr, "invalid forward IPv4 address: %s\n", ip);
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    return fd;
}

void forward_waf_run(void) {
    char server_ip[INET_ADDRSTRLEN] = FORWARD_IP;
    unsigned short server_port = FORWARD_PORT;
#if RUN_MODE == FORWARD_MULTI
    if (get_host_from_file(server_ip, sizeof(server_ip), &server_port) < 0) return;
#endif
    int server_fd = connect_server(server_ip, server_port);
    if (server_fd < 0) return;

    char buffer[IO_BUF_SIZE];
    int input_open = 1;
    while (1) {
        fd_set reads;
        FD_ZERO(&reads);
        if (input_open) FD_SET(STDIN_FILENO, &reads);
        FD_SET(server_fd, &reads);
        int maximum = server_fd > STDIN_FILENO ? server_fd : STDIN_FILENO;
        int selected = select(maximum + 1, &reads, NULL, NULL, NULL);
        if (selected < 0 && errno == EINTR) continue;
        if (selected < 0) {
            perror("select");
            break;
        }
        if (input_open && FD_ISSET(STDIN_FILENO, &reads)) {
            ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) break;
            if (count == 0) {
                input_open = 0;
                shutdown(server_fd, SHUT_WR);
            } else {
                log_bytes(buffer, (size_t)count, LOG_READ_);
                if (write_all(server_fd, buffer, (size_t)count) < 0) break;
            }
        }
        if (FD_ISSET(server_fd, &reads)) {
            ssize_t count = read(server_fd, buffer, sizeof(buffer));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            log_bytes(buffer, (size_t)count, LOG_WRITE_);
            if (write_all(STDOUT_FILENO, buffer, (size_t)count) < 0) break;
        }
    }
    close(server_fd);
}

void waf_init(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
#if LOG_METHOD == OPEN
    logger_init(LOG_PATH);
    waf_log_open();
    waf_write_logo();
#endif
}

int main(int argc, char *argv[]) {
    waf_init();
#if RUN_MODE == FORWARD || RUN_MODE == FORWARD_MULTI
    (void)argc;
    (void)argv;
    forward_waf_run();
#else
    bin_waf_run(argc, argv);
#endif
    waf_write_hex_log();
    logger_close();
    return 0;
}

int get_host_from_file(char *ip, size_t ip_size, unsigned short *port) {
    FILE *hosts = fopen(HOSTS_FILE, "r");
    if (!hosts) {
        perror("hosts.txt");
        return -1;
    }
    char addresses[MAX_FORWARD_TARGETS][INET_ADDRSTRLEN];
    unsigned short ports[MAX_FORWARD_TARGETS];
    size_t count = 0;
    char line[256];
    while (count < MAX_FORWARD_TARGETS && fgets(line, sizeof(line), hosts)) {
        char host[INET_ADDRSTRLEN];
        unsigned int parsed_port = 0;
        char extra = 0;
        if (sscanf(line, " %15[0-9.] : %u %c", host, &parsed_port, &extra) != 2 || parsed_port == 0 || parsed_port > 65535) {
            continue;
        }
        struct in_addr parsed;
        if (inet_pton(AF_INET, host, &parsed) != 1) continue;
        snprintf(addresses[count], sizeof(addresses[count]), "%s", host);
        ports[count++] = (unsigned short)parsed_port;
    }
    fclose(hosts);
    if (count == 0) {
        fprintf(stderr, "hosts.txt contains no valid targets\n");
        return -1;
    }

    int index_fd = open(HOSTS_ATTACK_INDEX_FILE, O_RDWR | O_CREAT, 0660);
    if (index_fd < 0) {
        perror(".multi_index");
        return -1;
    }
    flock(index_fd, LOCK_EX);
    char value[32] = {0};
    ssize_t read_size = read(index_fd, value, sizeof(value) - 1);
    unsigned long index = read_size > 0 ? strtoul(value, NULL, 10) % count : 0;
    unsigned long next = (index + 1) % count;
    int length = snprintf(value, sizeof(value), "%lu\n", next);
    ftruncate(index_fd, 0);
    lseek(index_fd, 0, SEEK_SET);
    write_all(index_fd, value, (size_t)length);
    flock(index_fd, LOCK_UN);
    close(index_fd);

    if (ip_size == 0) return -1;
    snprintf(ip, ip_size, "%s", addresses[index]);
    *port = ports[index];
    return 0;
}
