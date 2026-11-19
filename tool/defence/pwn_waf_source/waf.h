// Based on pwn_waf by i0gan: https://github.com/i0gan/pwn_waf
// MIT License. See the bundled LICENSE file.

#pragma once

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "logger.h"

#define CATCH 0x01
#define I0GAN 0x02
#define FORWARD 0x03
#define FORWARD_MULTI 0x04

#define OPEN 0x01
#define CLOSE 0x02

#ifndef ORIGINAL_PATH
#define ORIGINAL_PATH LOG_PATH "/pwn"
#endif
#define LISTEN_ELF ORIGINAL_PATH
#define HOSTS_FILE LOG_PATH "/hosts.txt"
#define HOSTS_ATTACK_INDEX_FILE LOG_PATH "/.multi_index"

#define MODE_CATCH_STR "// Mode: CATCH\n"
#define MODE_I0GAN_STR "// Mode: I0GAN\n"
#define MODE_FORWARD_STR "// Mode: FORWARD\n"
#define MODE_FORWARD_MULTI_STR "// Mode: FORWARD_MULTI\n"

#define IO_BUF_SIZE 0x2000
#define MAX_FORWARD_TARGETS 256

#ifndef FORWARD_IP
#define FORWARD_IP "127.0.0.1"
#endif

#ifndef FORWARD_PORT
#define FORWARD_PORT 8080
#endif

#ifndef LOG_METHOD
#define LOG_METHOD OPEN
#endif

#ifndef ARCH
#define ARCH 64
#endif

enum log_state {
    LOG_NONE_,
    LOG_READ_,
    LOG_WRITE_
};

int write_all(int fd, const void *buffer, size_t length);
void waf_write_logo(void);
void waf_write_hex_log(void);
void waf_log_open(void);
void waf_interactive_log(pid_t pid, uintptr_t address, size_t size, enum log_state state);
void bin_waf_run(int argc, char *argv[]);
int connect_server(const char *ip, unsigned short port);
void forward_waf_run(void);
void waf_init(void);
int get_host_from_file(char *ip, size_t ip_size, unsigned short *port);
