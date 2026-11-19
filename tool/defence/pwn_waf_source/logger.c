// Author: i0gan
// Github: https://github.com/i0gan/pwn_waf
// Pwn Waf for AWD CTF

#include "logger.h"
#include <errno.h>

struct log_buf logger = {NULL, 0, 0, 0};
char logger_path[0x100] = {0};
int logger_fd = -1;

void logger_init(const char *path) {
    snprintf(logger_path, sizeof(logger_path), "%s", path);
}

int logger_open(const char *file_name) {
    logger_fd = open(file_name, O_CREAT | O_APPEND | O_WRONLY, 0600);
    if (logger_fd == -1) {
        perror("open");
        return 0;
    }
    return 1;
}

void logger_close() {
    if (logger_fd >= 0) close(logger_fd);
    free(logger.buf);
    logger.buf = NULL;
    logger.size = 0;
    logger.cap = 0;
    logger.truncated = 0;
}

void logger_append_hex(const char *buf, int length) {
    char encoded[8] = {0};
    for (int i = 0; i < length && !logger.truncated; i++) {
        snprintf(encoded, sizeof(encoded), "\\x%02x", (unsigned char)buf[i]);
        logger_append(encoded, (int)strlen(encoded));
    }
}

static void logger_write_all(const char *buf, int length) {
    int written = 0;
    while (logger_fd >= 0 && written < length) {
        ssize_t count = write(logger_fd, buf + written, (size_t)(length - written));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        written += (int)count;
    }
}

void logger_append(const char *buf, int length) {
    if (length <= 0 || logger.truncated) return;
    int available = LOGGER_MAX_BUFFER - logger.size;
    if (available <= 0) {
        logger.truncated = 1;
        return;
    }
    if (length > available) {
        length = available;
        logger.truncated = 1;
    }
    if (logger.cap == 0) {
        logger.buf = malloc(0x1000);
        if (!logger.buf) {
            logger.truncated = 1;
            return;
        }
        logger.cap = 0x1000;
    }
    if (length > logger.cap - logger.size) {
        int required = logger.size + length;
        int next_cap = ((required + 0xfff) / 0x1000) * 0x1000;
        if (next_cap > LOGGER_MAX_BUFFER) next_cap = LOGGER_MAX_BUFFER;
        char *expanded = realloc(logger.buf, (size_t)next_cap);
        if (!expanded) {
            logger.truncated = 1;
            return;
        }
        logger.buf = expanded;
        logger.cap = next_cap;
    }
    memcpy(logger.buf + logger.size, buf, (size_t)length);
    logger.size += length;
}

void logger_write_buf() {
    static const char truncated[] = "...[hex log truncated at 1 MiB]";
    if (logger.size > 0) logger_write_all(logger.buf, logger.size);
    if (logger.truncated) logger_write_all(truncated, (int)sizeof(truncated) - 1);
    logger.size = 0;
    logger.truncated = 0;
}

void logger_write(const char *buf, int len) {
    if (len > 0) logger_write_all(buf, len);
}

int logger_size() { return logger.size; }
int logger_cap() { return logger.cap; }
