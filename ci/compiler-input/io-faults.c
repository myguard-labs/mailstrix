/* Deterministic libc fault controls for the real static compiler. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int target(int fd, const char *suffix) {
  char proc[64], path[4096];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(proc, path, sizeof(path) - 1);
  if (n < 0)
    return 0;
  path[n] = '\0';
  size_t a = (size_t)n, b = strlen(suffix);
  return a >= b && strcmp(path + a - b, suffix) == 0;
}

static const char *mode(void) {
  const char *value = getenv("MX_IO_MODE");
  return value == NULL ? "" : value;
}

ssize_t read(int fd, void *buf, size_t size) {
  ssize_t (*real_read)(int, void *, size_t) = dlsym(RTLD_NEXT, "read");
  if (!target(fd, "fault.inc"))
    return real_read(fd, buf, size);
  if (strcmp(mode(), "include_error") == 0) {
    errno = EIO;
    return -1;
  }
  if (strcmp(mode(), "include_short") == 0 && size > 0)
    return real_read(fd, buf, size - 1);
  ssize_t n = real_read(fd, buf, size);
  if (strcmp(mode(), "include_transient") == 0 && n > 0) {
    /* Rewrite disk only AFTER the compiler's original descriptor returned. */
    const char *path = getenv("MX_IO_INCLUDE");
    if (path == NULL)
      _exit(98);
    int out = open(path, O_WRONLY | O_TRUNC);
    const char replacement[] = "rule Fault { condition: false }\n";
    if (out < 0 || write(out, replacement, sizeof(replacement) - 1) < 0)
      _exit(99);
    close(out);
  }
  return n;
}

size_t fread(void *buf, size_t size, size_t count, FILE *stream) {
  size_t (*real_fread)(void *, size_t, size_t, FILE *) =
      dlsym(RTLD_NEXT, "fread");
  if (!target(fileno(stream), "fault.yar"))
    return real_fread(buf, size, count, stream);
  if (strcmp(mode(), "root_short") == 0 && count > 3)
    return real_fread(buf, size, 3, stream);
  if (strcmp(mode(), "root_error") == 0)
    close(fileno(stream));
  size_t n = real_fread(buf, size, count, stream);
  if (strcmp(mode(), "root_transient") == 0 && n > 0) {
    const char *path = getenv("MX_IO_ROOT");
    if (path == NULL)
      _exit(98);
    int out = open(path, O_WRONLY | O_TRUNC);
    const char replacement[] = "rule Root { condition: false }\n";
    if (out < 0 || write(out, replacement, sizeof(replacement) - 1) < 0)
      _exit(99);
    close(out);
  }
  return n;
}

ssize_t write(int fd, const void *buf, size_t size) {
  ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
  static int interrupted;
  if (target(fd, ".native")) {
    if (strcmp(mode(), "capture_eintr") == 0 && !interrupted++) {
      errno = EINTR;
      return -1;
    }
    if (strcmp(mode(), "capture_short") == 0 && size > 1)
      return real_write(fd, buf, size / 2);
    if (strcmp(mode(), "capture_zero") == 0)
      return 0;
    if (strcmp(mode(), "capture_error") == 0) {
      errno = ENOSPC;
      return -1;
    }
  }
  return real_write(fd, buf, size);
}

int close(int fd) {
  int (*real_close)(int) = dlsym(RTLD_NEXT, "close");
  int fail =
      target(fd, ".native") && strcmp(mode(), "capture_close_error") == 0;
  int result = real_close(fd);
  if (fail) {
    errno = EIO;
    return -1;
  }
  return result;
}
