/* Observe compiler-owned buffers; never reopen or substitute a source
 * descriptor. Linux/static YARA build only. Enabled solely by the
 * per-invocation log path. A failed evidence write exits 125, distinct from
 * yarac's compilation failure.
 */
#ifndef MAILSTRIX_COMPILER_INPUT_CAPTURE_H
#define MAILSTRIX_COMPILER_INPUT_CAPTURE_H
#include <stddef.h>
void mailstrix_input_capture(unsigned char kind, const char *path,
                             const void *bytes, size_t size);
#ifdef MAILSTRIX_CAPTURE_IMPLEMENTATION
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void mailstrix_capture_failure(void) {
  const char message[] = "mailstrix-input-capture: retention write failed\n";
  (void)write(STDERR_FILENO, message, sizeof(message) - 1);
  _exit(125);
}

static void mailstrix_capture_write(int fd, const void *bytes, size_t size) {
  const unsigned char *p = bytes;
  while (size != 0) {
    ssize_t n = write(fd, p, size);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      mailstrix_capture_failure();
    p += n;
    size -= (size_t)n;
  }
}

void mailstrix_input_capture(unsigned char kind, const char *path,
                             const void *bytes, size_t size) {
  int saved_errno = errno;
  const char *log = getenv("MAILSTRIX_COMPILER_INPUT_LOG");
  if (log != NULL && *log != '\0') {
    /* Fixed little-endian framing also retains embedded NULs in source bytes.
     */
    unsigned char header[17];
    size_t path_size = path == NULL ? 0 : strlen(path);
    uint64_t a = path_size, b = size;
    header[0] = kind;
    for (unsigned int i = 0; i < 8; ++i) {
      header[1 + i] = (unsigned char)(a >> (8 * i));
      header[9 + i] = (unsigned char)(b >> (8 * i));
    }
    int fd = open(log, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
      mailstrix_capture_failure();
    mailstrix_capture_write(fd, header, sizeof(header));
    mailstrix_capture_write(fd, path, path_size);
    mailstrix_capture_write(fd, bytes, size);
    if (close(fd) != 0)
      mailstrix_capture_failure();
  }
  errno = saved_errno;
}
#endif
#endif
