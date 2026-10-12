/* Observe compiler-owned buffers; never reopen or substitute a source
 * descriptor. Linux/static YARA build only. Enabled solely by the
 * per-invocation log path. A failed evidence write exits 125, distinct from
 * yarac's compilation failure.
 */
#ifndef MAILSTRIX_COMPILER_INPUT_CAPTURE_H
#define MAILSTRIX_COMPILER_INPUT_CAPTURE_H
#include <stddef.h>
#include <stdint.h>
void mailstrix_input_capture(unsigned char kind, const char *path,
                             const void *bytes, size_t size);
void mailstrix_rule_begin(void);
void mailstrix_rule_capture(unsigned char kind, uint64_t source,
                            uint64_t target);
void mailstrix_rule_inventory(uint64_t index, uint32_t flags,
                              const char *namespace_, const char *identifier);
void mailstrix_rule_tag(uint64_t index, const char *tag);
void mailstrix_rule_summary(uint64_t count);
#ifdef MAILSTRIX_CAPTURE_IMPLEMENTATION
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Noreturn void mailstrix_capture_failure(void) {
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
/* Graph frame version 1. All integers are fixed little endian, independent of
 * host ABI. References are emitted only after native bytecode emission
 * succeeds; inventory comes from yr_compiler_get_rules, never source text. */
static uint64_t mailstrix_edges, mailstrix_completions, mailstrix_tags;
static int mailstrix_graph_active;
void mailstrix_rule_begin(void) {
  mailstrix_graph_active = 1;
  mailstrix_edges = mailstrix_completions = mailstrix_tags = 0;
  mailstrix_input_capture(10, "mailstrix-rule-graph/1", NULL, 0);
}
static void mailstrix_uint64(unsigned char *bytes, uint64_t value) {
  for (unsigned int i = 0; i < 8; ++i)
    bytes[i] = (unsigned char)(value >> (8 * i));
}
void mailstrix_rule_capture(unsigned char kind, uint64_t source,
                            uint64_t target) {
  if (!mailstrix_graph_active)
    return;
  unsigned char bytes[16];
  mailstrix_uint64(bytes, source);
  mailstrix_uint64(bytes + 8, target);
  if (kind == 11)
    ++mailstrix_edges;
  else
    ++mailstrix_completions;
  mailstrix_input_capture(kind, "", bytes, sizeof(bytes));
}
void mailstrix_rule_inventory(uint64_t index, uint32_t flags,
                              const char *namespace_, const char *identifier) {
  int saved_errno = errno;
  const char *log = getenv("MAILSTRIX_COMPILER_INPUT_LOG");
  if (log == NULL || *log == '\0')
    return;
  size_t length = strlen(identifier);
  unsigned char *bytes = malloc(12 + length);
  if (bytes == NULL) {
    mailstrix_capture_failure();
  } else {
    mailstrix_uint64(bytes, index);
    for (unsigned int i = 0; i < 4; ++i)
      bytes[8 + i] = (unsigned char)(flags >> (8 * i));
    memcpy(bytes + 12, identifier, length);
    mailstrix_input_capture(13, namespace_, bytes, 12 + length);
    free(bytes);
  }
  errno = saved_errno;
}
void mailstrix_rule_tag(uint64_t index, const char *tag) {
  ++mailstrix_tags;
  unsigned char bytes[8];
  mailstrix_uint64(bytes, index);
  mailstrix_input_capture(14, tag, bytes, sizeof(bytes));
}
void mailstrix_rule_summary(uint64_t count) {
  unsigned char bytes[32];
  mailstrix_uint64(bytes, count);
  mailstrix_uint64(bytes + 8, mailstrix_edges);
  mailstrix_uint64(bytes + 16, mailstrix_completions);
  mailstrix_uint64(bytes + 24, mailstrix_tags);
  mailstrix_input_capture(15, "", bytes, sizeof(bytes));
}

#endif
#endif
