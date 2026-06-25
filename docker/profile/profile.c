/* PERF-12 profiling harness — compile the full yarad ruleset with a
 * YR_PROFILING_ENABLED libyara, scan every live sample on ONE scanner so cost
 * accumulates, then dump per-rule cost (descending). Mirrors compile-rules.sh
 * external-variable defaults so the same rule set compiles. */
#include <yara.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

static int cb(YR_SCAN_CONTEXT *c, int msg, void *md, void *ud) {
  (void)c;(void)msg;(void)md;(void)ud;
  return CALLBACK_CONTINUE; /* we don't care about matches, only cost */
}

/* define the same externals compile-rules.sh passes (-d ...), so THOR/InQuest/
 * Didier rules that reference them compile + scan. */
static void defexts(YR_COMPILER *comp) {
  yr_compiler_define_string_variable(comp, "filepath", "");
  yr_compiler_define_string_variable(comp, "filename", "");
  yr_compiler_define_string_variable(comp, "extension", "");
  yr_compiler_define_string_variable(comp, "filetype", "");
  yr_compiler_define_string_variable(comp, "file_type", "");
  yr_compiler_define_string_variable(comp, "owner", "");
  yr_compiler_define_integer_variable(comp, "VBA", 0);
}

/* add every *.yar / *.yara under dir to the compiler, namespaced by filename,
 * each guarded so one bad file doesn't abort (matches compile-rules per-file
 * validation intent — but here we add to one compiler; a hard error on a file
 * is reported and skipped by re-creating is overkill, so we just count errors). */
static int add_dir(YR_COMPILER *comp, const char *dir, int *added) {
  DIR *d = opendir(dir);
  if (!d) { fprintf(stderr, "opendir %s failed\n", dir); return 1; }
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    const char *n = e->d_name;
    size_t l = strlen(n);
    if (l < 5) continue;
    if (strcmp(n+l-4, ".yar") && strcmp(n+l-5, ".yara")) continue;
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, n);
    FILE *f = fopen(path, "r");
    if (!f) continue;
    int errs = yr_compiler_add_file(comp, f, n /*ns*/, path);
    fclose(f);
    if (errs > 0) {
      fprintf(stderr, "skip-ish %s (%d compile errors; left in set)\n", n, errs);
    } else {
      (*added)++;
    }
  }
  closedir(d);
  return 0;
}

static unsigned char *readfile(const char *p, size_t *len) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
  unsigned char *b = malloc(sz);
  if (fread(b, 1, sz, f) != (size_t)sz) { free(b); fclose(f); return NULL; }
  fclose(f); *len = sz; return b;
}

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: profile <compiled.yac> <sample-dir>\n"); return 2; }
  if (yr_initialize() != ERROR_SUCCESS) { fprintf(stderr, "yr_initialize\n"); return 1; }
  (void)defexts; (void)add_dir; /* unused now: rules come prebuilt from yarac */

  /* load the precompiled .yac (built by the SAME profiling yarac via
   * compile-rules.sh, so per-file validation already dropped uncompilable
   * files and the external-var defaults are baked in). */
  YR_RULES *rules;
  if (yr_rules_load(argv[1], &rules) != ERROR_SUCCESS) {
    fprintf(stderr, "yr_rules_load(%s) failed\n", argv[1]); return 1;
  }

  /* count rules */
  YR_RULE *r; int nrules = 0;
  yr_rules_foreach(rules, r) { nrules++; }
  fprintf(stderr, "compiled %d rules\n", nrules);

  YR_SCANNER *sc;
  if (yr_scanner_create(rules, &sc) != ERROR_SUCCESS) { fprintf(stderr, "scanner_create\n"); return 1; }
  yr_scanner_set_callback(sc, cb, NULL);
  /* PERF-15: mirror yarad's SCAN_FLAGS_FAST_MODE when FAST_MODE=1 in the env, so
   * the cost table can be compared with/without the flag. Default OFF keeps the
   * rule-cost numbers (PERF-12) directly comparable across runs. */
  const char *fm = getenv("FAST_MODE");
  if (fm && fm[0] == '1') {
    yr_scanner_set_flags(sc, SCAN_FLAGS_FAST_MODE);
    fprintf(stderr, "FAST_MODE enabled (SCAN_FLAGS_FAST_MODE)\n");
  }
  /* match yarad scan-time externals (define on scanner; constant across run) */
  yr_scanner_define_string_variable(sc, "filepath", "");
  yr_scanner_define_string_variable(sc, "filename", "");
  yr_scanner_define_string_variable(sc, "extension", "");
  yr_scanner_define_string_variable(sc, "filetype", "");
  yr_scanner_define_string_variable(sc, "file_type", "");
  yr_scanner_define_string_variable(sc, "owner", "");
  yr_scanner_define_integer_variable(sc, "VBA", 0);

  /* scan every sample on the SAME scanner so profiling cost accumulates */
  DIR *d = opendir(argv[2]);
  if (!d) { fprintf(stderr, "opendir samples\n"); return 1; }
  struct dirent *e; int scanned = 0;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') continue;
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", argv[2], e->d_name);
    size_t len; unsigned char *buf = readfile(path, &len);
    if (!buf) { fprintf(stderr, "read %s failed\n", path); continue; }
    int err = yr_scanner_scan_mem(sc, buf, len);
    free(buf);
    if (err != ERROR_SUCCESS) fprintf(stderr, "scan %s err=%d (continuing)\n", e->d_name, err);
    else scanned++;
  }
  closedir(d);
  fprintf(stderr, "scanned %d samples\n", scanned);

  /* dump full per-rule cost descending (not just top — we sort ourselves) */
  YR_RULE_PROFILING_INFO *info = yr_scanner_get_profiling_info(sc);
  if (info == NULL) { fprintf(stderr, "no profiling info (libyara not built with YR_PROFILING_ENABLED?)\n"); return 1; }
  printf("COST\tNAMESPACE\tRULE\n");
  for (YR_RULE_PROFILING_INFO *p = info; p->rule != NULL; p++) {
    printf("%llu\t%s\t%s\n", (unsigned long long)p->cost, p->rule->ns->name, p->rule->identifier);
  }
  yr_free(info);

  yr_scanner_destroy(sc);
  yr_rules_destroy(rules);
  yr_finalize();
  return 0;
}
