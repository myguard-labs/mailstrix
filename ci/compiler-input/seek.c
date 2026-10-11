/* Compare real FILE position/error and include/parse contract across builds. */
#include <stdio.h>
#include <yara.h>

int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  FILE *input = fopen(argv[1], "r");
  YR_COMPILER *compiler = NULL;
  YR_RULES *rules = NULL;
  if (input == NULL)
    return 3;
  if (fseek(input, 8, SEEK_SET) != 0 || yr_initialize() != 0 ||
      yr_compiler_create(&compiler) != 0) {
    fclose(input);
    return 3;
  }
  int code = yr_compiler_add_file(compiler, input, "seek", argv[1]);
  printf("compile=%d position=%ld error=%d eof=%d\n", code, ftell(input),
         ferror(input), feof(input));
  if (code == 0) {
    code = yr_compiler_get_rules(compiler, &rules);
    if (code == 0)
      code = yr_rules_save(rules, argv[2]);
  }
  fclose(input);
  if (rules != NULL)
    yr_rules_destroy(rules);
  yr_compiler_destroy(compiler);
  yr_finalize();
  return code;
}
