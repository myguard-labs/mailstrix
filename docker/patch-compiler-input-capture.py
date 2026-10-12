#!/usr/bin/env python3
"""Apply checked, pinned native observation points to the static YARA build.

The generated scanner's existing YY_INPUT remains untouched. Includes retain
YARA's default callback identity, path resolution, allocation, descriptor, read,
close and returned pointer. Only the already returned buffers are observed.
"""

import hashlib
import shutil
import sys
from pathlib import Path

HASHES = {
    "libyara/parser.c": "a85e6352bea135af8c43681878282c9a585512e112d95c05a4218b9a2229ec17",
    "libyara/lexer.c": "015c0d1d8126274ef84a4bceefbd59ead11c51799fe925b42a4f49211dddf820",
    "libyara/compiler.c": "62705fc9703947ffb41918e50f1bb489d941f57fff341a75fe96e03682a8d131",
    "cli/yarac.c": "ef83dd39038f9663fb3d6bf8883ddb24e4d8c2af7248a8ffc58450e14b034ed0",
}


def patch(root):
    contents = {}
    for name, expected in HASHES.items():
        data = (root / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"unsupported YARA capture source: {name}")
        contents[name] = data.decode()

    def replace(name, old, new):
        if contents[name].count(old) != 1:
            raise ValueError(f"capture anchor mismatch: {name}")
        contents[name] = contents[name].replace(old, new)

    replace(
        "libyara/compiler.c",
        "#include <yara/compiler.h>",
        (
            "#define MAILSTRIX_CAPTURE_IMPLEMENTATION\n#include "
            '"compiler-input-capture.h"\n#include <yara/compiler'
            ".h>"
        ),
    )
    replace(
        "libyara/compiler.c",
        "  return file_buffer;\n}",
        (
            "  mailstrix_input_capture(4, include_name, file_bu"
            "ffer, (size_t) file_size);\n  return file_buffer;\n}"
        ),
    )
    replace(
        "libyara/lexer.c",
        "#include <yara/lexer.h>",
        '#include "compiler-input-capture.h"\n#include <yara/lexer.h>',
    )
    anchor = "\t\t\tyyg->yy_n_chars, num_to_read );"
    replace(
        "libyara/lexer.c",
        anchor,
        anchor
        + (
            "\n\t\tmailstrix_input_capture(2, yr_compiler_get_curr"
            "ent_file_name(yyextra),\n\t\t    &YY_CURRENT_BUFFER_L"
            "VALUE->yy_ch_buf[number_to_move], (size_t) yyg->yy"
            "_n_chars);"
        ),
    )
    anchor = "  result = yr_lex_parse_rules_file(rules_file, compiler);"
    replace(
        "libyara/compiler.c",
        anchor,
        "  mailstrix_input_capture(8, YR_VERSION, NULL, 0);\n"
        '  mailstrix_input_capture(1, file_name, namespace_ == NULL ? "default" : namespace_,\n'
        '      strlen(namespace_ == NULL ? "default" : namespace_));\n'
        + anchor
        + "\n  mailstrix_input_capture(3, file_name, &compiler->errors, sizeof(compiler->errors));",
    )
    replace(
        "cli/yarac.c",
        "int _tmain(int argc, const char_t** argv)",
        '#include "compiler-input-capture.h"\n\nint _tmain(int argc, const char_t** argv)',
    )
    replace(
        "cli/yarac.c",
        "  return result;\n}",
        "  mailstrix_input_capture(9, YR_VERSION, &result, sizeof(result));\n  return result;\n}",
    )
    replace(
        "libyara/parser.c",
        "#include <yara/parser.h>",
        '#include "compiler-input-capture.h"\n#include <yara/parser.h>',
    )
    replace(
        "libyara/parser.c",
        "        sizeof(int64_t),\n        argument_ref);\n\n  return result;",
        "        sizeof(int64_t),\n        argument_ref);\n"
        "  if (result == ERROR_SUCCESS &&\n"
        "      (instruction == OP_PUSH_RULE || instruction == OP_MATCH_RULE))\n"
        "    mailstrix_rule_capture(instruction == OP_PUSH_RULE ? 11 : 12,\n"
        "        yyget_extra(yyscanner)->current_rule_idx, (uint64_t) argument);\n"
        "\n  return result;",
    )
    replace(
        "cli/yarac.c",
        "  if (!compile_files(compiler, argc, argv))",
        "  mailstrix_rule_begin();\n  if (!compile_files(compiler, argc, argv))",
    )
    replace(
        "cli/yarac.c",
        "  // Not using yr_rules_save because it does not have support for unicode",
        "  {\n"
        "    YR_RULE* rule;\n"
        "    const char* tag;\n"
        "    uint64_t index = 0;\n"
        "    yr_rules_foreach(rules, rule) {\n"
        "      mailstrix_rule_inventory(index, rule->flags, rule->ns->name, rule->identifier);\n"
        "      yr_rule_tags_foreach(rule, tag)\n"
        "        mailstrix_rule_tag(index, tag);\n"
        "      ++index;\n"
        "    }\n"
        "    mailstrix_rule_summary(index);\n"
        "  }\n\n"
        "  // Not using yr_rules_save because it does not have support for unicode",
    )
    header = Path(__file__).with_name("compiler-input-capture.h")
    for folder in ("libyara", "cli"):
        shutil.copyfile(header, root / folder / header.name)
    for name, data in contents.items():
        (root / name).write_text(data)


if __name__ == "__main__":
    patch(Path(sys.argv[1]))
