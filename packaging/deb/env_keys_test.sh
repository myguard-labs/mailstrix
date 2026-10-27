#!/bin/sh
# Guard against the .deb env samples drifting from the code. Every MAILSTRIX_* key
# named in a packaging/deb/*.env (commented or not) must be read by production Go
# code or expanded by a systemd unit.
# Catches renamed/stale knobs (e.g. MAILSTRIX_ADDR when the code reads MAILSTRIX_HOST).
# Covers every shipped unit's env file (strixd, strix-milter, ...), so a new one
# cannot be added without its keys being checked.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

# Parse Go syntax instead of grepping source text. This excludes comments, inert
# strings and *_test.go while retaining package-level named string constants
# passed to readers. Function-local constants are deliberately excluded: a
# same-named local in another function must not override package scope.
# envOrFile consumes both NAME and NAME_FILE even though the latter is assembled
# dynamically inside the helper.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cat >"$tmp/env_consumers.go" <<'EOF'
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var helperReaders = map[string]bool{
	"envBool": true, "envDur": true, "envDurInvalid": true,
	"envInt": true, "envInt64": true, "envInt64Range": true,
	"envIntAuto": true, "envList": true, "envOr": true, "envOrFile": true,
	"envSet": true, "envStr": true,
}

type sourceFile struct {
	file            *ast.File
	constants       map[string]string
	constantObjects map[*ast.Object]bool
}

func main() {
	packageConstants := make(map[string]map[string]string)
	var files []sourceFile
	for _, root := range os.Args[1:] {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			packageKey := filepath.Dir(path) + "\x00" + file.Name.Name
			constants := packageConstants[packageKey]
			if constants == nil {
				constants = make(map[string]string)
				packageConstants[packageKey] = constants
			}
			constantObjects := make(map[*ast.Object]bool)
			files = append(files, sourceFile{
				file: file, constants: constants, constantObjects: constantObjects,
			})
			for _, declaration := range file.Decls {
				decl, ok := declaration.(*ast.GenDecl)
				if !ok || decl.Tok != token.CONST {
					continue
				}
				for _, spec := range decl.Specs {
					valueSpec := spec.(*ast.ValueSpec)
					for index, name := range valueSpec.Names {
						if name.Obj != nil {
							constantObjects[name.Obj] = true
						}
						if index >= len(valueSpec.Values) {
							continue
						}
						if value, ok := stringValue(valueSpec.Values[index], nil); ok {
							constants[name.Name] = value
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan %s: %v\n", root, err)
			os.Exit(1)
		}
	}

	consumed := make(map[string]bool)
	for _, source := range files {
		for _, declaration := range source.file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				if function.Body == nil {
					continue
				}
				inspectReaders(function.Body, source.constants, source.constantObjects, consumed)
				continue
			}
			inspectReaders(declaration, source.constants, source.constantObjects, consumed)
		}
	}
	for key := range consumed {
		fmt.Println(key)
	}
}

func inspectReaders(root ast.Node, constants map[string]string, constantObjects map[*ast.Object]bool, consumed map[string]bool) {
	ast.Inspect(root, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			reader, ok := readerName(call.Fun)
			if !ok {
				return true
			}
			if identifier, ok := call.Args[0].(*ast.Ident); ok {
				if identifier.Obj != nil && !constantObjects[identifier.Obj] {
					return true
				}
			}
			key, ok := stringValue(call.Args[0], constants)
			if !ok || !strings.HasPrefix(key, "MAILSTRIX_") {
				return true
			}
			consumed[key] = true
			if reader == "envOrFile" {
				consumed[key+"_FILE"] = true
			}
			return true
	})
}

func readerName(expr ast.Expr) (string, bool) {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name, helperReaders[value.Name]
	case *ast.SelectorExpr:
		pkg, ok := value.X.(*ast.Ident)
		if ok && pkg.Name == "os" && (value.Sel.Name == "Getenv" || value.Sel.Name == "LookupEnv") {
			return value.Sel.Name, true
		}
	}
	return "", false
}

func stringValue(expr ast.Expr, constants map[string]string) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		decoded, err := strconv.Unquote(value.Value)
		return decoded, err == nil
	case *ast.Ident:
		if constants == nil {
			return "", false
		}
		decoded, ok := constants[value.Name]
		return decoded, ok
	}
	return "", false
}
EOF
known_file="$tmp/known"
known_unsorted="$tmp/known.unsorted"
command -v go >/dev/null 2>&1 || {
	echo "FAIL - Go is required to parse environment consumers" >&2
	exit 1
}
(
	cd "$tmp"
	GOWORK=off GOFLAGS='' go run ./env_consumers.go "$root/internal" "$root/cmd"
) >"$known_unsorted"
sort -u "$known_unsorted" >"$known_file"

# A key may legitimately be consumed by a systemd unit instead of by Go — e.g.
# MAILSTRIX_MILTER_ARGS, which the unit interpolates into ExecStart to pass extra
# flags. Those are still checked, just against the units rather than the sources:
# a key that NOTHING reads is the drift we are hunting.
unit_known_file="$tmp/unit_known"
awk '
    /^[[:space:]]*#/ { next }
    {
        line = $0
        while (match(line, /\$\{?MAILSTRIX_[A-Z0-9_]+/)) {
            key = substr(line, RSTART, RLENGTH)
            sub(/^\$\{?/, "", key)
            print key
            line = substr(line, RSTART + RLENGTH)
        }
    }
' "$here"/*.service | sort -u >"$unit_known_file"

fail=0
found_env=0
for env in "$here"/*.env; do
	[ -e "$env" ] || continue
	found_env=1
	name="$(basename "$env")"
	# Keys used in the env file: left-hand side of an (optionally #-commented) NAME=…
	# (MAILSTRIX_* tokens have no whitespace, so word-splitting the list is intended.)
	# shellcheck disable=SC2013
	for key in $(grep -oE '^#?[[:space:]]*MAILSTRIX_[A-Z0-9_]+=' "$env" |
		sed -E 's/^#?[[:space:]]*//; s/=$//' | sort -u); do
		if grep -qx "$key" "$known_file"; then
			echo "ok   - $name: $key"
		elif grep -qx "$key" "$unit_known_file"; then
			echo "ok   - $name: $key (consumed by a systemd unit)"
		else
			echo "FAIL - $key in $name is read by neither a Go source nor a systemd unit"
			fail=1
		fi
	done
done

# A glob that matched nothing would make this whole gate silently vacuous.
if [ "$found_env" -eq 0 ]; then
	echo "FAIL - no packaging/deb/*.env found; this test would pass vacuously"
	fail=1
fi

if [ "$fail" -eq 0 ]; then
	echo "ALL OK"
else
	echo "FAILURES"
	exit 1
fi
