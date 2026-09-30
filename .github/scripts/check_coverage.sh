#!/bin/sh
set -eu

# Gate: every statement is covered OR listed in coverage_waivers.txt as a
# proven-unreachable defensive statement. Any uncovered statement missing
# from the inventory fails the build.
#
# Waiver format: guardcore/<file>:<startLine> per line; comments (#) and
# blank lines are ignored.

# Fail closed: a missing or empty profile must fail the gate, not skip it.
if [ ! -s cover.out ]; then
    printf 'coverage gate: cover.out is missing or empty; refusing to pass vacuously\n'
    exit 1
fi

total=0
covered=0
uncovered_waived=0
uncovered_real=0

while IFS=' ' read -r loc stmts count; do
    case "$loc" in
        github.com/*)
            file_line="${loc#github.com/rennf93/guard-core-go/v4/}"
            file_line="${file_line%.*}"
            file_line="${file_line%.*}"
            total=$((total + stmts))
            if [ "$count" != "0" ]; then
                covered=$((covered + stmts))
            elif grep -qxF "$file_line" .github/scripts/coverage_waivers.txt 2>/dev/null; then
                uncovered_waived=$((uncovered_waived + stmts))
            else
                uncovered_real=$((uncovered_real + stmts))
                printf 'UNCOVERED (not waived): %s (%s stmts)\n' "$file_line" "$stmts"
            fi
            ;;
    esac
done < cover.out

if [ "$total" -eq 0 ]; then
    printf 'coverage gate: no coverage rows parsed from cover.out; refusing to pass vacuously\n'
    exit 1
fi

if [ "$uncovered_real" -gt 0 ]; then
    printf 'coverage gate: %d uncovered statement(s) not in the waiver inventory\n' "$uncovered_real"
    exit 1
fi

printf 'coverage gate: covered-or-waived 100%% (%d covered, %d waived-proven-unreachable of %d statements)\n' \
    "$covered" "$uncovered_waived" "$total"
