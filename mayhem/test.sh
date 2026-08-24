#!/usr/bin/env bash
#
# bumpalo/mayhem/test.sh — RUN bumpalo's own functional test suite for the FUZZED code and emit a
# CTRF summary. exit 0 iff no test failed. This script only RUNS the suite (via `cargo test`); it
# never builds it — mayhem/build.sh precompiled it with `--no-run` in a separate, non-sanitized
# build.
#
# PATCH-grade oracle. tests/all/{tests,vec,string,boxed,emplace,collect_in,check,quickchecks,...}.rs
# assert EXACT allocator/collection behavior (values, lengths, capacities) against `bumpalo`'s
# public API — many via `mutatis`-driven property checks (tests/all/check.rs). A no-op /
# "return Ok(())" / output-altering patch to the arena or emplace code fails here, same as it fails
# the fuzz harnesses' own inline asserts (mayhem/fuzz/fuzz_targets/*.rs).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SRC:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not available — cannot run the test suite" >&2
  emit_ctrf "cargo-test" 0 1 0; exit 2
fi

echo "=== running cargo test --features collections,boxed (precompiled by build.sh --no-run) ==="
# Use the image's DEFAULT toolchain (same nightly the fuzz build uses), so no `+toolchain`
# override. --no-fail-fast so we count every test; RUSTFLAGS cleared so it inherits nothing from
# the sanitizer build.
out="$(RUSTFLAGS="" cargo test --features collections,boxed --no-fail-fast --jobs "$MAYHEM_JOBS" 2>&1)"; rc=$?
echo "$out"

# libtest prints one line per test binary:
#   test result: ok. 137 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; ...
# Sum across all binaries (lib unit tests + the "all" integration test binary + doctests).
PASSED=0; FAILED=0; IGNORED=0
while read -r p f i; do
  PASSED=$(( PASSED + p )); FAILED=$(( FAILED + f )); IGNORED=$(( IGNORED + i ))
done < <(printf '%s\n' "$out" \
  | sed -n 's/^test result:.* \([0-9][0-9]*\) passed; \([0-9][0-9]*\) failed; \([0-9][0-9]*\) ignored.*/\1 \2 \3/p')

# If we parsed no result lines, fall back to the cargo exit code (e.g. compile error).
if [ "$(( PASSED + FAILED + IGNORED ))" -eq 0 ]; then
  echo "could not parse any 'test result:' lines; using cargo exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "cargo-test" 1 0 0; exit 0; }
  emit_ctrf "cargo-test" 0 1 0; exit 1
fi

emit_ctrf "cargo-test" "$PASSED" "$FAILED" "$IGNORED"
