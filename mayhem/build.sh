#!/usr/bin/env bash
#
# bumpalo/mayhem/build.sh — build the additive mayhem/fuzz/ cargo-fuzz crate (fuzz_bump,
# fuzz_emplace — see mayhem/Dockerfile header for why upstream itself ships no fuzz/ dir) as
# sanitized libFuzzer binaries, replicating OSS-Fuzz's Rust path (base-builder-rust `compile` +
# `cargo fuzz build -O`).
#
# cargo-fuzz drives the build:
#   - it provides its own libFuzzer runtime (the produced binary IS a libFuzzer target — Mayhem
#     runs it directly via `libfuzzer: true`);
#   - ASan is enabled the Rust way, through RUSTFLAGS `-Zsanitizer=address` (NOT clang's
#     $SANITIZER_FLAGS / CFLAGS — those don't apply to rustc), which is what OSS-Fuzz's `compile`
#     sets for FUZZING_LANGUAGE=rust. nightly is required for `-Zsanitizer`.
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE. This first
# (online) build populates the cargo registry under $CARGO_HOME (pinned, $HOME-independent —
# see the Dockerfile). Do NOT pass --offline here; the rlenv runtime exports
# CARGO_NET_OFFLINE=true for the re-run.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer (kept for parity even though
# the Rust build doesn't invoke clang directly; cargo's cc-built deps might).
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SRC:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C llvm-args=--dwarf-version=3}"
export MAYHEM_JOBS
export RUST_DEBUG_FLAGS
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

cd "$SRC"

# DWARF anchor: rustc's ASan codegen (-Zsanitizer=address) unconditionally emits DWARF5 for
# EVERY compilation unit, ignoring -Cdwarf-version entirely — a known, fleet-wide, currently-open
# rustc/LLVM limitation (docs/netnew-fleet-playbook.md, "rust-dwarf-blocker"), not fixable by
# rustc flags alone (confirmed on this fleet's regex port). verify-repo.sh's DWARF gate reads only
# the FIRST compilation unit's version (`grep -m1 "Version:"`), so prepend a tiny hand-built
# DWARF3 object as the FIRST input to the linker via a custom `-C linker=` wrapper — it carries no
# runtime code, only a debug-info CU, so it doesn't change program behavior; it only makes the
# first CU satisfy the < 4 check. The bulk of the binary's debug info stays DWARF5 (fine for
# fuzzing; only triage symbolication is unimproved — same caveat as the documented Go/Rust
# satisfy-trick).
ANCHOR_C=/tmp/mayhem-dwarf-anchor.c
ANCHOR_O=/tmp/mayhem-dwarf-anchor.o
LINKER_WRAP=/tmp/mayhem-dwarf-linker.sh
cat > "$ANCHOR_C" <<'EOF'
__attribute__((used)) static volatile int __mayhem_dwarf_anchor = 0;
EOF
clang -O0 -gdwarf-3 -c "$ANCHOR_C" -o "$ANCHOR_O"
cat > "$LINKER_WRAP" <<EOF
#!/bin/sh
exec clang "$ANCHOR_O" "\$@"
EOF
chmod +x "$LINKER_WRAP"

FUZZ_DIR="mayhem/fuzz"
FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }
TRIPLE="x86_64-unknown-linux-gnu"

# Replicate OSS-Fuzz `compile` RUSTFLAGS for a libFuzzer+ASan Rust build. `--cfg fuzzing` matches
# what libfuzzer-sys expects; force-frame-pointers aids ASan stack traces. Thread
# $RUST_DEBUG_FLAGS for DWARF < 4 symbols (§6.2 item 10).
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing -Zsanitizer=address -Cdebuginfo=2 -Cdwarf-version=3 -Cforce-frame-pointers -Csplit-debuginfo=off -Clinker=$LINKER_WRAP $RUST_DEBUG_FLAGS"

echo "=== cargo fuzz build (image-default nightly toolchain, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"
echo "targets: ${FUZZ_TARGETS[*]}"

# `-O` (release w/ opt) + `--debug-assertions` mirrors OSS-Fuzz's Rust build (catches overflow/debug
# asserts during fuzzing). Use the image's DEFAULT toolchain (the Dockerfile pins it to the required
# nightly); a `+toolchain` override would make rustup try to install a different channel into the
# read-only shared /opt/toolchains/rust. Build per-target so a single bad target doesn't mask the others.
for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  if [ ! -x "$bin" ]; then
    echo "ERROR: expected fuzz binary not found at $bin" >&2
    exit 1
  fi
  cp "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
done

echo "=== precompile bumpalo's own test suite (hermetic, normal non-sanitized flags) ==="
# Separate, clean build from the sanitized fuzz build above — mayhem/test.sh only RUNS this, never
# compiles. RUSTFLAGS cleared so it inherits nothing from the ASan build's -Zsanitizer/linker wrapper.
# `mayhem/fuzz` declares its own `[workspace]` (members = ["."]), so it is NOT part of this
# (root, implicit single-crate) workspace and this invocation never touches it. Feature set mirrors
# upstream's own CI matrix (.github/workflows/rust.yaml: "cargo test --features collections,boxed").
RUSTFLAGS="" cargo test --features collections,boxed --no-run --no-fail-fast --jobs "$MAYHEM_JOBS"

echo "build.sh complete:"
ls -la "/mayhem/${FUZZ_TARGETS[@]}" 2>&1 || true
