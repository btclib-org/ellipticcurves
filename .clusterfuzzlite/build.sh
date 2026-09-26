#!/bin/bash -eu
# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.
#
# Runs inside the container the Dockerfile beside this file builds, cwd
# at $SRC/ellipticcurves (the Dockerfile's WORKDIR). `pip3 install .`
# asks for no extra, so the bindings are absent and the harnesses fuzz
# the Python arithmetic and codecs, which is the code this package
# writes.
#
# The three-line shape -- install, discover, compile -- is
# docs/build-integration/python_lang.md's own example build.sh for a
# Python project.
pip3 install .

# compile_python_fuzzer forwards every extra argument straight to
# pyinstaller, ahead of the fuzzer's own path (base-builder's own
# compile_python_fuzzer script). --collect-data=btclib_ecc is what
# closes a gap PyInstaller's own analysis does not: `curves.curve` reads
# JSON files under its package's `_data/` directory at import time, from
# a path built off `__file__`, and a frozen onefile executable bundles no
# non-Python file PyInstaller cannot trace a reference to. It walks the
# whole package rather than naming `curves/_data` alone, so a `_data/`
# directory the next harness reaches is bundled with no edit here.
#
# The same loop also zips each target's own seed corpus, one
# fuzz/corpus/<name>/ directory per fuzzer, under the name libFuzzer picks
# up next to a target's own binary with no configuration -- so a new
# fuzz_*.py with a corpus directory beside it is picked up here without a
# second list of names to keep in step with the first.
for fuzzer in $(find "$SRC/ellipticcurves/fuzz" -maxdepth 1 -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer" --collect-data=btclib_ecc
  name=$(basename "$fuzzer" .py)
  if [ -d "fuzz/corpus/$name" ]; then
    zip -j "$OUT/${name}_seed_corpus.zip" "fuzz/corpus/$name"/*.bin
  fi
done
