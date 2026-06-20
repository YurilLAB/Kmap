#!/bin/bash -eu
#
# OSS-Fuzz / ClusterFuzzLite build script.
#
# Compiles each libFuzzer target in fuzz/ossfuzz/ with the toolchain the
# fuzzing infra provides via the environment:
#   $CXX                 clang++ from the oss-fuzz base-builder image
#   $CXXFLAGS            includes -fsanitize=fuzzer-no-link plus the chosen
#                        sanitizer (address / undefined / memory)
#   $LIB_FUZZING_ENGINE  the libFuzzer (or AFL++) engine to link against
#   $OUT                 directory the built fuzzers are dropped into
#
# Each target is a single self-contained .cc that exposes
# LLVMFuzzerTestOneInput -- either a verbatim copy of the shipping parser or a
# direct #include of the real dependency-light source/header (fuzz_hassh pulls
# in ssh_hassh.cc, fuzz_banner the header-only banner_classify.h), so no
# kmap/sqlite linkage is needed and the build stays trivial. The same sources
# build locally with fuzz/ossfuzz/standalone_main.cc under plain g++ for
# verification without clang.

TARGETS="fuzz_dns fuzz_cidr fuzz_jsonescape fuzz_proto fuzz_hassh fuzz_banner"

for t in $TARGETS; do
  echo "Building $t"
  "$CXX" $CXXFLAGS -std=gnu++17 \
    "fuzz/ossfuzz/${t}.cc" \
    $LIB_FUZZING_ENGINE \
    -o "$OUT/${t}"
done

echo "Built: $TARGETS"
