# OSS-Fuzz / ClusterFuzzLite build container for kmap.
# base-builder ships clang + the sanitizers + libFuzzer/AFL++ engines.
FROM gcr.io/oss-fuzz-base/base-builder:latest

# Copy the whole repo in; the fuzz targets are self-contained single .cc files
# under fuzz/ossfuzz/ so no extra dependencies are needed to build them.
COPY . $SRC/kmap
WORKDIR $SRC/kmap

# ClusterFuzzLite / OSS-Fuzz invoke $SRC/build.sh.
COPY .clusterfuzzlite/build.sh $SRC/build.sh
