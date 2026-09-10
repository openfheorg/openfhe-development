#!/usr/bin/env bash
# Build only; never runs experiments. Dependencies are listed in the root README.
set -euo pipefail
artifact_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_build=${1:-"$artifact_root/build-artifact"}
mkdir -p "$artifact_build"
artifact_build=$(cd "$artifact_build" && pwd)
artifact_jobs=${JOBS:-4}
artifact_tcm=${WITH_TCM:-ON}
artifact_cc=${CC:-clang-19}
artifact_cxx=${CXX:-clang++-19}

CC="$artifact_cc" CXX="$artifact_cxx" cmake -S "$artifact_root" -B "$artifact_build" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$artifact_build/install" \
    -DMATHBACKEND=6 -DWITH_NTL=ON -DNATIVE_SIZE=64 -DWITH_OPENMP=ON \
    -DWITH_TCM="$artifact_tcm" -DWITH_FBT_INSTRUMENTATION=ON \
    -DBUILD_EXAMPLES=ON -DBUILD_UNITTESTS=ON -DBUILD_BENCHMARKS=OFF \
    -DBUILD_SHARED=ON -DBUILD_STATIC=OFF
if [[ "$artifact_tcm" == ON ]]; then
    cmake --build "$artifact_build" --target tcm --parallel "$artifact_jobs"
fi
cmake --build "$artifact_build" --target fbt-benchmark pke_tests core_tests --parallel "$artifact_jobs"
printf 'Build complete: %s/bin/examples/pke/fbt-benchmark\n' "$artifact_build"
