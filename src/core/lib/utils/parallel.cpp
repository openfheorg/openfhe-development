//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  This file contains the functionality for parallel operation
 */

#include "utils/parallel.h"

#ifdef PARALLEL
    #include <cstdio>
    #include <cstdlib>
#endif

namespace lbcrypto {

ParallelControls OpenFHEParallelControls;

#ifdef PARALLEL
namespace {
// width of the calling thread's current top-level team and the narrower requests made since it was set
struct TeamState {
    int width{1};
    int narrower{0};
    int widestNarrower{1};
};
thread_local TeamState team;

bool SmtActive() {
    #if defined(__linux__)
    std::FILE* file = std::fopen("/sys/devices/system/cpu/smt/active", "r");
    if (file == nullptr)
        return false;
    const int c = std::fgetc(file);
    std::fclose(file);
    return c == '1';
    #else
    return false;
    #endif
}
}  // namespace

int ParallelControls::TeamWidth(int requested, int lim) {
    if (team.width > lim)
        team.width = lim;
    if (requested >= team.width) {
        team = TeamState{requested, 0, 1};
        return requested;
    }
    if (requested > team.widestNarrower)
        team.widestNarrower = requested;
    if (++team.narrower < TEAM_SHRINK_REGIONS)
        return team.width;
    team = TeamState{team.widestNarrower, 0, 1};
    return team.width;
}

int ParallelControls::DefaultThreads(int machineThreads) {
    if (std::getenv("OMP_NUM_THREADS") != nullptr || !SmtActive())
        return machineThreads;
    const int half = omp_get_num_procs() / 2;
    return half > 0 && half < machineThreads ? half : machineThreads;
}
#endif

}  // namespace lbcrypto
