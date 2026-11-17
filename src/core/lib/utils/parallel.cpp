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
    #if defined(__linux__)
        #include <sched.h>

        #include <set>
        #include <string>
        #include <utility>
    #endif
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

    #if defined(__linux__)
int ReadTopology(int cpu, const char* leaf) {
    const std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/" + leaf;
    std::FILE* file = std::fopen(path.c_str(), "r");
    if (file == nullptr)
        return -1;
    int value = -1;
    if (std::fscanf(file, "%d", &value) != 1)
        value = -1;
    std::fclose(file);
    return value;
}
    #endif

// number of distinct cores among the processors the process may run on, from the CPU topology; 0 when unknown
int AvailableCores() {
    #if defined(__linux__)
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof(set), &set) != 0)
        return 0;
    std::set<std::pair<int, int>> cores;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &set))
            continue;
        const int core = ReadTopology(cpu, "core_id");
        if (core < 0)
            return 0;
        cores.emplace(ReadTopology(cpu, "physical_package_id"), core);
    }
    return static_cast<int>(cores.size());
    #else
    return 0;
    #endif
}
}  // namespace

int ParallelControls::TeamWidth(int requested, int lim) {
    if (team.width > lim)
        team = TeamState{lim, 0, 1};
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
    if (std::getenv("OMP_NUM_THREADS") != nullptr)
        return machineThreads;
    const int cores = AvailableCores();
    return cores > 0 && cores < machineThreads ? cores : machineThreads;
}
#endif

}  // namespace lbcrypto
