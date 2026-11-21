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
    #include <cstdlib>
    #if defined(__linux__)
        #include <sched.h>

        #include <fstream>
        #include <set>
        #include <string>
    #endif
#endif

namespace lbcrypto {

ParallelControls OpenFHEParallelControls;

#ifdef PARALLEL
namespace {
    #ifdef _LIBGOMP_OMP_LOCK_DEFINED
/** consecutive narrower top-level regions after which a libgomp team shrinks */
constexpr int TEAM_SHRINK_REGIONS{256};

// width of the calling thread's top-level team, the consecutive narrower requests since it was set and the widest of
// them
struct TeamState {
    int width{1};
    int narrower{0};
    int widest{1};
};
thread_local TeamState team;
    #endif

// number of distinct cores among the processors the process may run on, a core being identified by the list of
// thread siblings its processors share in the CPU topology; 0 when unknown
int AvailableCores() {
    #if defined(__linux__)
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof(set), &set) != 0)
        return 0;
    std::set<std::string> cores;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &set))
            continue;
        std::ifstream file("/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/thread_siblings_list");
        std::string siblings;
        if (!std::getline(file, siblings) || siblings.empty())
            return 0;
        cores.insert(siblings);
    }
    return static_cast<int>(cores.size());
    #else
    return 0;
    #endif
}
}  // namespace

int ParallelControls::DefaultThreads(int machineThreads) {
    const char* env = std::getenv("OMP_NUM_THREADS");
    if (env != nullptr && *env != '\0')
        return machineThreads;
    const int cores = AvailableCores();
    return cores > 0 && cores < machineThreads ? cores : machineThreads;
}
#endif

int ParallelControls::GetThreadLimit([[maybe_unused]] int n) const {
#ifdef PARALLEL
    const int lim = threadLimit.load(std::memory_order_relaxed);
    const int width = n > lim ? lim : (n < 1 ? 1 : n);
    #ifdef _LIBGOMP_OMP_LOCK_DEFINED
    if (width > 1 && omp_get_level() == 0) {
        if (width >= team.width || team.width > lim) {
            team = TeamState{width, 0, 1};
        } else {
            if (width > team.widest)
                team.widest = width;
            if (++team.narrower == TEAM_SHRINK_REGIONS)
                team = TeamState{team.widest, 0, 1};
        }
        return team.width;
    }
    #endif
    return width;
#else
    return 1;
#endif
}

}  // namespace lbcrypto
