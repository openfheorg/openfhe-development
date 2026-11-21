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
  Unit tests for ParallelControls: the thread limit, the default thread count and the kept libgomp team
 */

#include <cstdlib>
#include <fstream>
#include <string>
#if defined(PARALLEL) && defined(__linux__)
    #include <sched.h>
#endif

#include "gtest/gtest.h"
#include "utils/parallel.h"

using namespace lbcrypto;

namespace {
// restores the thread limit and OpenMP's own thread count a test changed
struct ThreadLimitGuard {
    int saved{OpenFHEParallelControls.GetNumThreads()};
#ifdef PARALLEL
    int savedMax{omp_get_max_threads()};
#endif
    ~ThreadLimitGuard() {
        OpenFHEParallelControls.SetNumThreads(saved);
#ifdef PARALLEL
        omp_set_num_threads(savedMax);
#endif
    }
};

#if defined(PARALLEL) && !defined(_WIN32)
// restores OMP_NUM_THREADS a test changed
struct OmpNumThreadsGuard {
    const char* old{std::getenv("OMP_NUM_THREADS")};
    const std::string saved{old != nullptr ? old : ""};
    ~OmpNumThreadsGuard() {
        if (old != nullptr)
            setenv("OMP_NUM_THREADS", saved.c_str(), 1);
        else
            unsetenv("OMP_NUM_THREADS");
    }
};
#endif

#if defined(PARALLEL) && defined(__linux__)
std::string ThreadSiblings(int cpu) {
    std::ifstream file("/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/thread_siblings_list");
    std::string siblings;
    std::getline(file, siblings);
    return siblings;
}
#endif
}  // namespace

TEST(UTParallel, default_thread_count) {
    const int machine = OpenFHEParallelControls.GetMachineThreads();
    const int dflt = OpenFHEParallelControls.GetDefaultThreads();
    EXPECT_GE(dflt, 1);
    EXPECT_LE(dflt, machine);
#ifdef PARALLEL
    EXPECT_EQ(ParallelControls::DefaultThreads(1), 1);
    EXPECT_LE(ParallelControls::DefaultThreads(machine), machine);
    EXPECT_GE(ParallelControls::DefaultThreads(machine), 1);
#endif
}

#if defined(PARALLEL) && !defined(_WIN32)
TEST(UTParallel, default_thread_count_honours_omp_num_threads) {
    OmpNumThreadsGuard guard;
    unsetenv("OMP_NUM_THREADS");
    const int unset = ParallelControls::DefaultThreads(16);
    setenv("OMP_NUM_THREADS", "", 1);
    EXPECT_EQ(ParallelControls::DefaultThreads(16), unset);
    setenv("OMP_NUM_THREADS", "3", 1);
    EXPECT_EQ(ParallelControls::DefaultThreads(16), 16);
    EXPECT_EQ(ParallelControls::DefaultThreads(2), 2);
}
#endif

#if defined(PARALLEL) && defined(__linux__)
TEST(UTParallel, default_thread_count_counts_cores_in_the_affinity_mask) {
    const int machine = OpenFHEParallelControls.GetMachineThreads();
    cpu_set_t saved;
    ASSERT_EQ(sched_getaffinity(0, sizeof(saved), &saved), 0);
    int first = -1, sibling = -1, otherCore = -1;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &saved))
            continue;
        if (first < 0) {
            first = cpu;
            continue;
        }
        if (ThreadSiblings(cpu) == ThreadSiblings(first)) {
            if (sibling < 0)
                sibling = cpu;
        } else if (otherCore < 0) {
            otherCore = cpu;
        }
    }
    if (first < 0 || ThreadSiblings(first).empty() || machine < 2)
        GTEST_SKIP() << "needs the CPU topology and 2 machine threads";
    OmpNumThreadsGuard guard;
    unsetenv("OMP_NUM_THREADS");
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(first, &set);
    ASSERT_EQ(sched_setaffinity(0, sizeof(set), &set), 0);
    EXPECT_EQ(ParallelControls::DefaultThreads(machine), 1);
    if (sibling >= 0) {
        CPU_SET(sibling, &set);
        ASSERT_EQ(sched_setaffinity(0, sizeof(set), &set), 0);
        EXPECT_EQ(ParallelControls::DefaultThreads(machine), 1);
    }
    if (otherCore >= 0) {
        CPU_ZERO(&set);
        CPU_SET(first, &set);
        CPU_SET(otherCore, &set);
        ASSERT_EQ(sched_setaffinity(0, sizeof(set), &set), 0);
        EXPECT_EQ(ParallelControls::DefaultThreads(machine), 2);
    }
    EXPECT_EQ(sched_setaffinity(0, sizeof(saved), &saved), 0);
}
#endif

TEST(UTParallel, clamp_to_thread_limit) {
    ThreadLimitGuard guard;
    const int machine = OpenFHEParallelControls.GetMachineThreads();
    OpenFHEParallelControls.SetNumThreads(machine);
    EXPECT_EQ(OpenFHEParallelControls.GetNumThreads(), machine);
    EXPECT_EQ(OpenFHEParallelControls.ClampToThreadLimit(0), 1);
    EXPECT_EQ(OpenFHEParallelControls.ClampToThreadLimit(1), 1);
    EXPECT_EQ(OpenFHEParallelControls.ClampToThreadLimit(machine), machine);
    EXPECT_EQ(OpenFHEParallelControls.ClampToThreadLimit(machine + 5), machine);
    EXPECT_EQ(OpenFHEParallelControls.GetThreadLimit(machine + 5), machine);
    OpenFHEParallelControls.SetNumThreads(1);
    EXPECT_EQ(OpenFHEParallelControls.ClampToThreadLimit(machine), 1);
    EXPECT_EQ(OpenFHEParallelControls.GetThreadLimit(machine), 1);
    OpenFHEParallelControls.SetNumThreads(machine + 5);
    EXPECT_EQ(OpenFHEParallelControls.GetNumThreads(), machine);
}

TEST(UTParallel, enable_restores_start_state) {
    ThreadLimitGuard guard;
    OpenFHEParallelControls.Disable();
    EXPECT_EQ(OpenFHEParallelControls.GetNumThreads(), 1);
    OpenFHEParallelControls.Enable();
    EXPECT_EQ(OpenFHEParallelControls.GetNumThreads(), OpenFHEParallelControls.GetDefaultThreads());
#ifdef PARALLEL
    EXPECT_EQ(omp_get_max_threads(), OpenFHEParallelControls.GetMachineThreads());
#endif
}

#ifdef _LIBGOMP_OMP_LOCK_DEFINED
TEST(UTParallel, kept_team_keeps_resets_and_shrinks) {
    ThreadLimitGuard guard;
    auto& pc = OpenFHEParallelControls;
    if (pc.GetMachineThreads() < 4)
        GTEST_SKIP() << "needs 4 machine threads";
    pc.SetNumThreads(4);
    EXPECT_EQ(pc.GetThreadLimit(4), 4);
    for (int i = 1; i < 256; ++i)
        ASSERT_EQ(pc.GetThreadLimit(3), 4) << "narrower request " << i;
    EXPECT_EQ(pc.GetThreadLimit(2), 3);
    EXPECT_EQ(pc.GetThreadLimit(2), 3);
    EXPECT_EQ(pc.GetThreadLimit(3), 3);
    EXPECT_EQ(pc.GetThreadLimit(4), 4);
    EXPECT_EQ(pc.GetThreadLimit(1), 1);
    EXPECT_EQ(pc.GetThreadLimit(2), 4);
}

TEST(UTParallel, kept_team_never_exceeds_a_lowered_limit) {
    ThreadLimitGuard guard;
    auto& pc = OpenFHEParallelControls;
    if (pc.GetMachineThreads() < 6)
        GTEST_SKIP() << "needs 6 machine threads";
    pc.SetNumThreads(6);
    EXPECT_EQ(pc.GetThreadLimit(6), 6);
    for (int i = 0; i < 10; ++i)
        ASSERT_EQ(pc.GetThreadLimit(5), 6);
    pc.SetNumThreads(3);
    for (int i = 0; i < 600; ++i) {
        const int width = pc.GetThreadLimit(2);
        ASSERT_LE(width, 3) << "request " << i;
        ASSERT_GE(width, 2) << "request " << i;
    }
    EXPECT_EQ(pc.GetThreadLimit(2), 2);
    pc.SetNumThreads(6);
    EXPECT_EQ(pc.GetThreadLimit(5), 5);
    EXPECT_EQ(pc.GetThreadLimit(4), 5);
}
#endif
