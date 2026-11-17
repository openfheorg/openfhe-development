//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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
#include <string>

#include "gtest/gtest.h"
#include "utils/parallel.h"

using namespace lbcrypto;

namespace {
// restores the thread limit a test changed
struct ThreadLimitGuard {
    int saved{OpenFHEParallelControls.GetNumThreads()};
    ~ThreadLimitGuard() {
        OpenFHEParallelControls.SetNumThreads(saved);
    }
};
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
    const char* old = std::getenv("OMP_NUM_THREADS");
    const std::string saved(old != nullptr ? old : "");
    setenv("OMP_NUM_THREADS", "3", 1);
    EXPECT_EQ(ParallelControls::DefaultThreads(16), 16);
    EXPECT_EQ(ParallelControls::DefaultThreads(2), 2);
    if (old != nullptr)
        setenv("OMP_NUM_THREADS", saved.c_str(), 1);
    else
        unsetenv("OMP_NUM_THREADS");
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
