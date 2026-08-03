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
  This file contains the functionality for parallel operation
 */

#ifndef SRC_CORE_LIB_UTILS_PARALLEL_H_
#define SRC_CORE_LIB_UTILS_PARALLEL_H_

#ifdef PARALLEL
    #include <atomic>
    #include <omp.h>
#endif

namespace lbcrypto {

class ParallelControls {
public:
    // @Brief CTOR, latches the number of machine threads the system reports
    // (can be overridden by environment variables) and allows all of them by default.
    ParallelControls() {
#ifdef PARALLEL
        machineThreads = omp_get_max_threads();
        threadLimit.store(machineThreads, std::memory_order_relaxed);
#endif
    }

    // @Brief Enable() enables parallel operation
    void Enable() {
        SetNumThreads(machineThreads);
    }

    // @Brief Disable() disables parallel operation
    void Disable() {
        SetNumThreads(1);
    }

    // @Brief returns the number of threads latched at construction
    int GetMachineThreads() const {
        return machineThreads;
    }

    // @Brief returns the number of processors available to the process
    static int GetNumProcs() {
#ifdef PARALLEL
        return omp_get_num_procs();
#else
        return 1;
#endif
    }

    // @Brief returns current number of threads that are usable
    int GetNumThreads() const {
#ifdef PARALLEL
        return threadLimit.load(std::memory_order_relaxed);
#else
        return 1;
#endif
    }

    // @Brief returns min of int n and the current thread limit
    int GetThreadLimit(int n) const {
#ifdef PARALLEL
        int lim = threadLimit.load(std::memory_order_relaxed);
        return n > lim ? lim : n;
#else
        return 1;
#endif
    }

    // @Brief sets number of threads to use (clamped to [1, machineThreads])
    void SetNumThreads(int nthreads) {
#ifdef PARALLEL
        if (nthreads < 1)
            nthreads = 1;
        else if (nthreads > machineThreads)
            nthreads = machineThreads;
        threadLimit.store(nthreads, std::memory_order_relaxed);
        omp_set_num_threads(nthreads);
#endif
    }

    // @Brief caps unit tests at half the processors; restored by UnitTestStop()
    void UnitTestStart() {
#ifdef PARALLEL
        savedLimit = threadLimit.load(std::memory_order_relaxed);
        SetNumThreads(GetNumProcs() / 2);
#endif
    }

    // @Brief restores the thread limit saved by UnitTestStart()
    void UnitTestStop() {
#ifdef PARALLEL
        SetNumThreads(savedLimit);
#endif
    }

private:
#ifdef PARALLEL
    std::atomic<int> threadLimit{1};
    int savedLimit{1};
#endif
    int machineThreads{1};
};

extern ParallelControls OpenFHEParallelControls;

}  // namespace lbcrypto

#endif /* SRC_CORE_LIB_UTILS_PARALLEL_H_ */
