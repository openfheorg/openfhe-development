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

#ifndef SRC_CORE_INCLUDE_UTILS_PARALLEL_H_
#define SRC_CORE_INCLUDE_UTILS_PARALLEL_H_

#ifdef PARALLEL
    #include <omp.h>

    #include <atomic>
#endif

namespace lbcrypto {

/**
 * @brief Runtime control of the number of OpenMP threads OpenFHE uses. Holds the thread count reported by the
 * system at construction (machine threads) and a current thread limit in [1, machine threads] that the library's
 * parallel regions consult through GetThreadLimit(). Without the PARALLEL build option every query returns 1 and
 * the setters are no-ops. A single global instance, OpenFHEParallelControls, is used throughout the library.
 */
class ParallelControls {
  public:
    /**
   * @brief Constructor; latches the number of machine threads the system reports (can be overridden by the
   * OpenMP environment variables) and allows all of them by default.
   */
    ParallelControls() {
#ifdef PARALLEL
        machineThreads = omp_get_max_threads();
        threadLimit.store(machineThreads, std::memory_order_relaxed);
#endif
    }

    /**
   * @brief Enables parallel operation by setting the thread limit to the number of machine threads.
   */
    void Enable() {
        SetNumThreads(machineThreads);
    }

    /**
   * @brief Disables parallel operation by setting the thread limit to 1.
   */
    void Disable() {
        SetNumThreads(1);
    }

    /**
   * @brief Returns the number of machine threads latched at construction.
   * @return number of machine threads (1 without PARALLEL)
   */
    int GetMachineThreads() const {
        return machineThreads;
    }

    /**
   * @brief Returns the number of processors available to the process, as reported by OpenMP.
   * @return number of processors (1 without PARALLEL)
   */
    static int GetNumProcs() {
#ifdef PARALLEL
        return omp_get_num_procs();
#else
        return 1;
#endif
    }

    /**
   * @brief Returns the current thread limit.
   * @return number of threads the library may currently use (1 without PARALLEL)
   */
    int GetNumThreads() const {
#ifdef PARALLEL
        return threadLimit.load(std::memory_order_relaxed);
#else
        return 1;
#endif
    }

    /**
   * @brief Reports whether the caller is inside an active OpenMP parallel region, where a nested region would
   * get one thread.
   * @return true inside an active parallel region; false otherwise and without PARALLEL
   */
    static bool InParallelRegion() {
#ifdef PARALLEL
        return omp_in_parallel() != 0;
#else
        return false;
#endif
    }

    /**
   * @brief Clamps a requested thread count to [1, current thread limit]; used as the num_threads value of the
   * library's parallel regions.
   * @param n requested number of threads (typically the amount of independent work available)
   * @return n clamped to [1, current thread limit] (1 without PARALLEL)
   */
    int GetThreadLimit(int n) const {
#ifdef PARALLEL
        int lim = threadLimit.load(std::memory_order_relaxed);
        return n > lim ? lim : (n < 1 ? 1 : n);
#else
        return 1;
#endif
    }

    /**
   * @brief Sets the thread limit, clamped to [1, machine threads], and passes it to omp_set_num_threads().
   * @param nthreads requested number of threads
   */
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

    /**
   * @brief Saves the current thread limit and caps it at half the processors for the duration of unit tests;
   * the saved value is restored by UnitTestStop().
   */
    void UnitTestStart() {
#ifdef PARALLEL
        savedLimit = threadLimit.load(std::memory_order_relaxed);
        SetNumThreads(GetNumProcs() / 2);
#endif
    }

    /**
   * @brief Restores the thread limit saved by UnitTestStart().
   */
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

/** the global instance consulted by all parallel regions in the library */
extern ParallelControls OpenFHEParallelControls;

}  // namespace lbcrypto

#endif  // SRC_CORE_INCLUDE_UTILS_PARALLEL_H_
