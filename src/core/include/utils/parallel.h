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
 * parallel regions consult through GetThreadLimit(). The limit starts at the default thread count: half the
 * processors available to the process when the system reports simultaneous multithreading as active (Linux), and
 * the number of machine threads otherwise or when OMP_NUM_THREADS is set. Without the PARALLEL build option every
 * query returns 1 and the setters are no-ops. A single global instance, OpenFHEParallelControls, is used throughout
 * the library.
 */
class ParallelControls {
  public:
    /**
     * @brief Constructor; latches the number of machine threads the system reports (can be overridden by the
     * OpenMP environment variables) and sets the thread limit to the default thread count.
     */
    ParallelControls() {
#ifdef PARALLEL
        machineThreads = omp_get_max_threads();
        defaultThreads = DefaultThreads(machineThreads);
        threadLimit.store(defaultThreads, std::memory_order_relaxed);
#endif
    }

    /**
     * @brief Enables parallel operation by setting the thread limit to the default thread count.
     */
    void Enable() {
        SetNumThreads(defaultThreads);
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
     * @brief Returns the default thread count the thread limit starts at and Enable() restores.
     * @return the default thread count (1 without PARALLEL)
     */
    int GetDefaultThreads() const {
        return defaultThreads;
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
     * @brief Team width for a parallel region that requests n threads; used as the num_threads value of the
     * library's parallel regions. The request is clamped to [1, current thread limit]. With libgomp, a top-level
     * region that requests fewer threads than the calling thread's current team keeps that team's width until
     * TEAM_SHRINK_REGIONS consecutive such regions have been requested; the team then shrinks to the widest of
     * those requests. Threads without work wait at the region's closing barrier.
     * @param n requested number of threads (typically the amount of independent work available)
     * @return the team width (1 without PARALLEL)
     */
    int GetThreadLimit(int n) const {
#ifdef PARALLEL
        int lim = threadLimit.load(std::memory_order_relaxed);
        int width = n > lim ? lim : (n < 1 ? 1 : n);
    #ifdef _LIBGOMP_OMP_LOCK_DEFINED
        if (width > 1 && omp_get_level() == 0)
            width = TeamWidth(width, lim);
    #endif
        return width;
#else
        return 1;
#endif
    }

    /**
     * @brief Clamps a requested thread count to [1, current thread limit]; used where the thread count sizes the
     * work split or selects an algorithm, and as the width of regions that must run with exactly that count.
     * @param n requested number of threads
     * @return n clamped to [1, current thread limit] (1 without PARALLEL)
     */
    int ClampToThreadLimit(int n) const {
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
    /** consecutive narrower top-level regions after which a libgomp team shrinks */
    static constexpr int TEAM_SHRINK_REGIONS{256};

    /**
     * @brief Width of the calling thread's next top-level team for a request of `requested` threads, following the
     * rule described in GetThreadLimit().
     */
    static int TeamWidth(int requested, int lim);

    /**
     * @brief Default thread count for a machine thread count of `machineThreads`: half the processors available to
     * the process when the system reports simultaneous multithreading as active, that is fewer than
     * `machineThreads` and OMP_NUM_THREADS is not set; otherwise `machineThreads`.
     */
    static int DefaultThreads(int machineThreads);

    std::atomic<int> threadLimit{1};
    int savedLimit{1};
#endif
    int machineThreads{1};
    int defaultThreads{1};
};

/** the global instance consulted by all parallel regions in the library */
extern ParallelControls OpenFHEParallelControls;

}  // namespace lbcrypto

#endif  // SRC_CORE_INCLUDE_UTILS_PARALLEL_H_
