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
    #include <omp.h>
#endif

namespace lbcrypto {

class ParallelControls {
public:
    // @Brief CTOR, enables parallel operations as default
    // Cache the number of machine threads the system reports (can be
    // overridden by environment variables)
    // enable on startup by default
    ParallelControls() {
#ifdef PARALLEL
        machineThreads = omp_get_max_threads();
        Enable();
            // omp_set_dynamic(0);
            // omp_set_nested(0);
            // omp_set_max_active_levels(1);
#endif
    }

    // @Brief Enable() enables parallel operation
    void Enable() const {
#ifdef PARALLEL
        omp_set_num_threads(machineThreads);
#endif
    }

    // @Brief Disable() disables parallel operation
    void Disable() const {
#ifdef PARALLEL
        omp_set_num_threads(1);
#endif
    }

    int GetMachineThreads() const {
        return machineThreads;
    }

    static int GetNumProcs() {
#ifdef PARALLEL
        return omp_get_num_procs();
#else
        return 1;
#endif
    }

    // @Brief returns current number of threads that are usable
    // @return int # threads
    int GetNumThreads() const {
#ifdef PARALLEL
        int nthreads = 1;
        int tid      = 1;
            // Fork a team of threads giving them their own copies of variables
            // so we can see how many threads we have to work with
    #pragma omp parallel private(tid)
        {
            /* Obtain thread number */
            tid = omp_get_thread_num();

            /* Only main thread does this */
            if (tid == 0) {
                nthreads = omp_get_num_threads();
            }
        }
        return nthreads;
#else
        return 1;
#endif
    }

    // @Brief returns min of int n and machineThreads
    int GetThreadLimit(int n) const {
#ifdef PARALLEL
        return n > machineThreads ? machineThreads : n;
#else
        return 1;
#endif
    }

    // @Brief sets number of threads to use (limited by system value)
    void SetNumThreads(int nthreads) {
#ifdef PARALLEL
        // set number of thread, but limit to the system set number of machine threads...
        omp_set_num_threads(nthreads > machineThreads ? machineThreads : nthreads);
#endif
    }

private:
    int machineThreads{1};
};

extern ParallelControls OpenFHEParallelControls;

}  // namespace lbcrypto

#endif /* SRC_CORE_LIB_UTILS_PARALLEL_H_ */
