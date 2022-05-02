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
  This is an example demo file that demonstrates timing of Parallel operations using openmp
 */

#define PROFILE  // by defining this we activate the PROFILELOG() outputs

#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>
#include "openfhecore.h"
#include "time.h"

// function to verify our generated array
void verify(float* foo, uint32_t array_size) {
    // verify that the data was generated correctly.
    bool goodflag = true;
    for (size_t i = 1; i < array_size; ++i) {
        if ((foo[i] - foo[i - 1]) != 1) {
            goodflag = goodflag & false;
        }
    }
    if (goodflag) {
        std::cout << "verification succeeded" << std::endl;
    }
    else {
        std::cout << "verification failed" << std::endl;
        for (size_t i = 0; i < array_size; ++i) {
            std::cout << foo[i] << " ";
        }
        std::cout << std::endl;
    }
    return;
}

int main(int argc, char* argv[]) {
    // note if you set dbg_flag = true then all  the following OPENFHE_DEBUG() statments
    // print to stdout.
    OPENFHE_DEBUG_FLAG(true);

    lbcrypto::OpenFHEParallelControls.Enable();

    uint32_t array_size = 1000;
    OPENFHE_DEBUGEXP(argc);
    OPENFHE_DEBUGEXP(argv[0]);

    if (argc < 2) {
        std::cout << "running " << argv[0] << " with default array size of 1000" << std::endl;
    }
    else {
        array_size = atoi(argv[1]);
        if (array_size <= 0) {
            std::cout << "error in argment " << argv[1] << " must be greater than zero " << std::endl;
            exit(-1);
        }
    }

    // build the array and zero it out.
    float* foo = new float[array_size];
    for (size_t i = 0; i < array_size; i++) {
        foo[i] = 0;
    }

    TimeVar t_total;   // define timer variable for TIC() TOC() timing functions.
    double timeTotal;  // holds the resulting time

    std::cout << "Parallel computation demo using " << omp_get_num_procs() << " processors." << std::endl;
    std::cout << "and maximum of " << omp_get_max_threads() << " threads." << std::endl << std::endl;
    std::cout << "to change # threads from the default, execute at the comamnd line " << std::endl;
    std::cout << " For the bash shell, enter:" << std::endl
              << "export OMP_NUM_THREADS=<number of threads to use>" << std::endl
              << "For the csh or tcsh shell, enter: " << std::endl
              << " setenv OMP_NUM_THREADS <number of threads to use>" << std::endl;
    std::cout << " or use omp_set_num_threads() in your code." << std::endl << std::endl;

    std::cout << "HINT: use export OMP_DISPLAY_ENV=TRUE to see all your settings" << std::endl;

    int nthreads, tid;
// determine how many threads we will have.
#pragma omp parallel private(nthreads, tid)
    {
        /* Obtain thread number */
        tid = omp_get_thread_num();

        /* Only main thread does this */
        if (tid == 0) {
            nthreads = omp_get_num_threads();
            std::cout << "Confirmed Number of threads = " << nthreads << std::endl;
        }
    }

    // demonstrate debug functions (only active when dbg_flag = true)
    std::cout << "demonstrating OPENFHE_DEBUG()" << std::endl;
    OPENFHE_DEBUG("array_size = " << array_size);
    OPENFHE_DEBUGEXP(array_size);
    OPENFHE_DEBUGWHERE(array_size);

#if !defined(NDEBUG)
    dbg_flag = false;
#endif
    // these three no longer report any value
    OPENFHE_DEBUG("array_size = " << array_size);
    OPENFHE_DEBUGEXP(array_size);
    OPENFHE_DEBUGWHERE(array_size);

    std::cout << std::endl;
    // now run the parallel job

    TIC(t_total);  // set the timer.

    // define a parallel loop that takes 10 milliseconds to execute then performs
    // a small task of filling in an array
#pragma omp parallel for
    for (size_t i = 0; i < array_size; ++i) {
        float tmp = i;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        foo[i] = tmp;
    }

    // read the timer to get the computation time in miliseconds
    // look at debug.h to find other timers you can use

    timeTotal = TOC_MS(t_total);
    PROFILELOG("Total time with internal delay: "
               << "\t" << timeTotal << " ms");
    verify(foo, array_size);
    std::cout << std::endl;

    // repeat the parallel process without the internal delay
    // clear out foo.
    for (size_t i = 0; i < array_size; i++) {
        foo[i] = 0;
    }

    TIC(t_total);  // reset the timer.
                   // define a parallel loop that takes 10 milliseconds to execute then performs
                   // a small task of filling in an array
#pragma omp parallel for
    for (size_t i = 0; i < array_size; ++i) {
        float tmp = i;
        foo[i]    = tmp;
    }

    // read the timer to get the computation time in micro seconds
    timeTotal = TOC_US(t_total);
    PROFILELOG("Total time without internal delay: "
               << "\t" << timeTotal << " us");
    verify(foo, array_size);

    return 0;
}
