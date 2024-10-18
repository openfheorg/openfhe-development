//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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

// ATTENTION: enable this example for g++ on Linux only
//==================================================================================
#if (defined(__linux__) || defined(__unix__)) && !defined(__APPLE__) && defined(__GNUC__) && !defined(__clang__)
//==================================================================================
#pragma GCC push_options
#pragma GCC optimize("O0")  // Disable optimizations for this file
//==================================================================================

#include "math/distributiongenerator.h"
#include <random>
#include <iostream>

void usage() {
    std::cerr << "Usage: ./external-prng [absolute path to the external PRNG library]" << std::endl;
    std::cerr << "       " << "If no absolute library path is provided, then the built-in OpenFHE's PRNG is used" << std::endl;
}

int main(int argc, char* argv[]) {
    if(argc > 1) {
        std::string arg = argv[1];
        // handle -h
        if (arg == "-h") {
            usage();
            exit(0);
        }

        std::cerr << "==== Using external PRNG" << std::endl;
        lbcrypto::PseudoRandomNumberGenerator::InitPRNGEngine(arg);
    }
    else {
        std::cerr << "==== Using OpenFHE's built-in PRNG" << std::endl;
    }

    std::uniform_int_distribution<> dis(0, 10);
    for ( size_t i = 0; i < 5; ++i) {
        [[maybe_unused]] int randomNum = dis(lbcrypto::PseudoRandomNumberGenerator::GetPRNG());
    }

    return 0;
}

//==================================================================================
#pragma GCC pop_options  // Restore the previous optimization level
//==================================================================================
#else
// had to add the code below as clang++ didn't like linking this file without main. :)
#include <iostream>

int main(int argc, char* argv[]) {
    std::cerr << "This example is for g++ on Linux only" << std::endl;
    return 0;
}

#endif
