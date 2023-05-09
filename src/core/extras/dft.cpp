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
  Example of Discrete Fourier Transform
 */

#include "math/dftransform.h"

#include "utils/debug.h"

#include <complex>
#include <iostream>
#include <vector>

using namespace lbcrypto;

int main() {
    std::vector<std::complex<double>> dftVec(64);
    dftVec.at(0)  = std::complex<double>(4, 0);
    dftVec.at(1)  = std::complex<double>(5, 0);
    dftVec.at(2)  = std::complex<double>(5, 0);
    dftVec.at(3)  = std::complex<double>(4.2, 0);
    dftVec.at(4)  = std::complex<double>(5, 0);
    dftVec.at(5)  = std::complex<double>(7.1, 0);
    dftVec.at(6)  = std::complex<double>(6, 0);
    dftVec.at(7)  = std::complex<double>(3, 0);
    dftVec.at(8)  = std::complex<double>(4, 0);
    dftVec.at(9)  = std::complex<double>(5, 0);
    dftVec.at(10) = std::complex<double>(5, 0);
    dftVec.at(11) = std::complex<double>(4.2, 0);
    dftVec.at(12) = std::complex<double>(5, 0);
    dftVec.at(13) = std::complex<double>(7.1, 0);
    dftVec.at(14) = std::complex<double>(6, 0);
    dftVec.at(15) = std::complex<double>(3, 0);
    dftVec.at(16) = std::complex<double>(4, 0);
    dftVec.at(17) = std::complex<double>(5, 0);
    dftVec.at(18) = std::complex<double>(5, 0);
    dftVec.at(19) = std::complex<double>(4.2, 0);
    dftVec.at(20) = std::complex<double>(5, 0);
    dftVec.at(21) = std::complex<double>(7.1, 0);
    dftVec.at(22) = std::complex<double>(6, 0);
    dftVec.at(23) = std::complex<double>(3, 0);
    dftVec.at(24) = std::complex<double>(4, 0);
    dftVec.at(25) = std::complex<double>(5, 0);
    dftVec.at(26) = std::complex<double>(5, 0);
    dftVec.at(27) = std::complex<double>(4.2, 0);
    dftVec.at(28) = std::complex<double>(5, 0);
    dftVec.at(29) = std::complex<double>(7.1, 0);
    dftVec.at(30) = std::complex<double>(6, 0);
    dftVec.at(31) = std::complex<double>(3, 0);
    dftVec.at(32) = std::complex<double>(4, 0);
    dftVec.at(33) = std::complex<double>(5, 0);
    dftVec.at(34) = std::complex<double>(5, 0);
    dftVec.at(35) = std::complex<double>(4.2, 0);
    dftVec.at(36) = std::complex<double>(5, 0);
    dftVec.at(37) = std::complex<double>(7.1, 0);
    dftVec.at(38) = std::complex<double>(6, 0);
    dftVec.at(39) = std::complex<double>(3, 0);
    dftVec.at(40) = std::complex<double>(4, 0);
    dftVec.at(41) = std::complex<double>(5, 0);
    dftVec.at(42) = std::complex<double>(5, 0);
    dftVec.at(43) = std::complex<double>(4.2, 0);
    dftVec.at(44) = std::complex<double>(5, 0);
    dftVec.at(45) = std::complex<double>(7.1, 0);
    dftVec.at(46) = std::complex<double>(6, 0);
    dftVec.at(47) = std::complex<double>(3, 0);
    dftVec.at(48) = std::complex<double>(4, 0);
    dftVec.at(49) = std::complex<double>(5, 0);
    dftVec.at(50) = std::complex<double>(5, 0);
    dftVec.at(51) = std::complex<double>(4.2, 0);
    dftVec.at(52) = std::complex<double>(5, 0);
    dftVec.at(53) = std::complex<double>(7.1, 0);
    dftVec.at(54) = std::complex<double>(6, 0);
    dftVec.at(55) = std::complex<double>(3, 0);
    dftVec.at(56) = std::complex<double>(4, 0);
    dftVec.at(57) = std::complex<double>(5, 0);
    dftVec.at(58) = std::complex<double>(5, 0);
    dftVec.at(59) = std::complex<double>(4.2, 0);
    dftVec.at(60) = std::complex<double>(5, 0);
    dftVec.at(61) = std::complex<double>(7.1, 0);
    dftVec.at(62) = std::complex<double>(6, 0);
    dftVec.at(63) = std::complex<double>(3, 0);

    DiscreteFourierTransform::PreComputeTable(128);

    double start                              = currentDateTime();
    std::vector<std::complex<double>> dftVec2 = DiscreteFourierTransform::ForwardTransform(dftVec);
    double end                                = currentDateTime();
    std::cout << "Without table: " << end - start << " ms" << std::endl;

    start                                     = currentDateTime();
    std::vector<std::complex<double>> dftVec3 = DiscreteFourierTransform::ForwardTransform(dftVec);
    end                                       = currentDateTime();
    std::cout << "With table: " << end - start << " ms" << std::endl << std::endl;
}
