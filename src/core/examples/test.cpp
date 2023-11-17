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
  Example of integer Gaussian sampling
 */

#include "openfhecore.h"
// #include <vld.h>
using namespace lbcrypto;

int main() {
    // double std = 1000;
    // double std = 10000;

    usint m = 16;

    NativeInteger modulusP = FirstPrime<NativeInteger>(16, m);
    NativeInteger rootOfUnityP(RootOfUnity(m, modulusP));

    NativeInteger modulus = FirstPrime<NativeInteger>(22, m);
    NativeInteger rootOfUnity(RootOfUnity(m, modulus));

    ILNativeParams paramsP(m, modulusP, rootOfUnityP);
    auto epP = std::make_shared<ILNativeParams>(paramsP);

    ILNativeParams params(m, modulus, rootOfUnity);
    auto ep = std::make_shared<ILNativeParams>(params);

    std::cerr << modulus << std::endl;
    std::cerr << rootOfUnity << std::endl;

    NativePoly x1(epP, Format::EVALUATION);

    // x1 = {1,0,2,0,3,0,4,0};
    x1 = {1, 1, 2, 2, 3, 3, 4, 4};

    std::cerr << "x1 = " << x1 << std::endl;

    x1.SetFormat(Format::COEFFICIENT);

    std::cerr << "x1 = " << x1 << std::endl;

    x1.SwitchModulus(modulus, rootOfUnity, 0, 0);

    x1.SetFormat(Format::EVALUATION);

    std::cerr << "x1 = " << x1 << std::endl;

    usint m2 = 8;

    NativeInteger rootOfUnityP2 = rootOfUnityP.ModMul(rootOfUnityP, modulusP);
    ILNativeParams paramsP2(m2, modulusP, rootOfUnityP2);
    auto epP2 = std::make_shared<ILNativeParams>(paramsP2);

    NativePoly x2(epP2, Format::EVALUATION);
    x2 = {1, 2, 3, 4};

    std::cerr << "x2 = " << x2 << std::endl;

    x2.SetFormat(Format::COEFFICIENT);

    std::cerr << "x2 = " << x2 << std::endl;

    x2.SwitchModulus(modulus, rootOfUnity.ModMul(rootOfUnity, modulus), 0, 0);

    x2.SetFormat(Format::EVALUATION);

    std::cerr << "x2 = " << x2 << std::endl;
}
