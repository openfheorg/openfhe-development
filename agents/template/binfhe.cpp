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

// Starting point for an OpenFHE application: Boolean circuits with binfhe.
// It evaluates a one-bit full adder under encryption for every input and checks
// the results against the same computation in the clear. Keep that check in your
// own application.

#include <iostream>

#include "binfhecontext.h"

using namespace lbcrypto;

int main() {
    // 1. Context and keys. STD128 gives more than 128 bits of security. Every gate is a bootstrapping,
    //    so the bootstrapping keys are needed before the first gate.
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    int mismatches = 0;
    for (int bits = 0; bits < 8; ++bits) {
        LWEPlaintext a = bits & 1, b = (bits >> 1) & 1, carryIn = (bits >> 2) & 1;

        // 2. Encrypt one bit per ciphertext.
        auto ca = cc.Encrypt(sk, a);
        auto cb = cc.Encrypt(sk, b);
        auto cCarryIn = cc.Encrypt(sk, carryIn);

        // 3. Compute on ciphertexts. The two inputs of a gate must be different ciphertexts;
        //    a result can feed any number of later gates.
        auto aXorB = cc.EvalBinGate(XOR, ca, cb);
        auto cSum = cc.EvalBinGate(XOR, aXorB, cCarryIn);
        auto cCarry = cc.EvalBinGate(OR, cc.EvalBinGate(AND, ca, cb), cc.EvalBinGate(AND, cCarryIn, aXorB));

        // 4. Decrypt and compare with the expected values.
        LWEPlaintext sum, carry;
        cc.Decrypt(sk, cSum, &sum);
        cc.Decrypt(sk, cCarry, &carry);
        mismatches += sum != ((a + b + carryIn) & 1);
        mismatches += carry != ((a + b + carryIn) >> 1);
    }

    std::cout << "full adder, 8 inputs, 5 gates each\n";
    std::cout << "mismatches: " << mismatches << "\n";

    return mismatches == 0 ? 0 : 1;
}
