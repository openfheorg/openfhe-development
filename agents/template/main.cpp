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

// Starting point for an OpenFHE application: CKKS over real numbers.
// It computes x*y + rot(x, 1) under encryption and checks the result against
// the same computation in the clear. Keep that check in your own application.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <vector>

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // 1. Parameters. The multiplicative depth must cover the deepest chain of
    //    multiplications in the computation; here it is 1.
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8);
    parameters.SetSecurityLevel(HEORG24_128);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // 2. Keys. Multiplication needs a relinearization key, and every rotation
    //    index that is used needs its own rotation key.
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1});

    // 3. Encode and encrypt.
    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    std::vector<double> y = {5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25};
    auto cx = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));
    auto cy = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(y));

    // 4. Compute on ciphertexts.
    auto cres = cc->EvalAdd(cc->EvalMult(cx, cy), cc->EvalRotate(cx, 1));

    // 5. Decrypt and compare with the expected values.
    Plaintext result;
    cc->Decrypt(keys.secretKey, cres, &result);
    result->SetLength(x.size());
    std::vector<double> got = result->GetRealPackedValue();

    double maxError = 0.0;
    for (size_t i = 0; i < x.size(); ++i) {
        double expected = x[i] * y[i] + x[(i + 1) % x.size()];
        maxError = std::max(maxError, std::abs(got[i] - expected));
    }
    std::cout << "ring dimension: " << cc->GetRingDimension() << "\n";
    std::cout << "max error:      " << maxError << "\n";

    return maxError < 1e-6 ? 0 : 1;
}
