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

// Starting point for an OpenFHE application: BFV over exact integers.
// It computes x*y, a two-item moving sum of the products and their total under
// encryption, and checks the results against the same computation in the clear.
// Keep that check in your own application.

#include <cstdint>
#include <iostream>
#include <vector>

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // 1. Parameters. All arithmetic is modulo the plaintext modulus t, on values from -(t-1)/2 to (t-1)/2,
    //    and a result outside that range wraps around with no error. Choose t above twice the largest
    //    intermediate value. 786433 is a prime of the form k * 2^18 + 1, which packed encoding needs.
    const uint64_t plaintextModulus = 786433;

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetSecurityLevel(HEORG24_128);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);  // for EvalSum

    // An unsuitable modulus is not rejected above; it ends the process at the first encoding. Check it here.
    if ((plaintextModulus - 1) % (2 * cc->GetRingDimension()) != 0) {
        std::cerr << "plaintext modulus - 1 must be divisible by twice the ring dimension\n";
        return 1;
    }

    // 2. Keys. Multiplication needs a relinearization key, every rotation index its own key, and EvalSum its keys.
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1});
    cc->EvalSumKeyGen(keys.secretKey);

    // 3. Encode and encrypt. A vector shorter than the ring dimension is padded with zeros.
    std::vector<int64_t> x = {12, -7, 300, 45, 8, -120, 77, 250};
    std::vector<int64_t> y = {31, 90, 200, -16, 5, 64, -3, 400};
    const size_t n = x.size();  // EvalSum needs a power of two
    auto cx = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(x));
    auto cy = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(y));

    // 4. Compute on ciphertexts. A left rotation shifts the zero padding in, which is what a sliding window needs.
    auto cProduct = cc->EvalMult(cx, cy);
    auto cWindow = cc->EvalAdd(cProduct, cc->EvalRotate(cProduct, 1));
    auto cTotal = cc->EvalSum(cProduct, n);  // the total is in slot 0

    // 5. Decrypt and compare with the expected values.
    auto decrypt = [&](ConstCiphertext<DCRTPoly> ct, size_t length) {
        Plaintext plaintext;
        cc->Decrypt(keys.secretKey, ct, &plaintext);
        plaintext->SetLength(length);
        return plaintext->GetPackedValue();
    };
    std::vector<int64_t> product = decrypt(cProduct, n);
    std::vector<int64_t> window = decrypt(cWindow, n);
    int64_t total = decrypt(cTotal, 1)[0];

    size_t mismatches = 0;
    int64_t expectedTotal = 0;
    for (size_t i = 0; i < n; ++i) {
        int64_t expected = x[i] * y[i];
        int64_t next = i + 1 < n ? x[i + 1] * y[i + 1] : 0;
        expectedTotal += expected;
        mismatches += product[i] != expected;
        mismatches += window[i] != expected + next;
    }
    mismatches += total != expectedTotal;

    std::cout << "ring dimension: " << cc->GetRingDimension() << "\n";
    std::cout << "total:          " << total << " (expected " << expectedTotal << ")\n";
    std::cout << "mismatches:     " << mismatches << "\n";

    return mismatches == 0 ? 0 : 1;
}
