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

#include "rgsw-acc-dm.h"

#include <string>

namespace lbcrypto {

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWACCKey RingGSWAccumulatorDM::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params,
                                              const NativePoly& skNTT, ConstLWEPrivateKey& LWEsk) const {
    auto sv{LWEsk->GetElement()};
    auto mod{sv.GetModulus().ConvertToInt<int32_t>()};
    auto modHalf{mod >> 1};
    uint32_t n(sv.GetLength());
    int32_t baseR(params->GetBaseR());
    const auto& digitsR = params->GetDigitsR();
    RingGSWACCKey ek    = std::make_shared<RingGSWACCKeyImpl>(n, baseR, digitsR.size());

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (uint32_t i = 0; i < n; ++i) {
        for (int32_t j = 1; j < baseR; ++j) {
            for (size_t k = 0; k < digitsR.size(); ++k) {
                auto s{sv[i].ConvertToInt<int32_t>()};
                (*ek)[i][j][k] =
                    KeyGenDM(params, skNTT, (s > modHalf ? s - mod : s) * j * digitsR[k].ConvertToInt<int32_t>());
            }
        }
    }
    return ek;
}

void RingGSWAccumulatorDM::EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek,
                                   RLWECiphertext& acc, const NativeVector& a) const {
    NativeInteger baseR{params->GetBaseR()};
    auto q       = params->Getq();
    auto digitsR = params->GetDigitsR().size();
    uint32_t n   = a.GetLength();

    for (uint32_t i = 0; i < n; ++i) {
        auto aI = NativeInteger(0).ModSubFast(a[i], q);
        for (size_t k = 0; k < digitsR; ++k, aI /= baseR) {
            auto a0 = (aI.Mod(baseR)).ConvertToInt<uint32_t>();
            if (a0)
                AddToAccDM(params, (*ek)[i][a0][k], acc);
        }
    }
}

// Encryption as described in Section 5 of https://eprint.iacr.org/2014/816
// skNTT corresponds to the secret key z
RingGSWEvalKey RingGSWAccumulatorDM::KeyGenDM(const std::shared_ptr<RingGSWCryptoParams>& params,
                                              const NativePoly& skNTT, LWEPlaintext m) const {
    const auto& Gpow       = params->GetGPower();
    const auto& polyParams = params->GetPolyParams();

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};

    // Reduce mod q (dealing with negative number as well)
    uint64_t q = params->Getq().ConvertToInt();
    uint32_t N = params->GetN();
    int64_t mm = (((m % q) + q) % q) * (2 * N / q);
    bool isReducedMM;
    if ((isReducedMM = (mm >= N)))
        mm -= N;

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1) << 1};
    std::vector<NativePoly> tempA(digitsG2, NativePoly(dug, polyParams, Format::COEFFICIENT));
    RingGSWEvalKeyImpl result(digitsG2, 2);

    for (uint32_t i = 0; i < digitsG2; ++i) {
        result[i][0] = tempA[i];
        tempA[i].SetFormat(Format::EVALUATION);
        result[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
        if (!isReducedMM)
            result[i][i & 0x1][mm].ModAddFastEq(Gpow[(i >> 1) + 1], Q);
        else
            result[i][i & 0x1][mm].ModSubFastEq(Gpow[(i >> 1) + 1], Q);
        result[i][0].SetFormat(Format::EVALUATION);
        result[i][1].SetFormat(Format::EVALUATION);
        result[i][1] += (tempA[i] *= skNTT);
    }
    return std::make_shared<RingGSWEvalKeyImpl>(result);
}

// AP Accumulation as described in https://eprint.iacr.org/2020/086
void RingGSWAccumulatorDM::AddToAccDM(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWEvalKey& ek,
                                      RLWECiphertext& acc) const {
    std::vector<NativePoly> ct(acc->GetElements());
    ct[0].SetFormat(Format::COEFFICIENT);
    ct[1].SetFormat(Format::COEFFICIENT);

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1) << 1};
    std::vector<NativePoly> dct(digitsG2, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));

    SignedDigitDecompose(params, ct, dct);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG2))
    for (uint32_t j = 0; j < digitsG2; ++j)
        dct[j].SetFormat(Format::EVALUATION);

    // acc = dct * ek (matrix product);
    // uses in-place * operators for the last call to dct[i] to gain performance improvement
    const std::vector<std::vector<NativePoly>>& ev = ek->GetElements();
    acc->GetElements()[0]                          = (dct[0] * ev[0][0]);
    for (uint32_t l = 1; l < digitsG2; ++l)
        acc->GetElements()[0] += (dct[l] * ev[l][0]);
    acc->GetElements()[1] = (dct[0] *= ev[0][1]);
    for (uint32_t l = 1; l < digitsG2; ++l)
        acc->GetElements()[1] += (dct[l] *= ev[l][1]);
}

};  // namespace lbcrypto
