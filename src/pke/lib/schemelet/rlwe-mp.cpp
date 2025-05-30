//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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

#include "schemebase/rlwe-cryptoparameters.h"
#include "schemelet/rlwe-mp.h"

#include <stdint.h>
#include <vector>

template <typename typeT>
static void BitReverse(typeT& vals) {
    uint32_t size = vals.size();
    for (uint32_t i = 1, j = 0; i < size; ++i) {
        uint32_t bit = size >> 1;
        for (; j >= bit; bit >>= 1)
            j -= bit;
        j += bit;
        if (i < j) {
            auto t  = vals[i];
            vals[i] = vals[j];
            vals[j] = t;
        }
    }
}

template <typename typeT>
static void BitReverseTwoHalves(typeT& vals) {
    uint32_t size = vals.size() / 2;
    for (uint32_t i = 1, j = 0; i < size; ++i) {
        uint32_t bit = size >> 1;
        for (; j >= bit; bit >>= 1)
            j -= bit;
        j += bit;
        if (i < j) {
            auto t  = vals[i];
            vals[i] = vals[j];
            vals[j] = t;
        }
    }

    for (uint32_t i = size + 1, j = size; i < 2 * size; ++i) {
        uint32_t bit = size >> 1;
        for (; j >= size + bit; bit >>= 1)
            j -= bit;
        j += bit;
        if (i < j) {
            auto t  = vals[i];
            vals[i] = vals[j];
            vals[j] = t;
        }
    }
}

namespace lbcrypto {

namespace {

static std::vector<DCRTPoly> ModSwitchUp(const std::vector<Poly>& input, const BigInteger& Qfrom, const BigInteger& Qto,
                                         const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& ep) {
    Poly bPoly = input[0];
    bPoly.SwitchModulus(Qto, 1, 0, 0);  // need to switch to modulus before because the new modulus is bigger

    Poly aPoly = input[1];
    aPoly.SwitchModulus(Qto, 1, 0, 0);  // need to switch to modulus before because the new modulus is bigger

    std::vector<DCRTPoly> output{DCRTPoly(bPoly.MultiplyAndRound(Qto, Qfrom), ep),
                                 DCRTPoly(aPoly.MultiplyAndRound(Qto, Qfrom), ep)};
    output[0].SetFormat(Format::EVALUATION);
    output[1].SetFormat(Format::EVALUATION);

    return output;
}

static std::vector<DCRTPoly> ModSwitchDown(const std::vector<Poly>& input, const BigInteger& Qfrom,
                                           const BigInteger& Qto,
                                           const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& ep) {
    Poly bPoly = input[0];
    bPoly      = bPoly.MultiplyAndRound(Qto, Qfrom);
    bPoly.SwitchModulus(Qto, 1, 0, 0);

    Poly aPoly = input[1];
    aPoly      = aPoly.MultiplyAndRound(Qto, Qfrom);
    aPoly.SwitchModulus(Qto, 1, 0, 0);

    std::vector<DCRTPoly> output{DCRTPoly(bPoly, ep), DCRTPoly(aPoly, ep)};
    output[0].SetFormat(Format::EVALUATION);
    output[1].SetFormat(Format::EVALUATION);

    return output;
}

}  // namespace

std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>> SchemeletRLWEMP::GetElementParams(
    const PrivateKey<DCRTPoly>& privateKey, uint32_t level) {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(privateKey->GetCryptoParameters());

    auto ep = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(*(cryptoParams->GetElementParams()));
    for (uint32_t i = 0; i < level; ++i)
        ep->PopLastParam();

    return ep;
}

std::vector<Poly> SchemeletRLWEMP::EncryptCoeff(std::vector<int64_t> input, const BigInteger& Q, const BigInteger& p,
                                                const PrivateKey<DCRTPoly>& privateKey,
                                                const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& ep,
                                                bool bitReverse) {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(privateKey->GetCryptoParameters());

    DugType dug;
    DCRTPoly a(dug, ep, Format::EVALUATION);
    DCRTPoly e(cryptoParams->GetDiscreteGaussianGenerator(), ep, Format::EVALUATION);

    const DCRTPoly& s = privateKey->GetPrivateElement();
    auto scopy(s);
    scopy.DropLastElements(s.GetParams()->GetParams().size() - ep->GetParams().size());

    DCRTPoly b = e - a * scopy;  // encryption of 0 using Q'

    a.SetFormat(Format::COEFFICIENT);
    auto aPoly = a.CRTInterpolate();
    b.SetFormat(Format::COEFFICIENT);
    auto bPoly = b.CRTInterpolate();

    BigInteger bigQPrime = b.GetModulus();

    // Do modulus switching from Q' to Q
    if (Q < bigQPrime) {
        bPoly = bPoly.MultiplyAndRound(Q, bigQPrime);
        bPoly.SwitchModulus(Q, 1, 0, 0);

        aPoly = aPoly.MultiplyAndRound(Q, bigQPrime);
        aPoly.SwitchModulus(Q, 1, 0, 0);
    }
    else {
        bPoly.SwitchModulus(Q, 1, 0, 0);
        bPoly = bPoly.MultiplyAndRound(Q, bigQPrime);

        aPoly.SwitchModulus(Q, 1, 0, 0);
        aPoly = aPoly.MultiplyAndRound(Q, bigQPrime);
    }

    auto mPoly = bPoly;
    mPoly.SetValuesToZero();

    auto delta   = Q / p;
    uint32_t gap = mPoly.GetLength() / (2.0 * input.size());
    gap          = (gap == 0) ? 1 : gap;

    if (bitReverse) {
        if (gap == 1) {
            BitReverseTwoHalves(input);
        }
        else {
            BitReverse(input);
        }
    }

    const uint32_t limit = input.size() < mPoly.GetLength() ? input.size() : mPoly.GetLength();
    for (uint32_t i = 0; i < limit; ++i) {
        auto entry     = (input[i] < 0) ? mPoly.GetModulus() - BigInteger(static_cast<uint64_t>(llabs(input[i]))) :
                                          BigInteger{input[i]};
        mPoly[i * gap] = delta * entry;
    }

    return {bPoly += mPoly, aPoly};
}

std::vector<int64_t> SchemeletRLWEMP::DecryptCoeff(const std::vector<Poly>& input, const BigInteger& Q,
                                                   const BigInteger& p, const PrivateKey<DCRTPoly>& privateKey,
                                                   const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& ep,
                                                   uint32_t numSlots, bool bitReverse) {
    const auto& bigQPrime = ep->GetModulus();

    std::vector<lbcrypto::DCRTPoly> ba =
        (Q < bigQPrime) ? ModSwitchUp(input, Q, bigQPrime, ep) : ModSwitchDown(input, Q, bigQPrime, ep);

    const DCRTPoly& s = privateKey->GetPrivateElement();
    size_t sizeQ      = s.GetParams()->GetParams().size();
    size_t sizeQl     = ep->GetParams().size();
    size_t diffQl     = sizeQ - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    auto m = ba[0] + ba[1] * scopy;

    m.SetFormat(Format::COEFFICIENT);

    auto mPoly   = m.CRTInterpolate();
    uint32_t gap = mPoly.GetLength() / (2 * numSlots);

    if (Q < bigQPrime) {
        mPoly = mPoly.MultiplyAndRound(Q, bigQPrime);
        mPoly.SwitchModulus(Q, 1, 0, 0);
    }
    else {
        mPoly.SwitchModulus(Q, 1, 0, 0);
        mPoly = mPoly.MultiplyAndRound(Q, bigQPrime);
    }

    mPoly = mPoly.MultiplyAndRound(p, Q);
    mPoly.SwitchModulus(p, 1, 0, 0);

    BigInteger half = p >> 1;

    // uint32_t length = (gap == 1) ? 2 * numSlots : numSlots;
    uint32_t length = 2 * numSlots;  // For complex entries

    std::vector<int64_t> output(length);
    for (size_t i = 0, idx = 0; i < length; ++i, idx += gap) {
        int64_t val;
        if (mPoly[idx] > half) {
            val = (-(p - mPoly[idx]).ConvertToInt());
        }
        else {
            val = mPoly[idx].ConvertToInt();
        }
        output[i] = val;
    }

    if (bitReverse) {
        if (gap == 1) {
            BitReverseTwoHalves(output);
        }
        else {
            BitReverse(output);
        }
    }

    return output;
}

void SchemeletRLWEMP::ModSwitch(std::vector<Poly>& input, const BigInteger& Q1, const BigInteger& Q2) {
    input[0] = input[0].MultiplyAndRound(Q1, Q2);
    input[0].SwitchModulus(Q1, 1, 0, 0);
    input[1] = input[1].MultiplyAndRound(Q1, Q2);
    input[1].SwitchModulus(Q1, 1, 0, 0);
}

Ciphertext<DCRTPoly> SchemeletRLWEMP::convert(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<Poly>& coeffs,
                                              const PublicKey<DCRTPoly>& pubKey, const BigInteger& Bigq, uint32_t slots,
                                              uint32_t level) {
    std::vector<std::complex<double>> y(1);
    auto ptxt = cc.MakeCKKSPackedPlaintext(y, 1, level);
    ptxt->SetLength(slots);

    auto ctxt = cc.Encrypt(pubKey, ptxt);

    auto ep = ptxt->GetElement<DCRTPoly>().GetParams();

    auto& qPrimeCKKS = ep->GetModulus();

    auto elementsCKKS =
        (qPrimeCKKS > Bigq) ? ModSwitchUp(coeffs, Bigq, qPrimeCKKS, ep) : ModSwitchDown(coeffs, Bigq, qPrimeCKKS, ep);
    ctxt->SetElements(elementsCKKS);
    return ctxt;
}

std::vector<Poly> SchemeletRLWEMP::convert(ConstCiphertext<DCRTPoly>& ctxt, const BigInteger& Q,
                                           const BigInteger& QPrime) {
    auto b = ctxt->GetElements()[0];
    b.SetFormat(Format::COEFFICIENT);
    auto bPoly = b.CRTInterpolate();

    auto a = ctxt->GetElements()[1];
    a.SetFormat(Format::COEFFICIENT);
    auto aPoly = a.CRTInterpolate();

    if (Q < QPrime) {
        bPoly = bPoly.MultiplyAndRound(Q, QPrime);
        bPoly.SwitchModulus(Q, 1, 0, 0);

        aPoly = aPoly.MultiplyAndRound(Q, QPrime);
        aPoly.SwitchModulus(Q, 1, 0, 0);
    }
    else {
        bPoly.SwitchModulus(Q, 1, 0, 0);
        bPoly = bPoly.MultiplyAndRound(Q, QPrime);

        aPoly.SwitchModulus(Q, 1, 0, 0);
        aPoly = aPoly.MultiplyAndRound(Q, QPrime);
    }
    return {bPoly, aPoly};
}

}  // namespace lbcrypto
