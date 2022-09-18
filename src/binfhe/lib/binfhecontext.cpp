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
  Implementation file for Boolean Circuit FHE context class
 */

#include "binfhecontext.h"
#include <string>
#include <unordered_map>

namespace lbcrypto {

void BinFHEContext::GenerateBinFHEContext(uint32_t n, uint32_t N, const NativeInteger& q, const NativeInteger& Q,
                                          double std, uint32_t baseKS, uint32_t baseG, uint32_t baseR,
                                          BINFHEMETHOD method) {
    auto lweparams  = std::make_shared<LWECryptoParams>(n, N, q, Q, Q, std, baseKS);
    auto rgswparams = std::make_shared<RingGSWCryptoParams>(N, Q, q, baseG, baseR, method, std, true);
    m_params        = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme  = std::make_shared<BinFHEScheme>();
    m_binfhescheme->SetACCTechnique(method);
}

void BinFHEContext::GenerateBinFHEContext(BINFHEPARAMSET set, bool arbFunc, uint32_t logQ, int64_t N,
                                          BINFHEMETHOD method, bool timeOptimization) {
    if (GINX != method) {
        std::string errMsg("ERROR: CGGI is the only supported method");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    if (set != STD128 && set != TOY) {
        std::string errMsg("ERROR: STD128 and TOY are the onlysupported sets");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    if (logQ > 29) {
        std::string errMsg("ERROR: logQ > 29 is not supported");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    if (logQ < 11) {
        std::string errMsg("ERROR: logQ < 11 is not supported");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    auto logQprime = 54;
    uint32_t baseG = 0;
    if (logQ > 25) {
        baseG = 1 << 14;
    }
    else if (logQ > 16) {
        baseG = 1 << 18;
    }
    else if (logQ > 11) {
        baseG = 1 << 27;
    }
    else {  // if (logQ == 11)
        baseG     = 1 << 5;
        logQprime = 27;
    }

    m_timeOptimization = timeOptimization;
    SecurityLevel sl   = HEStd_128_classic;
    // choose minimum ringD satisfying sl and Q
    uint32_t ringDim = StdLatticeParm::FindRingDim(HEStd_ternary, sl, logQprime);
    if (N >= ringDim) {  // if specified some larger N, security is also satisfied
        ringDim = N;
    }
    // find prime Q for NTT
    NativeInteger Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(logQprime, ringDim), ringDim);
    // q = N*2 by default for maximum plaintext space, if needed for arbitrary function evlauation, q = ringDim/2
    uint32_t q = arbFunc ? ringDim : ringDim * 2;

    uint64_t qKS = 1 << 30;
    qKS <<= 5;

    uint32_t n      = (set == TOY) ? 32 : 1305;
    auto lweparams  = std::make_shared<LWECryptoParams>(n, ringDim, q, Q, qKS, 3.19, 32);
    auto rgswparams = std::make_shared<RingGSWCryptoParams>(ringDim, Q, q, baseG, 23, method, 3.19,
                                                            ((logQ != 11) && timeOptimization));

    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>();
    m_binfhescheme->SetACCTechnique(method);

#if defined(BINFHE_DEBUG)
    std::cout << ringDim << " " << Q < < < < " " << n << " " << q << " " << baseG << std::endl;
#endif
}

void BinFHEContext::GenerateBinFHEContext(BINFHEPARAMSET set, BINFHEMETHOD method) {
    struct BinFHEContextParams {
        // for intermediate prime, modulus for RingGSW / RLWE used in bootstrapping
        usint numberBits;
        usint cyclOrder;

        // for LWE crypto parameters
        usint latticeParam;
        usint mod;  // modulus for additive LWE
        // modulus for key switching; if it is zero, then it is replaced with intermediate prime for LWE crypto parameters
        usint modKS;
        double stdDev;
        usint baseKS;  // base for key switching

        // for Ring GSW + LWE parameters
        usint gadgetBase;  // gadget base used in the bootstrapping
        usint baseRK;      // base for the refreshing key
    };
    enum { PRIME = 0 };  // value for modKS if you want to use the intermediate prime for modulus for key switching
    const double STD_DEV = 3.19;
    // clang-format off
    const std::unordered_map<BINFHEPARAMSET, BinFHEContextParams> paramsMap({
        //           numberBits|cyclOrder|latticeParam|  mod|   modKS|  stdDev| baseKS| gadgetBase|baseRK
        { TOY,             { 27,     1024,          64,  512,   PRIME, STD_DEV,     25,    1 <<  9,  23 } },
        { MEDIUM,          { 28,     2048,         422, 1024, 1 << 14, STD_DEV, 1 << 7,    1 << 10,  32 } },
        { STD128_AP,       { 27,     2048,         512, 1024, 1 << 14, STD_DEV, 1 << 7,    1 <<  9,  32 } },
        { STD128_APOPT,    { 27,     2048,         502, 1024, 1 << 14, STD_DEV, 1 << 7,    1 <<  9,  32 } },
        { STD128,          { 27,     2048,         512, 1024, 1 << 14, STD_DEV, 1 << 7,    1 <<  7,  32 } },
        { STD128_OPT,      { 27,     2048,         502, 1024, 1 << 14, STD_DEV, 1 << 7,    1 <<  7,  32 } },
        { STD192,          { 37,     4096,        1024, 1024, 1 << 19, STD_DEV,     28,    1 << 13,  32 } },
        { STD192_OPT,      { 37,     4096,         805, 1024, 1 << 15, STD_DEV,     32,    1 << 13,  32 } },
        { STD256,          { 29,     4096,        1024, 2048, 1 << 14, STD_DEV, 1 << 7,    1 <<  8,  46 } },
        { STD256_OPT,      { 29,     4096,         990, 2048, 1 << 14, STD_DEV, 1 << 7,    1 <<  8,  46 } },
        { STD128Q,         { 50,     4096,        1024, 1024, 1 << 25, STD_DEV,     32,    1 << 25,  32 } },
        { STD128Q_OPT,     { 50,     4096,         585, 1024, 1 << 15, STD_DEV,     32,    1 << 25,  32 } },
        { STD192Q,         { 35,     4096,        1024, 1024, 1 << 17, STD_DEV,     64,    1 << 12,  32 } },
        { STD192Q_OPT,     { 35,     4096,         875, 1024, 1 << 15, STD_DEV,     32,    1 << 12,  32 } },
        { STD256Q,         { 27,     4096,        2048, 2048, 1 << 16, STD_DEV,     16,    1 <<  7,  46 } },
        { STD256Q_OPT,     { 27,     4096,        1225, 1024, 1 << 16, STD_DEV,     16,    1 <<  7,  32 } },
        { SIGNED_MOD_TEST, { 28,     2048,         512, 1024,   PRIME, STD_DEV,     25,    1 <<  7,  23 } },
    });
    // clang-format on

    auto search = paramsMap.find(set);
    if (paramsMap.end() == search) {
        std::string errMsg("ERROR: Unknown parameter set [" + std::to_string(set) + "] for FHEW.");
        OPENFHE_THROW(config_error, errMsg);
    }

    BinFHEContextParams params = search->second;
    // intermediate prime
    NativeInteger Q(
        PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(params.numberBits, params.cyclOrder), params.cyclOrder));

    usint ringDim   = params.cyclOrder / 2;
    auto lweparams  = (PRIME == params.modKS) ?
                          std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, Q,
                                                           params.stdDev, params.baseKS) :
                          std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, params.modKS,
                                                           params.stdDev, params.baseKS);
    auto rgswparams = std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase, params.baseRK,
                                                            method, params.stdDev);

    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>();
    m_binfhescheme->SetACCTechnique(method);
}

LWEPrivateKey BinFHEContext::KeyGen(NativeInteger modulus) const {
    auto& LWEParams = m_params->GetLWEParams();
    if (modulus > LWEParams->Getq()) {
        return m_LWEscheme->KeyGen(LWEParams->Getn(), modulus);
    }
    return m_LWEscheme->KeyGen(LWEParams->Getn(), LWEParams->Getq());
}

LWEPrivateKey BinFHEContext::KeyGenN() const {
    auto& LWEParams = m_params->GetLWEParams();
    return m_LWEscheme->KeyGen(LWEParams->GetN(), LWEParams->GetQ());
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey sk, const LWEPlaintext& m, BINFHEOUTPUT output,
                                     LWEPlaintextModulus p, NativeInteger DiffQ) const {
    auto& LWEParams = m_params->GetLWEParams();

    auto q = LWEParams->Getq();
    if (DiffQ > q) {
        SetQ(DiffQ);
    }
    LWECiphertext ct;

    ct = m_LWEscheme->Encrypt(LWEParams, sk, m, p);
    if ((output == FRESH) || (p != 4)) {
        // No bootstrapping needed
    }
    else {
        ct = m_binfhescheme->Bootstrap(m_params, m_BTKey, ct);
    }

    if (DiffQ > q) {
        SetQ(q);
    }
    return ct;
}

void BinFHEContext::Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct, LWEPlaintext* result, LWEPlaintextModulus p,
                            NativeInteger DiffQ) const {
    auto& LWEParams = m_params->GetLWEParams();

    auto q = LWEParams->Getq();
    if (DiffQ != 0) {
        SetQ(DiffQ);
        LWEPrivateKeyImpl skp(sk->GetElement());
        LWEPrivateKey skpptr = std::make_shared<LWEPrivateKeyImpl>(skp);
        skpptr->switchModulus(DiffQ);
        m_LWEscheme->Decrypt(LWEParams, skpptr, ct, result, p);
        SetQ(q);
    }
    else {
        m_LWEscheme->Decrypt(LWEParams, sk, ct, result, p);
    }
}

LWESwitchingKey BinFHEContext::KeySwitchGen(ConstLWEPrivateKey sk, ConstLWEPrivateKey skN) const {
    return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
}

void BinFHEContext::BTKeyGen(ConstLWEPrivateKey sk, NativeInteger DiffQ) {
    auto& LWEParams  = m_params->GetLWEParams();
    auto& RGSWParams = m_params->GetRingGSWParams();

    auto q = LWEParams->Getq();
    if (DiffQ > q) {
        SetQ(DiffQ);
    }

    auto temp = RGSWParams->GetBaseG();

    if (m_timeOptimization) {
        auto gpowermap = RGSWParams->GetGPowerMap();
        for (std::map<uint32_t, std::vector<NativeInteger>>::iterator it = gpowermap.begin(); it != gpowermap.end();
             ++it) {
            RGSWParams->Change_BaseG(it->first);
            m_BTKey_map[it->first] = m_binfhescheme->KeyGen(m_params, sk);
        }
        RGSWParams->Change_BaseG(temp);
    }

    if (m_BTKey_map.size() != 0) {
        m_BTKey = m_BTKey_map[temp];
    }
    else {
        m_BTKey           = m_binfhescheme->KeyGen(m_params, sk);
        m_BTKey_map[temp] = m_BTKey;
    }

    if (DiffQ > q) {
        SetQ(q);
    }
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, ConstLWECiphertext ct1, ConstLWECiphertext ct2) const {
    return m_binfhescheme->EvalBinGate(m_params, gate, m_BTKey, ct1, ct2);
}

LWECiphertext BinFHEContext::Bootstrap(ConstLWECiphertext ct) const {
    return m_binfhescheme->Bootstrap(m_params, m_BTKey, ct);
}

LWECiphertext BinFHEContext::EvalNOT(ConstLWECiphertext ct) const {
    return m_binfhescheme->EvalNOT(m_params, ct);
}

LWECiphertext BinFHEContext::EvalConstant(bool value) const {
    return m_LWEscheme->NoiselessEmbedding(m_params->GetLWEParams(), value);
}

LWECiphertext BinFHEContext::EvalFunc(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT) const {
    NativeInteger beta = GetBeta();
    return m_binfhescheme->EvalFunc(m_params, m_BTKey, ct, LUT, beta, 0);
}

LWECiphertext BinFHEContext::EvalFloor(ConstLWECiphertext ct, const uint32_t roundbits) const {
    auto q = m_params->GetLWEParams()->Getq().ConvertToInt();
    if (roundbits != 0) {
        NativeInteger newp = this->GetMaxPlaintextSpace();
        SetQ(q / newp * (1 << roundbits));
    }
    NativeInteger beta = GetBeta();
    auto res           = m_binfhescheme->EvalFloor(m_params, m_BTKey, ct, beta);
    SetQ(q);
    return res;
}

LWECiphertext BinFHEContext::EvalSign(ConstLWECiphertext ct) {
    auto params        = std::make_shared<BinFHECryptoParams>(*m_params);
    NativeInteger beta = GetBeta();
    return m_binfhescheme->EvalSign(params, m_BTKey_map, ct, beta);
}

std::vector<LWECiphertext> BinFHEContext::EvalDecomp(ConstLWECiphertext ct) {
    NativeInteger beta = GetBeta();
    return m_binfhescheme->EvalDecomp(m_params, m_BTKey_map, ct, beta);
}

std::vector<NativeInteger> BinFHEContext::GenerateLUTviaFunction(NativeInteger (*f)(NativeInteger m, NativeInteger p),
                                                                 NativeInteger p) {
    if (ceil(log2(p.ConvertToInt())) != floor(log2(p.ConvertToInt()))) {
        std::string errMsg("ERROR: Only support plaintext space to be power-of-two.");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    NativeInteger q        = GetParams()->GetLWEParams()->Getq();
    NativeInteger interval = q / p;
    NativeInteger outerval = interval;
    usint vecSize          = q.ConvertToInt();
    std::vector<NativeInteger> vec(vecSize);
    for (usint i = 0; i < vecSize; ++i) {
        auto temp = f(NativeInteger(i) / interval, p);
        if (temp >= p) {
            std::string errMsg("ERROR: input function should output in Z_{p_output}.");
            OPENFHE_THROW(not_implemented_error, errMsg);
        }
        vec[i] = temp * outerval;
    }

    return vec;
}

}  // namespace lbcrypto
