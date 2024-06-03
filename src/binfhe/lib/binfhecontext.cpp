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
                                          SecretKeyDist keyDist, BINFHE_METHOD method, uint32_t numAutoKeys) {
    auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, Q, std, baseKS);
    auto rgswparams =
        std::make_shared<RingGSWCryptoParams>(N, Q, q, baseG, baseR, method, std, keyDist, true, numAutoKeys);
    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

void BinFHEContext::GenerateBinFHEContext(BINFHE_PARAMSET set, bool arbFunc, uint32_t logQ, int64_t N,
                                          BINFHE_METHOD method, bool timeOptimization) {
    if (GINX != method) {
        std::string errMsg("ERROR: CGGI is the only supported method");
        OPENFHE_THROW(errMsg);
    }
    if (set != STD128 && set != TOY) {
        std::string errMsg("ERROR: STD128 and TOY are the only supported sets");
        OPENFHE_THROW(errMsg);
    }

    if (logQ > 29) {
        std::string errMsg("ERROR: logQ > 29 is not supported");
        OPENFHE_THROW(errMsg);
    }
    if (logQ < 11) {
        std::string errMsg("ERROR: logQ < 11 is not supported");
        OPENFHE_THROW(errMsg);
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
    NativeInteger Q = LastPrime<NativeInteger>(logQprime, 2 * ringDim);
    // q = 2*ringDim by default for maximum plaintext space, if needed for arbitrary function evaluation, q = ringDim
    uint32_t q = arbFunc ? ringDim : 2 * ringDim;

    uint64_t qKS = 1 << 30;
    qKS <<= 5;

    uint32_t n      = (set == TOY) ? 32 : 1305;
    auto lweparams  = std::make_shared<LWECryptoParams>(n, ringDim, q, Q, qKS, 3.19, 32);
    auto rgswparams = std::make_shared<RingGSWCryptoParams>(ringDim, Q, q, baseG, 23, method, 3.19, UNIFORM_TERNARY,
                                                            ((logQ != 11) && timeOptimization));

    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);

#if defined(BINFHE_DEBUG)
    std::cout << ringDim << " " << Q < < < < " " << n << " " << q << " " << baseG << std::endl;
#endif
}

void BinFHEContext::GenerateBinFHEContext(BINFHE_PARAMSET set, BINFHE_METHOD method, uint32_t num_of_parties) {
    enum { PRIME = 0 };  // value for modKS if you want to use the intermediate prime for modulus for key switching
    constexpr double STD_DEV = 3.19;
    // clang-format off
    const std::unordered_map<BINFHE_PARAMSET, BinFHEContextParams> paramsMap({
        //               numberBits|cyclOrder|latticeParam|  mod|   modKS|  stdDev| baseKS| gadgetBase| baseRK| numAutoKeys| keyDist
        { TOY,               { 27,     1024,          64,  512,   PRIME, STD_DEV,     25,    1 <<  9,  23,     9,  UNIFORM_TERNARY} },
        { MEDIUM,            { 28,     2048,         422, 1024, 1 << 14, STD_DEV, 1 << 7,    1 << 10,  32,    10,  UNIFORM_TERNARY} },
        { STD128_LMKCDEY,    { 28,     2048,         446, 2048, 1 << 13, STD_DEV, 1 << 5,    1 << 10,  32,    10,  GAUSSIAN       } },
        { STD128_AP,         { 27,     2048,         503, 1024, 1 << 14, STD_DEV, 1 << 5,    1 <<  9,  32,    10,  UNIFORM_TERNARY} },
        { STD128,            { 27,     2048,         503, 1024, 1 << 14, STD_DEV, 1 << 5,    1 <<  9,  32,    10,  UNIFORM_TERNARY} },
        { STD192,            { 37,     4096,         805, 1024, 1 << 15, STD_DEV,     32,    1 << 13,  32,    10,  UNIFORM_TERNARY} },
        { STD256,            { 29,     4096,         990, 2048, 1 << 14, STD_DEV, 1 << 7,    1 <<  8,  46,    10,  UNIFORM_TERNARY} },
        { STD128Q,           { 25,     2048,         534, 1024, 1 << 14, STD_DEV,     32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
        { STD128Q_LMKCDEY,   { 27,     2048,         448, 2048, 1 << 13, STD_DEV,     32,    1 <<  9,  32,    10,  GAUSSIAN       } },
        { STD128Q_LMKCDEY_T, { 53,     4096,         524, 4096, 1 << 15, STD_DEV,     32,    1 <<  9,  32,    10,  GAUSSIAN       } },
        { STD192Q,           { 35,     4096,         875, 1024, 1 << 15, STD_DEV,     32,    1 << 12,  32,    10,  UNIFORM_TERNARY} },
        { STD256Q,           { 27,     4096,        1225, 1024, 1 << 16, STD_DEV,     16,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
        { STD128_3,          { 27,     2048,         541, 1024, 1 << 15, STD_DEV,     32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
        { STD128_3_LMKCDEY,  { 28,     2048,         485, 1024, 1 << 15, STD_DEV,     32,    1 << 10,  32,    10,  GAUSSIAN       } },
        { STD128Q_3,         { 50,     4096,         575, 2048, 1 << 15, STD_DEV,     32,    1 << 25,  32,    10,  UNIFORM_TERNARY} },
        { STD128Q_3_LMKCDEY, { 27,     2048,         524, 1024, 1 << 15, STD_DEV,     32,    1 <<  9,  32,    10,  GAUSSIAN       } },
        { STD192Q_3,         { 34,     4096,         922, 2048, 1 << 16, STD_DEV,     16,    1 << 12,  32,    10,  UNIFORM_TERNARY} },
        { STD256Q_3,         { 27,     4096,        1400, 4096, 1 << 16, STD_DEV,     21,    1 <<  6,  32,    10,  UNIFORM_TERNARY} },
        { STD128_4,          { 27,     2048,         541, 2048, 1 << 15, STD_DEV,     32,    1 <<  7,  32,    10,  UNIFORM_TERNARY} },
        { STD128_4_LMKCDEY,  { 28,     2048,         522, 2048, 1 << 15, STD_DEV,     32,    1 << 10,  32,    10,  GAUSSIAN       } },
        { STD128Q_4,         { 50,     4096,         647, 2048, 1 << 16, STD_DEV,     16,    1 << 25,  32,    10,  UNIFORM_TERNARY} },
        { STD128Q_4_LMKCDEY, { 27,     2048,         524, 2048, 1 << 15, STD_DEV,     32,    1 <<  7,  32,    10,  GAUSSIAN       } },
        { STD192Q_4,         { 34,     4096,         980, 2048, 1 << 17, STD_DEV,     16,    1 << 12,  32,    10,  UNIFORM_TERNARY} },
        { STD256Q_4,         { 27,     4096,        1625, 4096, 1 << 21, STD_DEV,     16,    1 <<  6,  32,    10,  UNIFORM_TERNARY} },
        { SIGNED_MOD_TEST,   { 28,     2048,         512, 1024,   PRIME, STD_DEV,     25,    1 <<  7,  23,    10,  UNIFORM_TERNARY} },
    });
    // clang-format on

    auto search = paramsMap.find(set);
    if (paramsMap.end() == search) {
        std::string errMsg("ERROR: Unknown parameter set [" + std::to_string(set) + "] for FHEW.");
        OPENFHE_THROW(errMsg);
    }

    BinFHEContextParams params = search->second;
    // intermediate prime
    NativeInteger Q(LastPrime<NativeInteger>(params.numberBits, params.cyclOrder));

    usint ringDim  = params.cyclOrder / 2;
    auto lweparams = (PRIME == params.modKS) ?
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, Q,
                                                           params.stdDev, params.baseKS, params.keyDist) :
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, params.modKS,
                                                           params.stdDev, params.baseKS, params.keyDist);
    auto rgswparams =
        std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase, params.baseRK, method,
                                              params.stdDev, params.keyDist, false, params.numAutoKeys);

    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
    // TODO: captured with serialize/deserialize?
    m_binfhescheme->set_num_of_parties(num_of_parties);
}

void BinFHEContext::GenerateBinFHEContext(const BinFHEContextParams& params, BINFHE_METHOD method) {
    enum { PRIME = 0 };  // value for modKS if you want to use the intermediate prime for modulus for key switching
    // intermediate prime
    NativeInteger Q(LastPrime<NativeInteger>(params.numberBits, params.cyclOrder));

    usint ringDim = params.cyclOrder / 2;

    auto lweparams = (PRIME == params.modKS) ?
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, Q,
                                                           params.stdDev, params.baseKS, params.keyDist) :
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, params.modKS,
                                                           params.stdDev, params.baseKS, params.keyDist);

    auto rgswparams =
        std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase, params.baseRK, method,
                                              params.stdDev, params.keyDist, false, params.numAutoKeys);

    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

LWEPrivateKey BinFHEContext::KeyGen() const {
    auto& LWEParams = m_params->GetLWEParams();
    if (LWEParams->GetKeyDist() == GAUSSIAN)
        return m_LWEscheme->KeyGenGaussian(LWEParams->Getn(), LWEParams->GetqKS());
    return m_LWEscheme->KeyGen(LWEParams->Getn(), LWEParams->GetqKS());
}

LWEKeyPair BinFHEContext::MultipartyKeyGen(const std::vector<LWEPrivateKey>& privateKeyVec) {
    auto& LWEParams = m_params->GetLWEParams();
    return m_LWEscheme->MultipartyKeyGen(privateKeyVec, LWEParams);
}

void BinFHEContext::MultiPartyKeyGen(ConstLWEPrivateKey LWEsk, const NativePoly zN, const LWEPublicKey publicKey,
                                     LWESwitchingKey prevkskey, bool leadFlag) {
    auto& LWEParams  = m_params->GetLWEParams();
    auto& RGSWParams = m_params->GetRingGSWParams();

    auto temp = RGSWParams->GetBaseG();

    // if (m_BTKey_map.size() != 0) {
    //    m_BTKey = m_BTKey_map[temp];
    // }
    // else {
    m_BTKey           = m_binfhescheme->MultiPartyKeyGen(LWEParams, LWEsk, zN, publicKey, prevkskey, leadFlag);
    m_BTKey_map[temp] = m_BTKey;
    // }
}
LWEPublicKey BinFHEContext::MultipartyPubKeyGen(const LWEPrivateKey skN, const LWEPublicKey publicKey) {
    auto& LWEParams = m_params->GetLWEParams();
    return m_LWEscheme->MultipartyPubKeyGen(skN, publicKey, LWEParams);
}

NativePoly BinFHEContext::RGSWKeygen() {
    return m_binfhescheme->RGSWKeyGen(m_params);
}

LWEPrivateKey BinFHEContext::KeyGenN() const {
    auto& LWEParams = m_params->GetLWEParams();
    if (LWEParams->GetKeyDist() == GAUSSIAN)
        return m_LWEscheme->KeyGenGaussian(LWEParams->GetN(), LWEParams->GetQ());
    return m_LWEscheme->KeyGen(LWEParams->GetN(), LWEParams->GetQ());
}

LWEKeyPair BinFHEContext::KeyGenPair() const {
    auto&& LWEParams = m_params->GetLWEParams();
    return m_LWEscheme->KeyGenPair(LWEParams);
}

LWEPublicKey BinFHEContext::PubKeyGen(ConstLWEPrivateKey& sk) const {
    auto&& LWEParams = m_params->GetLWEParams();
    return m_LWEscheme->PubKeyGen(LWEParams, sk);
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey& sk, LWEPlaintext m, BINFHE_OUTPUT output,
                                     LWEPlaintextModulus p, const NativeInteger& mod) const {
    const auto& LWEParams = m_params->GetLWEParams();

    LWECiphertext ct = (mod == 0) ? m_LWEscheme->Encrypt(LWEParams, sk, m, p, LWEParams->Getq()) :
                                    m_LWEscheme->Encrypt(LWEParams, sk, m, p, mod);

    // BINFHE_OUTPUT is kept as it is for backward compatibility but
    // this logic is obsolete now and commented out
    // if ((output != FRESH) && (p == 4)) {
    //    ct = m_binfhescheme->Bootstrap(m_params, m_BTKey, ct);
    //}

    return ct;
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPublicKey& pk, LWEPlaintext m, BINFHE_OUTPUT output, LWEPlaintextModulus p,
                                     const NativeInteger& mod) const {
    const auto& LWEParams = m_params->GetLWEParams();

    LWECiphertext ct = (mod == 0) ? m_LWEscheme->EncryptN(LWEParams, pk, m, p, LWEParams->GetQ()) :
                                    m_LWEscheme->EncryptN(LWEParams, pk, m, p, mod);

    // Switch from ct of modulus Q and dimension N to smaller q and n
    // This is done by default while calling Encrypt but the output could
    // be set to LARGE_DIM to skip this switching
    if (output == SMALL_DIM) {
        LWECiphertext ct1 = SwitchCTtoqn(m_BTKey.KSkey, ct);
        return ct1;
    }
    return ct;
}

LWECiphertext BinFHEContext::SwitchCTtoqn(ConstLWESwitchingKey& ksk, ConstLWECiphertext& ct) const {
    const auto& LWEParams = m_params->GetLWEParams();
    auto Q                = LWEParams->GetQ();
    auto N                = LWEParams->GetN();

    if ((ct->GetLength() != N) && (ct->GetModulus() != Q)) {
        std::string errMsg("ERROR: Ciphertext dimension and modulus are not large N and Q");
        OPENFHE_THROW(errMsg);
    }

    LWECiphertext ct1 = m_LWEscheme->SwitchCTtoqn(LWEParams, ksk, ct);

    return ct1;
}

void BinFHEContext::Decrypt(ConstLWEPrivateKey& sk, ConstLWECiphertext& ct, LWEPlaintext* result,
                            LWEPlaintextModulus p) const {
    auto&& LWEParams = m_params->GetLWEParams();
    m_LWEscheme->Decrypt(LWEParams, sk, ct, result, p);
}
LWECiphertext BinFHEContext::MultipartyDecryptLead(ConstLWEPrivateKey sk, ConstLWECiphertext ct,
                                                   const LWEPlaintextModulus& p) const {
    auto& LWEParams = m_params->GetLWEParams();
    return m_LWEscheme->MultipartyDecryptLead(LWEParams, sk, ct, p);
}
LWECiphertext BinFHEContext::MultipartyDecryptMain(ConstLWEPrivateKey sk, ConstLWECiphertext ct,
                                                   const LWEPlaintextModulus& p) const {
    auto& LWEParams = m_params->GetLWEParams();
    return m_LWEscheme->MultipartyDecryptMain(LWEParams, sk, ct, p);
}
void BinFHEContext::MultipartyDecryptFusion(const std::vector<LWECiphertext>& partialCiphertextVec,
                                            LWEPlaintext* plaintext, const LWEPlaintextModulus& p) const {
    m_LWEscheme->MultipartyDecryptFusion(partialCiphertextVec, plaintext);
}

LWESwitchingKey BinFHEContext::KeySwitchGen(ConstLWEPrivateKey& sk, ConstLWEPrivateKey& skN) const {
    return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
}

NativePoly BinFHEContext::Generateacrs() {
    auto& RGSWParams = m_params->GetRingGSWParams();
    return m_binfhescheme->Generateacrs(RGSWParams);
}

std::vector<NativePoly> BinFHEContext::GenerateCRS() {
    auto& RGSWParams  = m_params->GetRingGSWParams();
    uint32_t digitsG2 = (RGSWParams->GetDigitsG() - 1) << 1;
    std::vector<NativePoly> acrs(digitsG2);
    for (uint32_t i = 0; i < digitsG2; i++) {
        acrs[i] = Generateacrs();
    }
    return acrs;
}

std::vector<std::vector<NativePoly>> BinFHEContext::GenerateCRSVector() {
    auto& RGSWParams = m_params->GetRingGSWParams();
    uint32_t digitsG = RGSWParams->GetDigitsG() - 1;
    uint32_t w       = RGSWParams->GetNumAutoKeys() + 1;
    std::vector<std::vector<NativePoly>> acrs(w, std::vector<NativePoly>(digitsG));
    for (uint32_t i = 0; i < w; i++) {
        for (uint32_t k = 0; k < digitsG; k++) {
            acrs[i][k] = Generateacrs();
        }
    }
    return acrs;
}

std::vector<std::vector<std::vector<NativePoly>>> BinFHEContext::GenerateCRSMatrix(uint32_t m, uint32_t n) {
    std::vector<std::vector<std::vector<NativePoly>>> acrs(m, std::vector<std::vector<NativePoly>>(n));
    for (uint32_t i = 0; i < m; i++) {
        for (uint32_t k = 0; k < n; k++) {
            acrs[i][k] = GenerateCRS();
        }
    }
    return acrs;
}

NativePoly BinFHEContext::RGSWKeyGen() const {
    return m_binfhescheme->RGSWKeyGen(m_params);
}
// RingGSWCiphertext
RingGSWEvalKey BinFHEContext::RGSWEncrypt(NativePoly acrs, const NativePoly& skNTT, const LWEPlaintext& m,
                                          bool leadFlag) const {
    auto& RGSWParams = m_params->GetRingGSWParams();
    return m_binfhescheme->RGSWEncrypt(RGSWParams, acrs, skNTT, m, leadFlag);
}

// RingGSWCiphertext
RingGSWEvalKey BinFHEContext::RGSWEncrypt(const std::vector<NativePoly>& acrs, const NativePoly& skNTT,
                                          const LWEPlaintext& m, bool leadFlag) const {
    auto& RGSWParams = m_params->GetRingGSWParams();
    return m_binfhescheme->RGSWEncrypt(RGSWParams, acrs, skNTT, m, leadFlag);
}

// RingGSWCiphertext
RingGSWEvalKey BinFHEContext::RGSWEvalAdd(RingGSWEvalKey a, RingGSWEvalKey b) {
    return m_binfhescheme->RGSWEvalAdd(a, b);
}

RingGSWACCKey BinFHEContext::RGSWClone(RingGSWEvalKey a, uint32_t n) {
    // for lmkcdey - 2nd index 0 for btkey, 2nd index 1 for auto key
    RingGSWACCKey rgswe1 = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);
    for (size_t j = 0; j < 2; j++) {
        for (size_t i = 0; i < n; i++) {
            (*rgswe1)[0][j][i] = a;
        }
    }
    return rgswe1;
}

RingGSWEvalKey BinFHEContext::RGSWEvalMultAdd(RingGSWEvalKey a, RingGSWEvalKey b, int32_t si) {
    return m_binfhescheme->RGSWEvalMultAdd(m_params->GetRingGSWParams(), a, b, si);
}

LWEPlaintext BinFHEContext::RGSWDecrypt(RingGSWEvalKey ct, const NativePoly& skNTT) const {
    auto& RGSWParams = m_params->GetRingGSWParams();
    return m_binfhescheme->RGSWDecrypt(RGSWParams, ct, skNTT);
}

RingGSWEvalKey BinFHEContext::KeyGenAuto(const NativePoly& skNTT, LWEPlaintext k) const {
    return m_binfhescheme->KeyGenAuto(m_params, skNTT, k);
}

RingGSWEvalKey BinFHEContext::MultiPartyKeyGenAuto(const RingGSWEvalKey prevautokey, const NativePoly& skNTT,
                                                   const LWEPlaintext& k, std::vector<NativePoly> acrsauto,
                                                   bool leadFlag) const {
    return m_binfhescheme->MultiPartyKeyGenAuto(m_params, prevautokey, skNTT, k, acrsauto, leadFlag);
}

void BinFHEContext::Automorphism(const NativeInteger& a, ConstRingGSWEvalKey& ak, RLWECiphertext& acc) const {
    m_binfhescheme->Automorphism(m_params, a, ak, acc);
}

void BinFHEContext::BTKeyGen(ConstLWEPrivateKey& sk, KEYGEN_MODE keygenMode) {
    auto& RGSWParams = m_params->GetRingGSWParams();

    auto temp = RGSWParams->GetBaseG();

    if (m_timeOptimization) {
        auto gpowermap = RGSWParams->GetGPowerMap();
        for (std::map<uint32_t, std::vector<NativeInteger>>::iterator it = gpowermap.begin(); it != gpowermap.end();
             ++it) {
            RGSWParams->Change_BaseG(it->first);
            m_BTKey_map[it->first] = m_binfhescheme->KeyGen(m_params, sk, keygenMode);
        }
        RGSWParams->Change_BaseG(temp);
    }

    if (m_BTKey_map.size() != 0) {
        m_BTKey = m_BTKey_map[temp];
    }
    else {
        m_BTKey           = m_binfhescheme->KeyGen(m_params, sk, keygenMode);
        m_BTKey_map[temp] = m_BTKey;
    }
}

void BinFHEContext::BTKeyGenTest(ConstLWEPrivateKey sk, NativePoly skNPoly, NativePoly acrs, LWESwitchingKey kskey,
                                 KEYGEN_MODE keygenMode) {
    auto& RGSWParams = m_params->GetRingGSWParams();

    auto temp = RGSWParams->GetBaseG();

    m_BTKey           = m_binfhescheme->KeyGenTest(m_params, sk, skNPoly, acrs, kskey, keygenMode);
    m_BTKey_map[temp] = m_BTKey;
}

void BinFHEContext::MultipartyBTKeyGen(ConstLWEPrivateKey sk, RingGSWACCKey prevbtkey, NativePoly zkey,
                                       std::vector<std::vector<NativePoly>> acrsauto,
                                       std::vector<RingGSWEvalKey> rgswenc0, LWESwitchingKey prevkskey, bool leadFlag) {
    auto& RGSWParams = m_params->GetRingGSWParams();
    auto temp        = RGSWParams->GetBaseG();

    // if (m_BTKey_map.size() != 0) {
    //    m_BTKey = m_BTKey_map[temp];
    // }
    // else {
    m_BTKey           = m_binfhescheme->MultipartyBTKeyGen(m_params, sk, prevbtkey, zkey, acrsauto, rgswenc0, prevkskey,
                                                           m_binfhescheme->get_num_of_parties(), leadFlag);
    m_BTKey_map[temp] = m_BTKey;
    // }
    return;
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, ConstLWECiphertext& ct1, ConstLWECiphertext& ct2,
                                         bool extended) const {
    return m_binfhescheme->EvalBinGate(m_params, gate, m_BTKey, ct1, ct2, (m_extended || extended));
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, const std::vector<LWECiphertext>& ctvector) const {
    return m_binfhescheme->EvalBinGate(m_params, gate, m_BTKey, ctvector);
}

LWECiphertext BinFHEContext::Bootstrap(ConstLWECiphertext& ct) const {
    return m_binfhescheme->Bootstrap(m_params, m_BTKey, ct);
}

LWECiphertext BinFHEContext::EvalNOT(ConstLWECiphertext& ct) const {
    return m_binfhescheme->EvalNOT(m_params, ct);
}

LWECiphertext BinFHEContext::EvalConstant(bool value) const {
    return m_LWEscheme->NoiselessEmbedding(m_params->GetLWEParams(), value);
}

LWECiphertext BinFHEContext::EvalFunc(ConstLWECiphertext& ct, const std::vector<NativeInteger>& LUT) const {
    return m_binfhescheme->EvalFunc(m_params, m_BTKey, ct, LUT, GetBeta());
}

LWECiphertext BinFHEContext::EvalFloor(ConstLWECiphertext& ct, uint32_t roundbits) const {
    //    auto q = m_params->GetLWEParams()->Getq().ConvertToInt();
    //    if (roundbits != 0) {
    //        NativeInteger newp = this->GetMaxPlaintextSpace();
    //        SetQ(q / newp * (1 << roundbits));
    //    }
    //    SetQ(q);
    //    return res;
    return m_binfhescheme->EvalFloor(m_params, m_BTKey, ct, GetBeta(), roundbits);
}

LWECiphertext BinFHEContext::EvalSign(ConstLWECiphertext& ct, bool schemeSwitch) {
    const auto& params = std::make_shared<BinFHECryptoParams>(*m_params);
    return m_binfhescheme->EvalSign(params, m_BTKey_map, ct, GetBeta(), schemeSwitch);
}

std::vector<LWECiphertext> BinFHEContext::EvalDecomp(ConstLWECiphertext& ct) {
    return m_binfhescheme->EvalDecomp(m_params, m_BTKey_map, ct, GetBeta());
}

std::vector<NativeInteger> BinFHEContext::GenerateLUTviaFunction(NativeInteger (*f)(NativeInteger m, NativeInteger p),
                                                                 NativeInteger p) {
    if (ceil(log2(p.ConvertToInt())) != floor(log2(p.ConvertToInt()))) {
        std::string errMsg("ERROR: Only support plaintext space to be power-of-two.");
        OPENFHE_THROW(errMsg);
    }

    NativeInteger q        = GetParams()->GetLWEParams()->Getq();
    NativeInteger interval = q / p;
    NativeInteger outerval = interval;
    usint vecSize          = q.ConvertToInt();
    std::vector<NativeInteger> vec(vecSize);
    for (size_t i = 0; i < vecSize; ++i) {
        auto temp = f(NativeInteger(i) / interval, p);
        if (temp >= p) {
            std::string errMsg("ERROR: input function should output in Z_{p_output}.");
            OPENFHE_THROW(errMsg);
        }
        vec[i] = temp * outerval;
    }

    return vec;
}

}  // namespace lbcrypto
