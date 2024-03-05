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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#define PROFILE

#include "scheme/ckksrns/ckksrns-multiparty.h"

#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "ciphertext.h"
#include "cryptocontext.h"

#include <memory>

namespace lbcrypto {

// {Q} = {q_1,...,q_l}, original RNS basis
// {P} = {p_1,...,p_k}, extended RNS basis
struct RNSExtensionTables {
    std::shared_ptr<ILDCRTParams<BigInteger>> paramsQP;  // the whole RNS basis
    std::shared_ptr<ILDCRTParams<BigInteger>> paramsP;   // only the new RNS basis
    std::vector<NativeInteger> QHatInvModq;              // done
    std::vector<NativeInteger> QHatInvModqPrecon;        // done
    std::vector<std::vector<NativeInteger>> QHatModp;    // done
    std::vector<std::vector<NativeInteger>> alphaQModp;  // done
    std::vector<DoubleNativeInt> modpBarrettMu;          // done
    std::vector<double> qInv;                            // done
    Format resultFormat;
};

DecryptResult MultipartyCKKSRNS::MultipartyDecryptFusion(const std::vector<Ciphertext<DCRTPoly>>& ciphertextVec,
                                                         Poly* plaintext) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertextVec[0]->GetCryptoParameters());
    const std::vector<DCRTPoly>& cv0 = ciphertextVec[0]->GetElements();

    DCRTPoly b = cv0[0];
    for (size_t i = 1; i < ciphertextVec.size(); i++) {
        const std::vector<DCRTPoly>& cvi = ciphertextVec[i]->GetElements();
        b += cvi[0];
    }
    b.SetFormat(Format::COEFFICIENT);

    *plaintext = b.CRTInterpolate();

    //  size_t sizeQl = b.GetParams()->GetParams().size();
    //  if (sizeQl > 1) {
    //    *plaintext = b.CRTInterpolate();
    //  } else if (sizeQl == 1) {
    //    *plaintext = Poly(b.GetElementAtIndex(0), Format::COEFFICIENT);
    //  } else {
    //    OPENFHE_THROW(
    //        math_error,
    //        "Decryption failure: No towers left; consider increasing the depth.");
    //  }

    return DecryptResult(plaintext->GetLength());
}

DecryptResult MultipartyCKKSRNS::MultipartyDecryptFusion(const std::vector<Ciphertext<DCRTPoly>>& ciphertextVec,
                                                         NativePoly* plaintext) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertextVec[0]->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv0 = ciphertextVec[0]->GetElements();

    DCRTPoly b = cv0[0];
    for (size_t i = 1; i < ciphertextVec.size(); i++) {
        const std::vector<DCRTPoly>& cvi = ciphertextVec[i]->GetElements();
        b += cvi[0];
    }
    b.SetFormat(Format::COEFFICIENT);

    //  const size_t sizeQl = b.GetParams()->GetParams().size();
    //  if (sizeQl == 1)
    //    *plaintext = b.GetElementAtIndex(0);
    //  else
    //    OPENFHE_THROW(
    //        math_error,
    //        "Decryption failure: No towers left; consider increasing the depth.");

    *plaintext = b.GetElementAtIndex(0);

    return DecryptResult(plaintext->GetLength());
}

Ciphertext<DCRTPoly> MultipartyCKKSRNS::IntMPBootAdjustScale(ConstCiphertext<DCRTPoly> ciphertext) const {
    if (ciphertext->GetElements().size() == 0) {
        std::string msg = "IntMPBootAdjustScale: no polynomials in the input ciphertext.";
        OPENFHE_THROW(openfhe_error, msg);
    }

    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    auto compressionLevel = cryptoParams->GetMPIntBootCiphertextCompressionLevel();

    // Compress ctxt and reduce it to numPrimesToKeep towers
    // 1 is for the message itself (assuming 1 tower (60-bit) for msg)
    size_t scalingFactorBits = cc->GetEncodingParams()->GetPlaintextModulus();
    size_t firstModulusSize =
        std::ceil(std::log2(ciphertext->GetElements()[0].GetAllElements()[0].GetParams()->GetModulus().ConvertToInt()));
    size_t numTowersToKeep = (scalingFactorBits / firstModulusSize + 1) + compressionLevel;

    if (ciphertext->GetElements()[0].GetNumOfElements() < numTowersToKeep) {
        std::string msg = std::string(__func__) +": not enough towers in the input polynomial.";
        OPENFHE_THROW(config_error, msg);
    }
    if (cryptoParams->GetScalingTechnique() == ScalingTechnique::FLEXIBLEAUTO ||
        cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {

        auto ciphertextAdjusted = cc->Compress(ciphertext, numTowersToKeep + 1);

        uint32_t lvl       = cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO ? 0 : 1;
        double targetSF    = cryptoParams->GetScalingFactorReal(lvl);
        double sourceSF    = ciphertextAdjusted->GetScalingFactor();
        uint32_t numTowers = ciphertextAdjusted->GetElements()[0].GetNumOfElements();
        double modToDrop = cryptoParams->GetElementParams()->GetParams()[numTowers - 1]->GetModulus().ConvertToDouble();
        double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF);

        ciphertextAdjusted = cc->EvalMult(ciphertextAdjusted, adjustmentFactor);
        cc->GetScheme()->ModReduceInternalInPlace(ciphertextAdjusted, 1);
        ciphertextAdjusted->SetScalingFactor(targetSF);
        return ciphertextAdjusted;
    }
    else {
        return cc->Compress(ciphertext, numTowersToKeep);
    }
}

Ciphertext<DCRTPoly> MultipartyCKKSRNS::IntMPBootRandomElementGen(std::shared_ptr<CryptoParametersCKKSRNS> params,
                                                                  const PublicKey<DCRTPoly> publicKey) const {
    auto ildcrtparams = params->GetElementParams();
    typename DCRTPoly::DugType dug;
    DCRTPoly crp(dug, ildcrtparams);
    crp.SetFormat(Format::EVALUATION);

    Ciphertext<DCRTPoly> outCtxt(std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

    outCtxt->SetElements({std::move(crp)});
    return outCtxt;
}

// Subroutines for Interactive Multi-Party Bootstrapping
// Calculating RNS parameters
void PrecomputeRNSExtensionTables(CryptoContext<DCRTPoly>& cc, usint from, usint to, RNSExtensionTables& rnsExtTables) {
    std::vector<NativeInteger> moduliQ;
    std::vector<NativeInteger> rootsQ;
    std::vector<NativeInteger> moduliP;
    std::vector<NativeInteger> rootsP;

    for (size_t i = 0; i < from; i++) {
        moduliQ.push_back(cc->GetCryptoParameters()->GetElementParams()->GetParams()[i]->GetModulus());
        rootsQ.push_back(cc->GetCryptoParameters()->GetElementParams()->GetParams()[i]->GetRootOfUnity());
    }

    for (size_t i = from; i < to; i++) {
        moduliP.push_back(cc->GetCryptoParameters()->GetElementParams()->GetParams()[i]->GetModulus());
        rootsP.push_back(cc->GetCryptoParameters()->GetElementParams()->GetParams()[i]->GetRootOfUnity());
    }

    size_t sizeQ = moduliQ.size();
    size_t sizeP = moduliP.size();
    BigInteger modulusQ(1);
    for (auto& it : moduliQ)
        modulusQ *= it;

    std::vector<NativeInteger> moduliQP(sizeQ + sizeP);
    std::vector<NativeInteger> rootsQP(sizeQ + sizeP);

    // populate moduli for CRT basis Q
    for (size_t i = 0; i < sizeQ; i++) {
        moduliQP[i] = moduliQ[i];
        rootsQP[i]  = rootsQ[i];
    }

    // populate moduli for CRT basis P
    for (size_t j = 0; j < sizeP; j++) {
        moduliQP[sizeQ + j] = moduliP[j];
        rootsQP[sizeQ + j]  = rootsP[j];
    }

    usint ringDim         = cc->GetCryptoParameters()->GetElementParams()->GetRingDimension();
    rnsExtTables.paramsP  = std::make_shared<ILDCRTParams<BigInteger>>(2 * ringDim, moduliP, rootsP);
    rnsExtTables.paramsQP = std::make_shared<ILDCRTParams<BigInteger>>(2 * ringDim, moduliQP, rootsQP);

    rnsExtTables.QHatInvModq.resize(sizeQ);
    rnsExtTables.QHatInvModqPrecon.resize(sizeQ);
    for (usint i = 0; i < sizeQ; i++) {
        BigInteger qi(moduliQ[i].ConvertToInt());
        BigInteger QHati                  = modulusQ / qi;
        rnsExtTables.QHatInvModq[i]       = QHati.ModInverse(qi).Mod(qi).ConvertToInt();
        rnsExtTables.QHatInvModqPrecon[i] = rnsExtTables.QHatInvModq[i].PrepModMulConst(qi.ConvertToInt());
    }

    // compute the [Q/q_i]_{p_j}
    // used for homomorphic multiplication
    rnsExtTables.QHatModp.resize(sizeP);
    for (usint j = 0; j < sizeP; j++) {
        BigInteger pj(moduliP[j].ConvertToInt());
        for (usint i = 0; i < sizeQ; i++) {
            BigInteger qi(moduliQ[i].ConvertToInt());
            BigInteger QHati = modulusQ / qi;
            rnsExtTables.QHatModp[j].push_back(QHati.Mod(pj).ConvertToInt());
        }
    }

    // compute the [\alpha*Q]p_j for 0 <= alpha <= sizeQ
    // used for homomorphic multiplication
    rnsExtTables.alphaQModp.resize(sizeQ + 1);
    for (usint j = 0; j < sizeP; j++) {
        BigInteger pj(moduliP[j].ConvertToInt());
        NativeInteger QModpj = modulusQ.Mod(pj).ConvertToInt();
        for (usint i = 0; i < sizeQ + 1; i++) {
            rnsExtTables.alphaQModp[i].push_back(QModpj.ModMul(NativeInteger(i), moduliP[j]));
        }
    }

    // Precomputations for Barrett modulo reduction
    const BigInteger BarrettBase128Bit("340282366920938463463374607431768211456");  // 2^128
    const BigInteger TwoPower64("18446744073709551616");                            // 2^64
    rnsExtTables.modpBarrettMu.resize(sizeP);
    for (uint32_t j = 0; j < moduliP.size(); j++) {
        BigInteger mu = BarrettBase128Bit / BigInteger(moduliP[j]);
        uint64_t val[2];
        val[0] = (mu % TwoPower64).ConvertToInt();
        val[1] = mu.RShift(64).ConvertToInt();

        memcpy(&rnsExtTables.modpBarrettMu[j], val, sizeof(DoubleNativeInt));
    }

    rnsExtTables.qInv.resize(sizeQ);
    for (size_t i = 0; i < sizeQ; i++) {
        rnsExtTables.qInv[i] = 1. / static_cast<double>(moduliQ[i].ConvertToInt());
    }
}

// Utility function to compute noisy multiplication ( sk * poly + noise )
// noise will not be added if IsZeroNoise is set to true (as in computing h_0,i)
DCRTPoly ComputeNoisyMult(CryptoContext<DCRTPoly>& cc, const DCRTPoly& sk, const DCRTPoly& poly, bool IsZeroNoise) {
    if (sk.GetNumOfElements() != poly.GetNumOfElements()) {
        std::string errMsg = "ERROR: Number of towers in input polys does not match!";
        OPENFHE_THROW(config_error, errMsg);
    }

    DCRTPoly res = sk * poly;
    if (false == IsZeroNoise) {
        const auto cryptoParams      = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const DCRTPoly::DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
        auto paramsq                 = poly.GetParams();

        DCRTPoly e(dgg, paramsq, Format::EVALUATION);
        res = res + e;
    }

    return res;
}

// Generate random mask
DCRTPoly GenerateMi(const DCRTPoly& c1, uint32_t maskBoundNumTowers) {
    auto c1Copy = c1;

    // drop twoers until we reach maskBoundNumTowers
    c1Copy.DropLastElements(c1Copy.GetAllElements().size() - maskBoundNumTowers);   

    auto& ildcrtparams = c1Copy.GetParams();
    typename DCRTPoly::DugType dug;
    DCRTPoly Mi(dug, ildcrtparams, Format::EVALUATION);

    return Mi;
}

// Compute h_{0,i}
DCRTPoly GenerateMaskedDecryptionShare(CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly> privateKey,
                                       const DCRTPoly& c1, DCRTPoly& Mi, uint32_t compressionLevel) {
    DCRTPoly sk = privateKey->GetPrivateElement();
    // reduce sk's numeTowers to c1's numTowers
    sk.DropLastElements(sk.GetAllElements().size() - c1.GetAllElements().size());

    DCRTPoly maskedDecryptionShare = ComputeNoisyMult(cc, sk, c1, true);

    DCRTPoly MiCopy = Mi;

    // Init RNS parameters - we generate these params online as of now - should be cheap
    // Extending Mi parameters:
    RNSExtensionTables MiForDecryptionShareRNSExtTables;  // extending Mi from R_t to R_q
    PrecomputeRNSExtensionTables(cc, compressionLevel, c1.GetAllElements().size(), MiForDecryptionShareRNSExtTables);

    MiCopy.ExpandCRTBasis(MiForDecryptionShareRNSExtTables.paramsQP, MiForDecryptionShareRNSExtTables.paramsP,
                          MiForDecryptionShareRNSExtTables.QHatInvModq,
                          MiForDecryptionShareRNSExtTables.QHatInvModqPrecon, MiForDecryptionShareRNSExtTables.QHatModp,
                          MiForDecryptionShareRNSExtTables.alphaQModp, MiForDecryptionShareRNSExtTables.modpBarrettMu,
                          MiForDecryptionShareRNSExtTables.qInv, EVALUATION);

    maskedDecryptionShare = maskedDecryptionShare - MiCopy;

    return maskedDecryptionShare;
}

// Compute h_{1,i}
DCRTPoly GenerateReEncryptionShare(CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly> privateKey,
                                   ConstCiphertext<DCRTPoly> a, DCRTPoly& Mi, uint32_t compressionLevel) {
    DCRTPoly sk                = privateKey->GetPrivateElement();
    auto negsk                 = sk.Negate();
    DCRTPoly reEncryptionShare = ComputeNoisyMult(cc, negsk, a->GetElements()[0], false);

    DCRTPoly MiCopy = Mi;
    // Init RNS parameters - we generate these params online as of now - should be cheap
    // Extending Mi parameters:
    RNSExtensionTables MiForReEncryptionShareRNSExtTables;  // extending Mi from R_t to R_Q
    PrecomputeRNSExtensionTables(cc, compressionLevel, a->GetElements()[0].GetAllElements().size(),
                                 MiForReEncryptionShareRNSExtTables);

    MiCopy.ExpandCRTBasis(
        MiForReEncryptionShareRNSExtTables.paramsQP, MiForReEncryptionShareRNSExtTables.paramsP,
        MiForReEncryptionShareRNSExtTables.QHatInvModq, MiForReEncryptionShareRNSExtTables.QHatInvModqPrecon,
        MiForReEncryptionShareRNSExtTables.QHatModp, MiForReEncryptionShareRNSExtTables.alphaQModp,
        MiForReEncryptionShareRNSExtTables.modpBarrettMu, MiForReEncryptionShareRNSExtTables.qInv, EVALUATION);
    reEncryptionShare = reEncryptionShare + MiCopy;

    return reEncryptionShare;
}

std::vector<Ciphertext<DCRTPoly>> MultipartyCKKSRNS::IntMPBootDecrypt(const PrivateKey<DCRTPoly> privateKey,
                                                                      ConstCiphertext<DCRTPoly> ciphertext,
                                                                      ConstCiphertext<DCRTPoly> a) const {
    // Generate maskedDecryptionShares: secretShare M_i and publicShare: s_i*c_1+e_{0,i} to compute h_{0,i}
    // Generate secretShare M_i \in R_{q*2^{\lambda}} where lambda is the security level
    // Calculate publicShare s_i*c_1 + e_{0,i} in R_{q*2^{\lambda}}
    // Calculate h_{0,i} = publicShare - secretShare

    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    auto compressionLevel = cryptoParams->GetMPIntBootCiphertextCompressionLevel();

    auto& c1    = ciphertext->GetElements()[0];      // input ctxt must only include one element which is c1
    DCRTPoly Mi = GenerateMi(c1, compressionLevel);  // Mi is in NTT domain

    // Encryption to Share protocol to compute: h_{0,i}
    DCRTPoly mdsp = GenerateMaskedDecryptionShare(cc, privateKey, c1, Mi, compressionLevel);
    Ciphertext<DCRTPoly> maskedDecryptionShare(std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));
    maskedDecryptionShare->SetElements({std::move(mdsp)});

    // Generate reEncryptionShares: secretShare M_i (no need to recompute, use M_i from above)
    // and publicShare: -s_i*a + e_{1,i} in R_{Q}
    // Get screteShare M_i
    // Calculate publicShare: -s_i*a + e_{1,i}
    // // Calculate h_{1,i} = publicShare + secretShare

    // Shares to Encryption protocol to compute h_{1,i}
    DCRTPoly rsp = GenerateReEncryptionShare(cc, privateKey, a, Mi, compressionLevel);
    Ciphertext<DCRTPoly> reEncryptionShare(std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));
    reEncryptionShare->SetElements({std::move(rsp)});

    std::vector<Ciphertext<DCRTPoly>> result = {maskedDecryptionShare, reEncryptionShare};

    return result;
}

std::vector<Ciphertext<DCRTPoly>> MultipartyCKKSRNS::IntMPBootAdd(
    std::vector<std::vector<Ciphertext<DCRTPoly>>>& sharesPairVec) const {
    if (sharesPairVec.size() == 0) {
        std::string msg = "IntMPBootAdd: no polynomials in input share(s).";
        OPENFHE_THROW(openfhe_error, msg);
    }

    std::vector<Ciphertext<DCRTPoly>> result = sharesPairVec[0];
    for (size_t i = 1; i < sharesPairVec.size(); i++) {
        // h_0 = h_0,0 + h_0,i
        result[0]->GetElements()[0] = result[0]->GetElements()[0] + sharesPairVec[i][0]->GetElements()[0];
        // h_1 = h_1,0 + h_1,i
        result[1]->GetElements()[0] = result[1]->GetElements()[0] + sharesPairVec[i][1]->GetElements()[0];
    }

    return result;
}

Ciphertext<DCRTPoly> MultipartyCKKSRNS::IntMPBootEncrypt(const PublicKey<DCRTPoly> publicKey,
                                                         const std::vector<Ciphertext<DCRTPoly>>& sharesPair,
                                                         ConstCiphertext<DCRTPoly> a,
                                                         ConstCiphertext<DCRTPoly> ciphertext) const {
    if (ciphertext->GetElements().size() == 0) {
        std::string msg = "IntMPBootEncrypt: no polynomials in the input ciphertext.";
        OPENFHE_THROW(openfhe_error, msg);
    }

    auto cc = ciphertext->GetCryptoContext();

    DCRTPoly c0Prime = ciphertext->GetElements()[0] + sharesPair[0]->GetElements()[0];
    // Init RNS parameters - we generate these params online as of now - should be cheap
    // Extending Mi parameters:
    RNSExtensionTables C0ForReEncryptRNSExtTables;  // extending c0 from R_q to R_Q
    PrecomputeRNSExtensionTables(cc, c0Prime.GetAllElements().size(), a->GetElements()[0].GetAllElements().size(),
                                 C0ForReEncryptRNSExtTables);

    c0Prime.ExpandCRTBasis(C0ForReEncryptRNSExtTables.paramsQP, C0ForReEncryptRNSExtTables.paramsP,
                           C0ForReEncryptRNSExtTables.QHatInvModq, C0ForReEncryptRNSExtTables.QHatInvModqPrecon,
                           C0ForReEncryptRNSExtTables.QHatModp, C0ForReEncryptRNSExtTables.alphaQModp,
                           C0ForReEncryptRNSExtTables.modpBarrettMu, C0ForReEncryptRNSExtTables.qInv, EVALUATION);

    c0Prime = c0Prime + sharesPair[1]->GetElements()[0];

    Ciphertext<DCRTPoly> outCtxt(std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

    outCtxt->SetElements({std::move(c0Prime), std::move(a->GetElements()[0])});

    // Ciphertext depth, level, and scaling factor should be
    // equal to that of the plaintext. However, Encrypt does
    // not take Plaintext as input (only DCRTPoly), so we
    // don't have access to these here and we copy them
    // from the input ciphertext.

    outCtxt->SetEncodingType(ciphertext->GetEncodingType());
    outCtxt->SetScalingFactor(ciphertext->GetScalingFactor());
    outCtxt->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg());
    outCtxt->SetLevel(0);
    outCtxt->SetMetadataMap(ciphertext->GetMetadataMap());
    outCtxt->SetSlots(ciphertext->GetSlots());

    return outCtxt;
}

}  // namespace lbcrypto
