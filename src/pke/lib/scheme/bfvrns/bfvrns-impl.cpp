// @file bfvrns-impl.cpp - template instantiations and methods for the BFVrns
// scheme
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "bfvrns.cpp"
#include "cryptocontext.h"

namespace lbcrypto {

#define NOPOLY                                                                \
  std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead."; \
  PALISADE_THROW(not_implemented_error, errMsg);

#define NONATIVEPOLY                                               \
  std::string errMsg =                                             \
      "BFVrns does not support NativePoly. Use DCRTPoly instead."; \
  PALISADE_THROW(not_implemented_error, errMsg);

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns() {
  NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns() {
  NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(
    const LPCryptoParametersBFVrns &rhs) {
  NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(
    const LPCryptoParametersBFVrns &rhs) {
  NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(
    shared_ptr<ParmType> params, const PlaintextModulus &plaintextModulus,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth) {
  NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(
    shared_ptr<ParmType> params, const PlaintextModulus &plaintextModulus,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth) {
  NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth) {
  NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth) {
  NONATIVEPOLY
}

// Parameter generation for BFV-RNS
template <>
bool LPCryptoParametersBFVrns<Poly>::PrecomputeCRTTables() {
  NOPOLY
}

template <>
bool LPCryptoParametersBFVrns<NativePoly>::PrecomputeCRTTables() {
  NONATIVEPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrns<Poly>::LPPublicKeyEncryptionSchemeBFVrns() {
  NOPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrns<
    NativePoly>::LPPublicKeyEncryptionSchemeBFVrns() {
  NONATIVEPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrns<Poly>::ParamsGen(
    shared_ptr<LPCryptoParameters<Poly>> cryptoParams, int32_t evalAddCount,
    int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits,
    uint32_t n) const {
  NOPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrns<NativePoly>::ParamsGen(
    shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams,
    int32_t evalAddCount, int32_t evalMultCount, int32_t keySwitchCount,
    size_t dcrtBits, uint32_t n) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrns<Poly>::Encrypt(
    const LPPublicKey<Poly> publicKey, Poly ptxt) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrns<NativePoly>::Encrypt(
    const LPPublicKey<NativePoly> publicKey, NativePoly ptxt) const {
  NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmBFVrns<Poly>::Decrypt(
    const LPPrivateKey<Poly> privateKey, ConstCiphertext<Poly> ciphertext,
    NativePoly *plaintext) const {
  NOPOLY
}

template <>
DecryptResult LPAlgorithmBFVrns<NativePoly>::Decrypt(
    const LPPrivateKey<NativePoly> privateKey,
    ConstCiphertext<NativePoly> ciphertext, NativePoly *plaintext) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrns<Poly>::Encrypt(
    const LPPrivateKey<Poly> privateKey, Poly ptxt) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrns<NativePoly>::Encrypt(
    const LPPrivateKey<NativePoly> privateKey, NativePoly ptxt) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalMult(
    ConstCiphertext<Poly> ciphertext1,
    ConstCiphertext<Poly> ciphertext2) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalMult(
    ConstCiphertext<NativePoly> ciphertext1,
    ConstCiphertext<NativePoly> ciphertext2) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalAdd(ConstCiphertext<Poly> ct,
                                                     ConstPlaintext pt) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalAdd(
    ConstCiphertext<NativePoly> ct, ConstPlaintext pt) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalSub(ConstCiphertext<Poly> ct,
                                                     ConstPlaintext pt) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalSub(
    ConstCiphertext<NativePoly> ct, ConstPlaintext pt) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBFVrns<Poly>::KeySwitchGen(
    const LPPrivateKey<Poly> originalPrivateKey,
    const LPPrivateKey<Poly> newPrivateKey) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::KeySwitchGen(
    const LPPrivateKey<NativePoly> originalPrivateKey,
    const LPPrivateKey<NativePoly> newPrivateKey) const {
  NONATIVEPOLY
}

template <>
void LPAlgorithmSHEBFVrns<Poly>::KeySwitchInPlace(
    const LPEvalKey<Poly> keySwitchHint,
    Ciphertext<Poly>& cipherText) const {
  NOPOLY
}

template <>
void LPAlgorithmSHEBFVrns<NativePoly>::KeySwitchInPlace(
    const LPEvalKey<NativePoly> keySwitchHint,
    Ciphertext<NativePoly>& cipherText) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalMultAndRelinearize(
    ConstCiphertext<Poly> ct1, ConstCiphertext<Poly> ct,
    const vector<LPEvalKey<Poly>> &ek) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalMultAndRelinearize(
    ConstCiphertext<NativePoly> ct1, ConstCiphertext<NativePoly> ct,
    const vector<LPEvalKey<NativePoly>> &ek) const {
  NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrns<Poly>::MultipartyDecryptFusion(
    const vector<Ciphertext<Poly>> &ciphertextVec,
    NativePoly *plaintext) const {
  NOPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrns<NativePoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<NativePoly>> &ciphertextVec,
    NativePoly *plaintext) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<Poly> LPAlgorithmMultipartyBFVrns<Poly>::MultiKeySwitchGen(
    const LPPrivateKey<Poly> originalPrivateKey,
    const LPPrivateKey<Poly> newPrivateKey, const LPEvalKey<Poly> ek) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly>
LPAlgorithmMultipartyBFVrns<NativePoly>::MultiKeySwitchGen(
    const LPPrivateKey<NativePoly> originalPrivateKey,
    const LPPrivateKey<NativePoly> newPrivateKey,
    const LPEvalKey<NativePoly> ek) const {
  NONATIVEPOLY
}

template class LPCryptoParametersBFVrns<Poly>;
template class LPPublicKeyEncryptionSchemeBFVrns<Poly>;
template class LPAlgorithmBFVrns<Poly>;
template class LPAlgorithmPREBFVrns<Poly>;
template class LPAlgorithmSHEBFVrns<Poly>;
template class LPAlgorithmMultipartyBFVrns<Poly>;
template class LPAlgorithmParamsGenBFVrns<Poly>;

template class LPCryptoParametersBFVrns<NativePoly>;
template class LPPublicKeyEncryptionSchemeBFVrns<NativePoly>;
template class LPAlgorithmBFVrns<NativePoly>;
template class LPAlgorithmPREBFVrns<NativePoly>;
template class LPAlgorithmSHEBFVrns<NativePoly>;
template class LPAlgorithmMultipartyBFVrns<NativePoly>;
template class LPAlgorithmParamsGenBFVrns<NativePoly>;

#undef NOPOLY
#undef NONATIVEPOLY

// Precomputation of CRT tables encryption, decryption, and homomorphic
// multiplication
template <>
bool LPCryptoParametersBFVrns<DCRTPoly>::PrecomputeCRTTables() {
  // read values for the CRT basis

  size_t sizeQ = GetElementParams()->GetParams().size();
  size_t ringDim = GetElementParams()->GetRingDimension();

  vector<NativeInteger> moduliQ(sizeQ);
  vector<NativeInteger> rootsQ(sizeQ);
  for (size_t i = 0; i < sizeQ; i++) {
    moduliQ[i] = GetElementParams()->GetParams()[i]->GetModulus();
    rootsQ[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
  }

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsQ, 2 * ringDim,
                                                         moduliQ);

  // computes the auxiliary CRT basis {P} = {p_1,p_2,...,p_k}
  // used in homomorphic multiplication

  size_t sizeP = sizeQ + 1;

  vector<NativeInteger> moduliP(sizeP);
  vector<NativeInteger> rootsP(sizeP);

  moduliP[0] = PreviousPrime<NativeInteger>(moduliQ[sizeQ - 1], 2 * ringDim);
  rootsP[0] = RootOfUnity<NativeInteger>(2 * ringDim, moduliP[0]);

  for (size_t j = 1; j < sizeP; j++) {
    moduliP[j] = PreviousPrime<NativeInteger>(moduliP[j - 1], 2 * ringDim);
    rootsP[j] = RootOfUnity<NativeInteger>(2 * ringDim, moduliP[j]);
  }

  m_paramsP =
      std::make_shared<ILDCRTParams<BigInteger>>(2 * ringDim, moduliP, rootsP);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsP, 2 * ringDim,
                                                         moduliP);

  // stores the parameters for the auxiliary expanded CRT basis
  // {Q,P} = {q_1,...,q_l,p_1,...p_k}

  vector<NativeInteger> moduliQP(sizeQ + sizeP);
  vector<NativeInteger> rootsQP(sizeQ + sizeP);

  // populate moduli for CRT basis Q
  for (size_t i = 0; i < sizeQ; i++) {
    moduliQP[i] = moduliQ[i];
    rootsQP[i] = rootsQ[i];
  }

  // populate moduli for CRT basis P
  for (size_t j = 0; j < sizeP; j++) {
    moduliQP[sizeQ + j] = moduliP[j];
    rootsQP[sizeQ + j] = rootsP[j];
  }

  m_paramsQP = std::make_shared<ILDCRTParams<BigInteger>>(2 * ringDim, moduliQP,
                                                          rootsQP);

  m_qInv.resize(sizeQ);
  for (size_t i = 0; i < sizeQ; i++) {
    m_qInv[i] = 1. / static_cast<double>(moduliQ[i].ConvertToInt());
  }

  m_pInv.resize(sizeP);
  for (size_t j = 0; j < sizeP; j++) {
    m_pInv[j] = 1. / static_cast<double>(moduliP[j].ConvertToInt());
  }

  const BigInteger BarrettBase128Bit(
      "340282366920938463463374607431768211456");       // 2^128
  const BigInteger TwoPower64("18446744073709551616");  // 2^64

  // Precomputations for Barrett modulo reduction
  m_modqBarrettMu.resize(sizeQ);
  for (uint32_t i = 0; i < moduliQ.size(); i++) {
    BigInteger mu = BarrettBase128Bit / BigInteger(moduliQ[i]);
    uint64_t val[2];
    val[0] = (mu % TwoPower64).ConvertToInt();
    val[1] = mu.RShift(64).ConvertToInt();

    memcpy(&m_modqBarrettMu[i], val, sizeof(DoubleNativeInt));
  }

  // Precomputations for Barrett modulo reduction
  m_modpBarrettMu.resize(sizeP);
  for (uint32_t j = 0; j < moduliP.size(); j++) {
    BigInteger mu = BarrettBase128Bit / BigInteger(moduliP[j]);
    uint64_t val[2];
    val[0] = (mu % TwoPower64).ConvertToInt();
    val[1] = mu.RShift(64).ConvertToInt();

    memcpy(&m_modpBarrettMu[j], val, sizeof(DoubleNativeInt));
  }

  const BigInteger modulusQ = GetElementParams()->GetModulus();

  usint qMSB = moduliQ[0].GetMSB();
  usint sizeQMSB = GetMSB64(sizeQ);
  m_tQHatInvModqDivqModt.resize(sizeQ);
  m_tQHatInvModqDivqModtPrecon.resize(sizeQ);
  m_tQHatInvModqDivqFrac.resize(sizeQ);
  if (qMSB + sizeQMSB < 52) {
    for (size_t i = 0; i < sizeQ; i++) {
      BigInteger qi(moduliQ[i].ConvertToInt());
      BigInteger tQHatInvModqi = ((modulusQ.DividedBy(qi)).ModInverse(qi) *
                                  BigInteger(GetPlaintextModulus()));
      BigInteger tQHatInvModqDivqi = tQHatInvModqi.DividedBy(qi);
      m_tQHatInvModqDivqModt[i] =
          tQHatInvModqDivqi.Mod(GetPlaintextModulus()).ConvertToInt();
      m_tQHatInvModqDivqModtPrecon[i] =
          m_tQHatInvModqDivqModt[i].PrepModMulConst(GetPlaintextModulus());

      int64_t numerator = tQHatInvModqi.Mod(qi).ConvertToInt();
      int64_t denominator = moduliQ[i].ConvertToInt();
      m_tQHatInvModqDivqFrac[i] =
          static_cast<double>(numerator) / static_cast<double>(denominator);
    }
  } else {
    m_tQHatInvModqBDivqModt.resize(sizeQ);
    m_tQHatInvModqBDivqModtPrecon.resize(sizeQ);
    m_tQHatInvModqBDivqFrac.resize(sizeQ);
    usint qMSBHf = qMSB >> 1;
    for (size_t i = 0; i < sizeQ; i++) {
      BigInteger qi(moduliQ[i].ConvertToInt());
      BigInteger tQHatInvModqi = ((modulusQ.DividedBy(qi)).ModInverse(qi) *
                                  BigInteger(GetPlaintextModulus()));
      BigInteger tQHatInvModqDivqi = tQHatInvModqi.DividedBy(qi);
      m_tQHatInvModqDivqModt[i] =
          tQHatInvModqDivqi.Mod(GetPlaintextModulus()).ConvertToInt();
      m_tQHatInvModqDivqModtPrecon[i] =
          m_tQHatInvModqDivqModt[i].PrepModMulConst(GetPlaintextModulus());

      int64_t numerator = tQHatInvModqi.Mod(qi).ConvertToInt();
      int64_t denominator = moduliQ[i].ConvertToInt();
      m_tQHatInvModqDivqFrac[i] =
          static_cast<double>(numerator) / static_cast<double>(denominator);

      tQHatInvModqi.LShiftEq(qMSBHf);
      tQHatInvModqDivqi = tQHatInvModqi.DividedBy(qi);
      m_tQHatInvModqBDivqModt[i] =
          tQHatInvModqDivqi.Mod(GetPlaintextModulus()).ConvertToInt();
      m_tQHatInvModqBDivqModtPrecon[i] =
          m_tQHatInvModqBDivqModt[i].PrepModMulConst(GetPlaintextModulus());

      numerator = tQHatInvModqi.Mod(qi).ConvertToInt();
      m_tQHatInvModqBDivqFrac[i] =
          static_cast<double>(numerator) / static_cast<double>(denominator);
    }
  }

  // compute the CRT delta table [\floor{Q/t}]_{q_i}
  // used for encryption

  const BigInteger QDivt = modulusQ.DividedBy(GetPlaintextModulus());

  m_QDivtModq.resize(sizeQ);
  for (size_t i = 0; i < sizeQ; i++) {
    BigInteger qi(moduliQ[i].ConvertToInt());
    BigInteger QDivtModqi = QDivt.Mod(qi);
    m_QDivtModq[i] = NativeInteger(QDivtModqi.ConvertToInt());
  }

  // compute the [(Q/q_i)^{-1}]_{q_i}
  // used for homomorphic multiplication and key switching

  m_QHatInvModq.resize(sizeQ);
  m_QHatInvModqPrecon.resize(sizeQ);
  for (usint i = 0; i < sizeQ; i++) {
    BigInteger qi(moduliQ[i].ConvertToInt());
    BigInteger QHati = modulusQ / qi;
    m_QHatInvModq[i] = QHati.ModInverse(qi).Mod(qi).ConvertToInt();
    m_QHatInvModqPrecon[i] =
        m_QHatInvModq[i].PrepModMulConst(qi.ConvertToInt());
  }

  // compute the [Q/q_i]_{p_j}
  // used for homomorphic multiplication
  m_QHatModp.resize(sizeP);
  for (usint j = 0; j < sizeP; j++) {
    BigInteger pj(moduliP[j].ConvertToInt());
    for (usint i = 0; i < sizeQ; i++) {
      BigInteger qi(moduliQ[i].ConvertToInt());
      BigInteger QHati = modulusQ / qi;
      m_QHatModp[j].push_back(QHati.Mod(pj).ConvertToInt());
    }
  }

  // compute the [\alpha*Q]p_j for 0 <= alpha <= sizeQ
  // used for homomorphic multiplication
  m_alphaQModp.resize(sizeQ + 1);
  for (usint j = 0; j < sizeP; j++) {
    BigInteger pj(moduliP[j].ConvertToInt());
    NativeInteger QModpj = modulusQ.Mod(pj).ConvertToInt();
    for (usint i = 0; i < sizeQ + 1; i++) {
      m_alphaQModp[i].push_back(QModpj.ModMul(NativeInteger(i), moduliP[j]));
    }
  }

  // For S = Q*P
  // compute the [t*P*(S/s_k)^{-1}]_{s_k} / s_k
  // used for homomorphic multiplication
  m_tPSHatInvModsDivsFrac.resize(sizeQ);

  const BigInteger modulusP = m_paramsP->GetModulus();
  const BigInteger modulusQP = m_paramsQP->GetModulus();
  const BigInteger modulust(GetPlaintextModulus());

  for (size_t i = 0; i < sizeQ; i++) {
    BigInteger qi(moduliQ[i].ConvertToInt());
    m_tPSHatInvModsDivsFrac[i] =
        static_cast<double>(
            ((modulusQP.DividedBy(qi)).ModInverse(qi) * modulusP * modulust)
                .Mod(qi)
                .ConvertToInt()) /
        static_cast<double>(qi.ConvertToInt());
  }

  // For S = Q*P
  // compute the [\floor{t*P*[(S/s_k)^{-1}]_{s_k}/s_k}]_{s_k}
  // used for homomorphic multiplication
  m_tPSHatInvModsDivsModp.resize(sizeP);
  for (usint j = 0; j < sizeP; j++) {
    BigInteger pj(moduliP[j].ConvertToInt());
    for (usint i = 0; i < sizeQ; i++) {
      BigInteger qi(moduliQ[i].ConvertToInt());
      BigInteger tPSHatInvMods =
          modulust * modulusP * ((modulusQP.DividedBy(qi)).ModInverse(qi));
      BigInteger tPSHatInvModsDivs = tPSHatInvMods / qi;
      m_tPSHatInvModsDivsModp[j].push_back(
          tPSHatInvModsDivs.Mod(pj).ConvertToInt());
    }

    BigInteger tPSHatInvMods =
        modulust * modulusP * ((modulusQP.DividedBy(pj)).ModInverse(pj));
    BigInteger tPSHatInvModsDivs = tPSHatInvMods / pj;
    m_tPSHatInvModsDivsModp[j].push_back(
        tPSHatInvModsDivs.Mod(pj).ConvertToInt());
  }

  // compute the [{P/p_j}^{-1}]_{p_j}
  // used for homomorphic multiplication
  m_PHatInvModp.resize(sizeP);
  m_PHatInvModpPrecon.resize(sizeP);
  for (usint j = 0; j < sizeP; j++) {
    BigInteger pj(moduliP[j].ConvertToInt());
    BigInteger PHatj = modulusP / pj;
    m_PHatInvModp[j] = PHatj.ModInverse(pj).Mod(pj).ConvertToInt();
    m_PHatInvModpPrecon[j] =
        m_PHatInvModp[j].PrepModMulConst(pj.ConvertToInt());
  }

  // compute [P/p_j]_{q_i}
  // used for homomorphic multiplication
  m_PHatModq.resize(sizeQ);
  for (usint i = 0; i < sizeQ; i++) {
    BigInteger qi(moduliQ[i].ConvertToInt());
    for (usint j = 0; j < sizeP; j++) {
      BigInteger pj(moduliP[j].ConvertToInt());
      BigInteger PHat = modulusP / pj;
      m_PHatModq[i].push_back(PHat.Mod(qi).ConvertToInt());
    }
  }

  // compute [\alpha*P]_{q_i} for 0 <= alpha <= sizeP
  // used for homomorphic multiplication
  m_alphaPModq.resize(sizeP + 1);
  for (usint i = 0; i < sizeQ; i++) {
    BigInteger qi(moduliQ[i].ConvertToInt());
    NativeInteger PModqi = modulusP.Mod(qi).ConvertToInt();
    for (usint j = 0; j < sizeP + 1; ++j) {
      m_alphaPModq[j].push_back(PModqi.ModMul(NativeInteger(j), moduliQ[i]));
    }
  }

  return true;
}

// Parameter generation for BFV-RNS
template <>
bool LPAlgorithmParamsGenBFVrns<DCRTPoly>::ParamsGen(
    shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams, int32_t evalAddCount,
    int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits,
    uint32_t nCustom) const {
  if (!cryptoParams)
    PALISADE_THROW(not_available_error,
                   "No crypto parameters are supplied to BFVrns ParamsGen");

  if ((dcrtBits < 30) || (dcrtBits > 60))
    PALISADE_THROW(math_error,
                   "BFVrns.ParamsGen: Number of bits in CRT moduli should be "
                   "in the range from 30 to 60");

  const auto cryptoParamsBFVrns =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          cryptoParams);

  double sigma = cryptoParamsBFVrns->GetDistributionParameter();
  double alpha = cryptoParamsBFVrns->GetAssuranceMeasure();
  double hermiteFactor = cryptoParamsBFVrns->GetSecurityLevel();
  double p = static_cast<double>(cryptoParamsBFVrns->GetPlaintextModulus());
  uint32_t relinWindow = cryptoParamsBFVrns->GetRelinWindow();
  SecurityLevel stdLevel = cryptoParamsBFVrns->GetStdLevel();

  // Bound of the Gaussian error polynomial
  double Berr = sigma * sqrt(alpha);

  // Bound of the key polynomial
  double Bkey;

  DistributionType distType;

  // supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases
  if (cryptoParamsBFVrns->GetMode() == RLWE) {
    Bkey = sigma * sqrt(alpha);
    distType = HEStd_error;
  } else {
    Bkey = 1;
    distType = HEStd_ternary;
  }

  // expansion factor delta
  auto delta = [](uint32_t n) -> double { return (2. * sqrt(n)); };

  // norm of fresh ciphertext polynomial
  auto Vnorm = [&](uint32_t n) -> double {
    return Berr * (1. + 2. * delta(n) * Bkey);
  };

  // RLWE security constraint
  auto nRLWE = [&](double logq) -> double {
    if (stdLevel == HEStd_NotSet) {
      return (logq - log(sigma)) / (4. * log(hermiteFactor));
    } else {
      return static_cast<double>(StdLatticeParm::FindRingDim(
          distType, stdLevel, static_cast<long>(ceil(logq / log(2)))));
    }
  };

  // initial values
  uint32_t n = (nCustom > 0) ? nCustom : 512;

  double logq = 0.;

  // only public key encryption and EvalAdd (optional when evalAddCount = 0)
  // operations are supported the correctness constraint from section 3.5 of
  // https://eprint.iacr.org/2014/062.pdf is used
  if ((evalMultCount == 0) && (keySwitchCount == 0)) {
    // Correctness constraint
    auto logqBFV = [&](uint32_t n) -> double {
      return log(p *
                 (4 * ((evalAddCount + 1) * Vnorm(n) + evalAddCount * p) + p));
    };

    // initial value
    logq = logqBFV(n);

    if ((nRLWE(logq) > n) && (nCustom > 0))
      PALISADE_THROW(config_error,
                     "Ring dimension n specified by the user does not meet the "
                     "security requirement. Please increase it.");

    while (nRLWE(logq) > n) {
      n = 2 * n;
      logq = logqBFV(n);
    }

    // this code updates n and q to account for the discrete size of CRT moduli
    // = dcrtBits

    int32_t k =
        static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));

    double logqCeil = k * dcrtBits * log(2);

    while (nRLWE(logqCeil) > n) {
      n = 2 * n;
      logq = logqBFV(n);
      k = static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));
      logqCeil = k * dcrtBits * log(2);
    }
  } else if ((evalMultCount == 0) && (keySwitchCount > 0) &&
             (evalAddCount == 0)) {
    // this case supports automorphism w/o any other operations
    // base for relinearization

    double w = relinWindow == 0 ? pow(2, dcrtBits) : pow(2, relinWindow);

    // Correctness constraint
    auto logqBFV = [&](uint32_t n, double logqPrev) -> double {
      return log(
          p * (4 * (Vnorm(n) + keySwitchCount * delta(n) *
                                   (floor(logqPrev / (log(2) * dcrtBits)) + 1) *
                                   w * Berr) +
               p));
    };

    // initial values
    double logqPrev = 6 * log(10);
    logq = logqBFV(n, logqPrev);
    logqPrev = logq;

    if ((nRLWE(logq) > n) && (nCustom > 0))
      PALISADE_THROW(config_error,
                     "Ring dimension n specified by the user does not meet the "
                     "security requirement. Please increase it.");

    // this "while" condition is needed in case the iterative solution for q
    // changes the requirement for n, which is rare but still theoretically
    // possible
    while (nRLWE(logq) > n) {
      while (nRLWE(logq) > n) {
        n = 2 * n;
        logq = logqBFV(n, logqPrev);
        logqPrev = logq;
      }

      logq = logqBFV(n, logqPrev);

      while (fabs(logq - logqPrev) > log(1.001)) {
        logqPrev = logq;
        logq = logqBFV(n, logqPrev);
      }

      // this code updates n and q to account for the discrete size of CRT
      // moduli = dcrtBits

      int32_t k =
          static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));

      double logqCeil = k * dcrtBits * log(2);
      logqPrev = logqCeil;

      while (nRLWE(logqCeil) > n) {
        n = 2 * n;
        logq = logqBFV(n, logqPrev);
        k = static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));
        logqCeil = k * dcrtBits * log(2);
        logqPrev = logqCeil;
      }
    }
  } else if ((evalAddCount == 0) && (evalMultCount > 0) &&
             (keySwitchCount == 0)) {
    // Only EvalMult operations are used in the correctness constraint
    // the correctness constraint from section 3.5 of
    // https://eprint.iacr.org/2014/062.pdf is used

    // base for relinearization
    double w = relinWindow == 0 ? pow(2, dcrtBits) : pow(2, relinWindow);

    // function used in the EvalMult constraint
    auto epsilon1 = [&](uint32_t n) -> double { return 5 / (delta(n) * Bkey); };

    // function used in the EvalMult constraint
    auto C1 = [&](uint32_t n) -> double {
      return (1 + epsilon1(n)) * delta(n) * delta(n) * p * Bkey;
    };

    // function used in the EvalMult constraint
    auto C2 = [&](uint32_t n, double logqPrev) -> double {
      return delta(n) * delta(n) * Bkey * ((1 + 0.5) * Bkey + p * p) +
             delta(n) * (floor(logqPrev / (log(2) * dcrtBits)) + 1) * w * Berr;
    };

    // main correctness constraint
    auto logqBFV = [&](uint32_t n, double logqPrev) -> double {
      return log(4 * p) + (evalMultCount - 1) * log(C1(n)) +
             log(C1(n) * Vnorm(n) + evalMultCount * C2(n, logqPrev));
    };

    // initial values
    double logqPrev = 6. * log(10);
    logq = logqBFV(n, logqPrev);
    logqPrev = logq;

    if ((nRLWE(logq) > n) && (nCustom > 0))
      PALISADE_THROW(config_error,
                     "Ring dimension n specified by the user does not meet the "
                     "security requirement. Please increase it.");

    // this "while" condition is needed in case the iterative solution for q
    // changes the requirement for n, which is rare but still theoretically
    // possible
    while (nRLWE(logq) > n) {
      while (nRLWE(logq) > n) {
        n = 2 * n;
        logq = logqBFV(n, logqPrev);
        logqPrev = logq;
      }

      logq = logqBFV(n, logqPrev);

      while (fabs(logq - logqPrev) > log(1.001)) {
        logqPrev = logq;
        logq = logqBFV(n, logqPrev);
      }

      // this code updates n and q to account for the discrete size of CRT
      // moduli = dcrtBits

      int32_t k =
          static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));

      double logqCeil = k * dcrtBits * log(2);
      logqPrev = logqCeil;

      while (nRLWE(logqCeil) > n) {
        n = 2 * n;
        logq = logqBFV(n, logqPrev);
        k = static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));
        logqCeil = k * dcrtBits * log(2);
        logqPrev = logqCeil;
      }
    }
  }

  size_t sizeQ =
      static_cast<size_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));

  vector<NativeInteger> moduliQ(sizeQ);
  vector<NativeInteger> rootsQ(sizeQ);

  // makes sure the first integer is less than 2^60-1 to take advantage of NTL
  // optimizations
  NativeInteger firstInteger = FirstPrime<NativeInteger>(dcrtBits, 2 * n);

  moduliQ[0] = PreviousPrime<NativeInteger>(firstInteger, 2 * n);
  rootsQ[0] = RootOfUnity<NativeInteger>(2 * n, moduliQ[0]);

  for (size_t i = 1; i < sizeQ; i++) {
    moduliQ[i] = PreviousPrime<NativeInteger>(moduliQ[i - 1], 2 * n);
    rootsQ[i] = RootOfUnity<NativeInteger>(2 * n, moduliQ[i]);
  }

  auto params =
      std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQ, rootsQ);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsQ, 2 * n,
                                                         moduliQ);

  cryptoParamsBFVrns->SetElementParams(params);

  const EncodingParams encodingParams = cryptoParamsBFVrns->GetEncodingParams();
  if (encodingParams->GetBatchSize() > n)
    PALISADE_THROW(config_error,
                   "The batch size cannot be larger than the ring dimension.");
  // if no batch size was specified, we set batchSize = n by default (for full
  // packing)
  if (encodingParams->GetBatchSize() == 0) {
    uint32_t batchSize = n;
    EncodingParams encodingParamsNew(std::make_shared<EncodingParamsImpl>(
        encodingParams->GetPlaintextModulus(), batchSize));
    cryptoParamsBFVrns->SetEncodingParams(encodingParamsNew);
  }

  return cryptoParamsBFVrns->PrecomputeCRTTables();
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrns<DCRTPoly>::Encrypt(
    const LPPublicKey<DCRTPoly> publicKey, DCRTPoly ptxt) const {
  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          publicKey->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  ptxt.SetFormat(Format::EVALUATION);

  const std::vector<NativeInteger> &delta = cryptoParams->GetDelta();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  TugType tug;

  const DCRTPoly &p0 = publicKey->GetPublicElements().at(0);
  const DCRTPoly &p1 = publicKey->GetPublicElements().at(1);

  DCRTPoly u;

  // Supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases
  if (cryptoParams->GetMode() == RLWE)
    u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
  else
    u = DCRTPoly(tug, elementParams, Format::EVALUATION);

  DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
  DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

  DCRTPoly c0(elementParams);
  DCRTPoly c1(elementParams);

  c0 = p0 * u + e1 + ptxt.Times(delta);

  c1 = p1 * u + e2;

  ciphertext->SetElements({std::move(c0), std::move(c1)});

  return ciphertext;
}

template <>
DecryptResult LPAlgorithmBFVrns<DCRTPoly>::Decrypt(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext, NativePoly *plaintext) const {
  // TimeVar t_total;
  // TIC(t_total);

  const auto cryptoParamsBFVrns =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          privateKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams =
      cryptoParamsBFVrns->GetElementParams();

  const std::vector<DCRTPoly> &c = ciphertext->GetElements();

  const DCRTPoly &s = privateKey->GetPrivateElement();
  DCRTPoly sPower = s;

  DCRTPoly b = c[0];
  b.SetFormat(Format::EVALUATION);

  DCRTPoly cTemp;
  for (size_t i = 1; i <= ciphertext->GetDepth(); i++) {
    cTemp = c[i];
    cTemp.SetFormat(Format::EVALUATION);

    b += sPower * cTemp;
    sPower *= s;
  }

  // Converts back to coefficient representation
  b.SetFormat(Format::COEFFICIENT);

  auto &t = cryptoParamsBFVrns->GetPlaintextModulus();

  const std::vector<double> &tQHatInvModqDivqFrac =
      cryptoParamsBFVrns->GettQHatInvModqDivqFrac();
  const std::vector<double> &tQHatInvModqBDivqFrac =
      cryptoParamsBFVrns->GettQHatInvModqBDivqFrac();
  const std::vector<NativeInteger> &tQHatInvModqDivqModt =
      cryptoParamsBFVrns->GettQHatInvModqDivqModt();
  const std::vector<NativeInteger> &tQHatInvModqDivqModtPrecon =
      cryptoParamsBFVrns->GettQHatInvModqDivqModtPrecon();
  const std::vector<NativeInteger> &tQHatInvModqBDivqModt =
      cryptoParamsBFVrns->GettQHatInvModqBDivqModt();
  const std::vector<NativeInteger> &tQHatInvModqBDivqModtPrecon =
      cryptoParamsBFVrns->GettQHatInvModqBDivqModtPrecon();

  // this is the resulting vector of coefficients;
  *plaintext =
      b.ScaleAndRound(t, tQHatInvModqDivqModt, tQHatInvModqDivqModtPrecon,
                      tQHatInvModqBDivqModt, tQHatInvModqBDivqModtPrecon,
                      tQHatInvModqDivqFrac, tQHatInvModqBDivqFrac);

  // std::cout << "Decryption time (internal): " << TOC_US(t_total) << " us" <<
  // std::endl;

  return DecryptResult(plaintext->GetLength());
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrns<DCRTPoly>::Encrypt(
    const LPPrivateKey<DCRTPoly> privateKey, DCRTPoly ptxt) const {
  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          privateKey->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  ptxt.SwitchFormat();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;

  const std::vector<NativeInteger> &delta = cryptoParams->GetDelta();

  DCRTPoly a(dug, elementParams, Format::EVALUATION);
  const DCRTPoly &s = privateKey->GetPrivateElement();
  DCRTPoly e(dgg, elementParams, Format::EVALUATION);

  DCRTPoly c0(a * s + e + ptxt.Times(delta));
  DCRTPoly c1(elementParams, Format::EVALUATION, true);
  c1 -= a;

  ciphertext->SetElements({std::move(c0), std::move(c1)});

  return ciphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalAdd(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetDepth(ciphertext->GetDepth());

  const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

  const DCRTPoly &ptElement = plaintext->GetElement<DCRTPoly>();

  std::vector<DCRTPoly> c(cipherTextElements.size());

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  const std::vector<NativeInteger> &delta = cryptoParams->GetDelta();

  c[0] = cipherTextElements[0] + ptElement.Times(delta);

  for (size_t i = 1; i < cipherTextElements.size(); i++) {
    c[i] = cipherTextElements[i];
  }

  newCiphertext->SetElements(std::move(c));

  return newCiphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalSub(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetDepth(ciphertext->GetDepth());

  const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

  plaintext->SetFormat(Format::EVALUATION);
  const DCRTPoly &ptElement = plaintext->GetElement<DCRTPoly>();

  std::vector<DCRTPoly> c(cipherTextElements.size());

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  const std::vector<NativeInteger> &delta = cryptoParams->GetDelta();

  c[0] = cipherTextElements[0] - ptElement.Times(delta);

  for (size_t i = 1; i < cipherTextElements.size(); i++) {
    c[i] = cipherTextElements[i];
  }

  newCiphertext->SetElements(std::move(c));

  return newCiphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  if (!(ciphertext1->GetCryptoParameters() ==
        ciphertext2->GetCryptoParameters())) {
    std::string errMsg =
        "LPAlgorithmSHEBFVrns::EvalMult crypto parameters are not the same";
    PALISADE_THROW(config_error, errMsg);
  }

  Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

  const auto cryptoParamsBFVrns =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          ciphertext1->GetCryptoContext()->GetCryptoParameters());

  // Get the ciphertext elements
  std::vector<DCRTPoly> cipherText1Elements = ciphertext1->GetElements();
  std::vector<DCRTPoly> cipherText2Elements = ciphertext2->GetElements();

  size_t cipherText1ElementsSize = cipherText1Elements.size();
  size_t cipherText2ElementsSize = cipherText2Elements.size();
  size_t cipherTextRElementsSize =
      cipherText1ElementsSize + cipherText2ElementsSize - 1;

  std::vector<DCRTPoly> c(cipherTextRElementsSize);

  const shared_ptr<ParmType> elementParams =
      cryptoParamsBFVrns->GetElementParams();
  const shared_ptr<ILDCRTParams<BigInteger>> paramsP =
      cryptoParamsBFVrns->GetParamsP();
  const shared_ptr<ILDCRTParams<BigInteger>> paramsQP =
      cryptoParamsBFVrns->GetParamsQP();

  // Expands the CRT basis to Q*S; Outputs the polynomials in Format::EVALUATION
  // representation

  for (size_t i = 0; i < cipherText1ElementsSize; i++)
    cipherText1Elements[i].ExpandCRTBasis(
        paramsQP, paramsP, cryptoParamsBFVrns->GetQHatInvModq(),
        cryptoParamsBFVrns->GetQHatInvModqPrecon(),
        cryptoParamsBFVrns->GetQHatModp(), cryptoParamsBFVrns->GetalphaQModp(),
        cryptoParamsBFVrns->GetModpBarrettMu(), cryptoParamsBFVrns->GetqInv());

  for (size_t i = 0; i < cipherText2ElementsSize; i++)
    cipherText2Elements[i].ExpandCRTBasis(
        paramsQP, paramsP, cryptoParamsBFVrns->GetQHatInvModq(),
        cryptoParamsBFVrns->GetQHatInvModqPrecon(),
        cryptoParamsBFVrns->GetQHatModp(), cryptoParamsBFVrns->GetalphaQModp(),
        cryptoParamsBFVrns->GetModpBarrettMu(), cryptoParamsBFVrns->GetqInv());

  // Performs the multiplication itself
  // Karatsuba technique is currently slower so it is commented out
  /*if (cipherText1ElementsSize == 2 && cipherText2ElementsSize == 2) // size of
  each ciphertxt = 2, use Karatsuba
  {

          c[0] = cipherText1Elements[0] * cipherText2Elements[0]; // a
          c[2] = cipherText1Elements[1] * cipherText2Elements[1]; // b

          c[1] = cipherText1Elements[0] + cipherText1Elements[1];
          c[1] *= (cipherText2Elements[0] + cipherText2Elements[1]);
          c[1] -= c[2];
          c[1] -= c[0];

  }
  else // if size of any of the ciphertexts > 2
  {*/

  bool *isFirstAdd = new bool[cipherTextRElementsSize];
  std::fill_n(isFirstAdd, cipherTextRElementsSize, true);

  for (size_t i = 0; i < cipherText1ElementsSize; i++) {
    for (size_t j = 0; j < cipherText2ElementsSize; j++) {
      if (isFirstAdd[i + j] == true) {
        c[i + j] = cipherText1Elements[i] * cipherText2Elements[j];
        isFirstAdd[i + j] = false;
      } else {
        c[i + j] += cipherText1Elements[i] * cipherText2Elements[j];
      }
    }
  }

  delete[] isFirstAdd;
  //};

  for (size_t i = 0; i < cipherTextRElementsSize; i++) {
    // converts to coefficient representation before rounding
    c[i].SetFormat(Format::COEFFICIENT);
    // Performs the scaling by t/Q followed by rounding; the result is in the
    // CRT basis P
    c[i] = c[i].ScaleAndRound(paramsP,
                              cryptoParamsBFVrns->GettPSHatInvModsDivsModp(),
                              cryptoParamsBFVrns->GettPSHatInvModsDivsFrac(),
                              cryptoParamsBFVrns->GetModpBarrettMu());

    // Converts from the CRT basis P to Q
    c[i] = c[i].SwitchCRTBasis(
        elementParams, cryptoParamsBFVrns->GetPHatInvModp(),
        cryptoParamsBFVrns->GetPHatInvModpPrecon(),
        cryptoParamsBFVrns->GetPHatModq(), cryptoParamsBFVrns->GetalphaPModq(),
        cryptoParamsBFVrns->GetModqBarrettMu(), cryptoParamsBFVrns->GetpInv());
  }

  newCiphertext->SetElements(std::move(c));
  newCiphertext->SetDepth((ciphertext1->GetDepth() + ciphertext2->GetDepth()));

  return newCiphertext;
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::KeySwitchGen(
    const LPPrivateKey<DCRTPoly> originalPrivateKey,
    const LPPrivateKey<DCRTPoly> newPrivateKey) const {
  LPEvalKey<DCRTPoly> ek(std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(
      newPrivateKey->GetCryptoContext()));

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          newPrivateKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams =
      cryptoParamsLWE->GetElementParams();
  const DCRTPoly &s = newPrivateKey->GetPrivateElement();

  const DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
  DugType dug;

  const DCRTPoly &oldKey = originalPrivateKey->GetPrivateElement();

  std::vector<DCRTPoly> evalKeyElements;
  std::vector<DCRTPoly> evalKeyElementsGenerated;

  uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

  for (usint i = 0; i < oldKey.GetNumOfElements(); i++) {
    if (relinWindow > 0) {
      vector<typename DCRTPoly::PolyType> decomposedKeyElements =
          oldKey.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (size_t k = 0; k < decomposedKeyElements.size(); k++) {
        // Creates an element with all zeroes
        DCRTPoly filtered(elementParams, Format::EVALUATION, true);

        filtered.SetElementAtIndex(i, decomposedKeyElements[k]);

        // Generate a_i vectors
        DCRTPoly a(dug, elementParams, Format::EVALUATION);
        evalKeyElementsGenerated.push_back(a);

        // Generate a_i * s + e - [oldKey]_{q_i} [(Q/q_i)^{-1}]_{q_i} (q/qi)
        DCRTPoly e(dgg, elementParams, Format::EVALUATION);
        evalKeyElements.push_back(filtered - (a * s + e));
      }
    } else {
      // Creates an element with all zeroes
      DCRTPoly filtered(elementParams, Format::EVALUATION, true);

      filtered.SetElementAtIndex(i, oldKey.GetElementAtIndex(i));

      // Generate a_i vectors
      DCRTPoly a(dug, elementParams, Format::EVALUATION);
      evalKeyElementsGenerated.push_back(a);

      // Generate a_i * s + e - [oldKey]_{q_i} [(Q/qi)^{-1}]_qi (q/qi)
      DCRTPoly e(dgg, elementParams, Format::EVALUATION);
      evalKeyElements.push_back(filtered - (a * s + e));
    }
  }

  ek->SetAVector(std::move(evalKeyElements));
  ek->SetBVector(std::move(evalKeyElementsGenerated));

  return ek;
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmMultipartyBFVrns<DCRTPoly>::MultiKeySwitchGen(
    const LPPrivateKey<DCRTPoly> originalPrivateKey,
    const LPPrivateKey<DCRTPoly> newPrivateKey,
    const LPEvalKey<DCRTPoly> ek) const {
  LPEvalKeyRelin<DCRTPoly> keySwitchHintRelin(
      new LPEvalKeyRelinImpl<DCRTPoly>(newPrivateKey->GetCryptoContext()));

  const shared_ptr<LPCryptoParametersRLWE<DCRTPoly>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersRLWE<DCRTPoly>>(
          newPrivateKey->GetCryptoParameters());
  const shared_ptr<typename DCRTPoly::Params> elementParams =
      cryptoParamsLWE->GetElementParams();

  // Getting a reference to the polynomials of new private key.
  const DCRTPoly &sNew = newPrivateKey->GetPrivateElement();

  // Getting a reference to the polynomials of original private key.
  const DCRTPoly &s = originalPrivateKey->GetPrivateElement();

  const typename DCRTPoly::DggType &dgg =
      cryptoParamsLWE->GetDiscreteGaussianGenerator();
  typename DCRTPoly::DugType dug;

  std::vector<DCRTPoly> evalKeyElements;
  std::vector<DCRTPoly> evalKeyElementsGenerated;

  uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

  const std::vector<DCRTPoly> &a = ek->GetBVector();

  for (usint i = 0; i < s.GetNumOfElements(); i++) {
    if (relinWindow > 0) {
      vector<typename DCRTPoly::PolyType> decomposedKeyElements =
          s.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (size_t k = 0; k < decomposedKeyElements.size(); k++) {
        // Creates an element with all zeroes
        DCRTPoly filtered(elementParams, EVALUATION, true);

        filtered.SetElementAtIndex(i, decomposedKeyElements[k]);

        // Generate a_i vectors
        evalKeyElementsGenerated.push_back(
            a[i * decomposedKeyElements.size() + k]);

        // Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
        DCRTPoly e(dgg, elementParams, Format::EVALUATION);
        evalKeyElements.push_back(
            filtered - (a[i * decomposedKeyElements.size() + k] * sNew + e));
      }
    } else {
      // Creates an element with all zeroes
      DCRTPoly filtered(elementParams, EVALUATION, true);

      filtered.SetElementAtIndex(i, s.GetElementAtIndex(i));

      // Generate a_i vectors
      evalKeyElementsGenerated.push_back(a[i]);

      // Generate  [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi) - (a_i * s + e)
      DCRTPoly e(dgg, elementParams, Format::EVALUATION);
      evalKeyElements.push_back(filtered - (a[i] * sNew + e));
    }
  }

  keySwitchHintRelin->SetAVector(std::move(evalKeyElements));
  keySwitchHintRelin->SetBVector(std::move(evalKeyElementsGenerated));

  return keySwitchHintRelin;
}

template <>
void LPAlgorithmSHEBFVrns<DCRTPoly>::KeySwitchInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly>& cipherText) const {

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          ek->GetCryptoParameters());

  LPEvalKeyRelin<DCRTPoly> evalKey =
      std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

  std::vector<DCRTPoly> &c = cipherText->GetElements();

  const std::vector<DCRTPoly> &b = evalKey->GetAVector();
  const std::vector<DCRTPoly> &a = evalKey->GetBVector();

  uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

  std::vector<DCRTPoly> digitsC2;

  // in the case of EvalMult, c[0] is initially in coefficient format and needs
  // to be switched to Format::EVALUATION format
  if (c.size() > 2) c[0].SetFormat(Format::EVALUATION);

  if (c.size() == 2) {  // case of automorphism or PRE
    digitsC2 = c[1].CRTDecompose(relinWindow);
    c[1] = digitsC2[0] * a[0];
  } else {  // case of EvalMult
    digitsC2 = c[2].CRTDecompose(relinWindow);
    // Convert ct1 to Format::EVALUATION representation
    c[1].SetFormat(Format::EVALUATION);
    c[1] += digitsC2[0] * a[0];
  }

  c[0] += digitsC2[0] * b[0];

  for (usint i = 1; i < digitsC2.size(); ++i) {
    c[0] += digitsC2[i] * b[i];
    c[1] += digitsC2[i] * a[i];
  }

  Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();
  newCiphertext->SetElements({std::move(c[0]), std::move(c[1])});
  cipherText = std::move(newCiphertext);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalMultAndRelinearize(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2,
    const vector<LPEvalKey<DCRTPoly>> &ek) const {
  Ciphertext<DCRTPoly> cipherText = this->EvalMult(ciphertext1, ciphertext2);

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          ek[0]->GetCryptoParameters());

  Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

  std::vector<DCRTPoly> c = cipherText->GetElements();

  // Do not change the format of the elements to decompose
  if (c[0].GetFormat() == Format::COEFFICIENT) {
    for (size_t i = 0; i < 2; i++) c[i].SwitchFormat();
  }

  DCRTPoly ct0(c[0]);
  DCRTPoly ct1(c[1]);
  // Perform a keyswitching operation to result of the multiplication. It does
  // it until it reaches to 2 elements.
  // TODO: Maybe we can change the number of keyswitching and terminate early.
  // For instance; perform keyswitching until 4 elements left.
  for (size_t j = 0; j <= cipherText->GetDepth() - 2; j++) {
    size_t index = cipherText->GetDepth() - 2 - j;
    LPEvalKeyRelin<DCRTPoly> evalKey =
        std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

    const std::vector<DCRTPoly> &b = evalKey->GetAVector();
    const std::vector<DCRTPoly> &a = evalKey->GetBVector();

    std::vector<DCRTPoly> digitsC2 = c[index + 2].CRTDecompose();

    for (usint i = 0; i < digitsC2.size(); ++i) {
      ct0 += digitsC2[i] * b[i];
      ct1 += digitsC2[i] * a[i];
    }
  }

  newCiphertext->SetElements({std::move(ct0), std::move(ct1)});

  return newCiphertext;
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPREBFVrns<DCRTPoly>::ReKeyGen(
    const LPPublicKey<DCRTPoly> newPK,
    const LPPrivateKey<DCRTPoly> origPrivateKey) const {
  // Get crypto context of new public key.
  auto cc = newPK->GetCryptoContext();

  // Create an Format::EVALUATION key that will contain all the re-encryption
  // key elements.
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          newPK->GetCryptoParameters());
  const shared_ptr<DCRTPoly::Params> elementParams =
      cryptoParamsLWE->GetElementParams();

  const DCRTPoly::DggType &dgg =
      cryptoParamsLWE->GetDiscreteGaussianGenerator();
  DCRTPoly::DugType dug;
  DCRTPoly::TugType tug;

  const DCRTPoly &oldKey = origPrivateKey->GetPrivateElement();

  std::vector<DCRTPoly> evalKeyElements;
  std::vector<DCRTPoly> evalKeyElementsGenerated;

  uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

  const DCRTPoly &p0 = newPK->GetPublicElements().at(0);
  const DCRTPoly &p1 = newPK->GetPublicElements().at(1);

  for (usint i = 0; i < oldKey.GetNumOfElements(); i++) {
    if (relinWindow > 0) {
      vector<DCRTPoly::PolyType> decomposedKeyElements =
          oldKey.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (size_t k = 0; k < decomposedKeyElements.size(); k++) {
        // Creates an element with all zeroes
        DCRTPoly filtered(elementParams, Format::EVALUATION, true);

        filtered.SetElementAtIndex(i, decomposedKeyElements[k]);

        DCRTPoly u;

        if (cryptoParamsLWE->GetMode() == RLWE)
          u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
        else
          u = DCRTPoly(tug, elementParams, Format::EVALUATION);

        DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
        DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

        DCRTPoly c0(elementParams);
        DCRTPoly c1(elementParams);

        c0 = p0 * u + e1 + filtered;

        c1 = p1 * u + e2;

        DCRTPoly a(dug, elementParams, Format::EVALUATION);
        evalKeyElementsGenerated.push_back(c1);

        DCRTPoly e(dgg, elementParams, Format::EVALUATION);
        evalKeyElements.push_back(c0);
      }
    } else {
      // Creates an element with all zeroes
      DCRTPoly filtered(elementParams, Format::EVALUATION, true);

      filtered.SetElementAtIndex(i, oldKey.GetElementAtIndex(i));

      DCRTPoly u;

      if (cryptoParamsLWE->GetMode() == RLWE)
        u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
      else
        u = DCRTPoly(tug, elementParams, Format::EVALUATION);

      DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
      DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

      DCRTPoly c0(elementParams);
      DCRTPoly c1(elementParams);

      c0 = p0 * u + e1 + filtered;

      c1 = p1 * u + e2;

      DCRTPoly a(dug, elementParams, Format::EVALUATION);
      evalKeyElementsGenerated.push_back(c1);

      DCRTPoly e(dgg, elementParams, Format::EVALUATION);
      evalKeyElements.push_back(c0);
    }
  }

  ek->SetAVector(std::move(evalKeyElements));
  ek->SetBVector(std::move(evalKeyElementsGenerated));

  return ek;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmPREBFVrns<DCRTPoly>::ReEncrypt(
    const LPEvalKey<DCRTPoly> ek, ConstCiphertext<DCRTPoly> ciphertext,
    const LPPublicKey<DCRTPoly> publicKey) const {
  if (publicKey == nullptr) {  // Sender PK is not provided - CPA-secure PRE
    return ciphertext->GetCryptoContext()->KeySwitch(ek, ciphertext);
  } else {  // Sender PK provided - HRA-secure PRE
    const auto cryptoParamsLWE =
        std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
            ek->GetCryptoParameters());

    // Get crypto and elements parameters
    const shared_ptr<ParmType> elementParams =
        cryptoParamsLWE->GetElementParams();

    const DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
    TugType tug;

    PlaintextEncodings encType = ciphertext->GetEncodingType();

    Ciphertext<DCRTPoly> zeroCiphertext(
        std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));
    zeroCiphertext->SetEncodingType(encType);

    const DCRTPoly &p0 = publicKey->GetPublicElements().at(0);
    const DCRTPoly &p1 = publicKey->GetPublicElements().at(1);

    DCRTPoly u;

    if (cryptoParamsLWE->GetMode() == RLWE)
      u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
    else
      u = DCRTPoly(tug, elementParams, Format::EVALUATION);

    DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
    DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

    DCRTPoly c0 = p0 * u + e1;
    DCRTPoly c1 = p1 * u + e2;

    zeroCiphertext->SetElements({std::move(c0), std::move(c1)});

    // Add the encryption of zero for re-randomization purposes
    auto c = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->EvalAdd(
        ciphertext, zeroCiphertext);

    ciphertext->GetCryptoContext()->KeySwitchInPlace(ek, c);
    return c;
  }
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrns<DCRTPoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<DCRTPoly>> &ciphertextVec,
    NativePoly *plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
          ciphertextVec[0]->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const std::vector<DCRTPoly> &cElem = ciphertextVec[0]->GetElements();
  DCRTPoly b = cElem[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<DCRTPoly> &c2 = ciphertextVec[i]->GetElements();
    b += c2[0];
  }

  // this is the resulting vector of coefficients;
  *plaintext = b.ScaleAndRound(cryptoParams->GetPlaintextModulus(),
                               cryptoParams->GettQHatInvModqDivqModt(),
                               cryptoParams->GettQHatInvModqDivqModtPrecon(),
                               cryptoParams->GettQHatInvModqBDivqModt(),
                               cryptoParams->GettQHatInvModqBDivqModtPrecon(),
                               cryptoParams->GettQHatInvModqDivqFrac(),
                               cryptoParams->GettQHatInvModqBDivqFrac());

  return DecryptResult(plaintext->GetLength());
}

template class LPCryptoParametersBFVrns<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeBFVrns<DCRTPoly>;
template class LPAlgorithmBFVrns<DCRTPoly>;
template class LPAlgorithmPREBFVrns<DCRTPoly>;
template class LPAlgorithmSHEBFVrns<DCRTPoly>;
template class LPAlgorithmMultipartyBFVrns<DCRTPoly>;
template class LPAlgorithmParamsGenBFVrns<DCRTPoly>;

}  // namespace lbcrypto
