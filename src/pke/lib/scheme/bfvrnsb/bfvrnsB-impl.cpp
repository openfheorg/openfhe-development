// @file bfvrnsB-impl.cpp - template instantiations and methods for the BFVrnsB
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
/*
Description:

This code implements a RNS variant of the Brakerski-Fan-Vercauteren (BFV)
homomorphic encryption scheme.  This scheme is also referred to as the FV
scheme.

The BFV scheme is introduced in the following papers:
   - Zvika Brakerski (2012). Fully Homomorphic Encryption without Modulus
Switching from Classical GapSVP. Cryptology ePrint Archive, Report 2012/078.
(https://eprint.iacr.org/2012/078)
   - Junfeng Fan and Frederik Vercauteren (2012). Somewhat Practical Fully
Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144.
(https://eprint.iacr.org/2012/144.pdf)

 Our implementation builds from the designs here:
   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption
Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in
Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer
Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
   - Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent Zucca
(2016). A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes.
Cryptology ePrint Archive, Report 2016/510. (https://eprint.iacr.org/2016/510)
   - Ahmad Al Badawi and Yuriy Polyakov and Khin Mi Mi Aung and Bharadwaj
Veeravalli and Kurt Rohloff (2018). Implementation and Performance Evaluation of
RNS Variants of the BFV Homomorphic Encryption Scheme. Cryptology ePrint
Archive, Report 2018/589. {https://eprint.iacr.org/2018/589}
 */

#include "bfvrnsB.cpp"
#include "cryptocontext.h"

// #define USE_KARATSUBA

namespace lbcrypto {

#define NOPOLY                                                                 \
  std::string errMsg = "BFVrnsB does not support Poly. Use DCRTPoly instead."; \
  PALISADE_THROW(not_implemented_error, errMsg);

#define NONATIVEPOLY                                                \
  std::string errMsg =                                              \
      "BFVrnsB does not support NativePoly. Use DCRTPoly instead."; \
  PALISADE_THROW(not_implemented_error, errMsg);

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB()
    : m_numq(0), m_numb(0), m_negQInvModmtilde(0) {
  NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB()
    : m_numq(0), m_numb(0), m_negQInvModmtilde(0) {
  NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB(
    const LPCryptoParametersBFVrnsB &rhs)
    : m_numq(0), m_numb(0), m_negQInvModmtilde(0) {
  NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(
    const LPCryptoParametersBFVrnsB &rhs)
    : m_numq(0), m_numb(0), m_negQInvModmtilde(0) {
  NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB(
    shared_ptr<ParmType> params, const PlaintextModulus &plaintextModulus,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth)
    : m_numq(0), m_numb(0), m_negQInvModmtilde(0) {
  NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(
    shared_ptr<ParmType> params, const PlaintextModulus &plaintextModulus,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth)
    : m_numq(0), m_numb(0), m_negQInvModmtilde(0) {
  NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth)
    : m_numq(0), m_numb(0), m_negQInvModmtilde(0) {
  NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth)
    : m_numq(0), m_numb(0), m_negQInvModmtilde(0) {
  NONATIVEPOLY
}

// Parameter generation for BFV-RNS
template <>
bool LPCryptoParametersBFVrnsB<Poly>::PrecomputeCRTTables() {
  NOPOLY
}

template <>
bool LPCryptoParametersBFVrnsB<NativePoly>::PrecomputeCRTTables() {
  NONATIVEPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrnsB<Poly>::LPPublicKeyEncryptionSchemeBFVrnsB() {
  NOPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrnsB<
    NativePoly>::LPPublicKeyEncryptionSchemeBFVrnsB() {
  NONATIVEPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrnsB<Poly>::ParamsGen(
    shared_ptr<LPCryptoParameters<Poly>> cryptoParams, int32_t evalAddCount,
    int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits,
    uint32_t n) const {
  NOPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrnsB<NativePoly>::ParamsGen(
    shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams,
    int32_t evalAddCount, int32_t evalMultCount, int32_t keySwitchCount,
    size_t dcrtBits, uint32_t n) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrnsB<Poly>::Encrypt(
    const LPPublicKey<Poly> publicKey, Poly ptxt) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrnsB<NativePoly>::Encrypt(
    const LPPublicKey<NativePoly> publicKey, NativePoly ptxt) const {
  NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmBFVrnsB<Poly>::Decrypt(
    const LPPrivateKey<Poly> privateKey, ConstCiphertext<Poly> ciphertext,
    NativePoly *plaintext) const {
  NOPOLY
}

template <>
DecryptResult LPAlgorithmBFVrnsB<NativePoly>::Decrypt(
    const LPPrivateKey<NativePoly> privateKey,
    ConstCiphertext<NativePoly> ciphertext, NativePoly *plaintext) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrnsB<Poly>::Encrypt(
    const LPPrivateKey<Poly> privateKey, Poly ptxt) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrnsB<NativePoly>::Encrypt(
    const LPPrivateKey<NativePoly> privateKey, NativePoly ptxt) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalMult(
    ConstCiphertext<Poly> ciphertext1,
    ConstCiphertext<Poly> ciphertext2) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalMult(
    ConstCiphertext<NativePoly> ciphertext1,
    ConstCiphertext<NativePoly> ciphertext2) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalAdd(ConstCiphertext<Poly> ct,
                                                      ConstPlaintext pt) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalAdd(
    ConstCiphertext<NativePoly> ct, ConstPlaintext pt) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalSub(ConstCiphertext<Poly> ct,
                                                      ConstPlaintext pt) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalSub(
    ConstCiphertext<NativePoly> ct, ConstPlaintext pt) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBFVrnsB<Poly>::KeySwitchGen(
    const LPPrivateKey<Poly> originalPrivateKey,
    const LPPrivateKey<Poly> newPrivateKey) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::KeySwitchGen(
    const LPPrivateKey<NativePoly> originalPrivateKey,
    const LPPrivateKey<NativePoly> newPrivateKey) const {
  NONATIVEPOLY
}

template <>
void LPAlgorithmSHEBFVrnsB<Poly>::KeySwitchInPlace(
    const LPEvalKey<Poly> keySwitchHint,
    Ciphertext<Poly>& cipherText) const {
  NOPOLY
}

template <>
void LPAlgorithmSHEBFVrnsB<NativePoly>::KeySwitchInPlace(
    const LPEvalKey<NativePoly> keySwitchHint,
    Ciphertext<NativePoly>& cipherText) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalMultAndRelinearize(
    ConstCiphertext<Poly> ct1, ConstCiphertext<Poly> ct,
    const vector<LPEvalKey<Poly>> &ek) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly>
LPAlgorithmSHEBFVrnsB<NativePoly>::EvalMultAndRelinearize(
    ConstCiphertext<NativePoly> ct1, ConstCiphertext<NativePoly> ct,
    const vector<LPEvalKey<NativePoly>> &ek) const {
  NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrnsB<Poly>::MultipartyDecryptFusion(
    const vector<Ciphertext<Poly>> &ciphertextVec,
    NativePoly *plaintext) const {
  NOPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrnsB<NativePoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<NativePoly>> &ciphertextVec,
    NativePoly *plaintext) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<Poly> LPAlgorithmMultipartyBFVrnsB<Poly>::MultiKeySwitchGen(
    const LPPrivateKey<Poly> originalPrivateKey,
    const LPPrivateKey<Poly> newPrivateKey, const LPEvalKey<Poly> ek) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly>
LPAlgorithmMultipartyBFVrnsB<NativePoly>::MultiKeySwitchGen(
    const LPPrivateKey<NativePoly> originalPrivateKey,
    const LPPrivateKey<NativePoly> newPrivateKey,
    const LPEvalKey<NativePoly> ek) const {
  NONATIVEPOLY
}

template class LPCryptoParametersBFVrnsB<Poly>;
template class LPPublicKeyEncryptionSchemeBFVrnsB<Poly>;
template class LPAlgorithmBFVrnsB<Poly>;
template class LPAlgorithmSHEBFVrnsB<Poly>;
template class LPAlgorithmMultipartyBFVrnsB<Poly>;
template class LPAlgorithmParamsGenBFVrnsB<Poly>;

template class LPCryptoParametersBFVrnsB<NativePoly>;
template class LPPublicKeyEncryptionSchemeBFVrnsB<NativePoly>;
template class LPAlgorithmBFVrnsB<NativePoly>;
template class LPAlgorithmSHEBFVrnsB<NativePoly>;
template class LPAlgorithmMultipartyBFVrnsB<NativePoly>;
template class LPAlgorithmParamsGenBFVrnsB<NativePoly>;

#undef NOPOLY
#undef NONATIVEPOLY

// Precomputation of CRT tables encryption, decryption, and homomorphic
// multiplication
template <>
bool LPCryptoParametersBFVrnsB<DCRTPoly>::PrecomputeCRTTables() {
  // read values for the CRT basis

  size_t sizeQ = GetElementParams()->GetParams().size();
  auto ringDim = GetElementParams()->GetRingDimension();

  vector<NativeInteger> moduliQ(sizeQ);
  vector<NativeInteger> rootsQ(sizeQ);

  const BigInteger BarrettBase128Bit(
      "340282366920938463463374607431768211456");       // 2^128
  const BigInteger TwoPower64("18446744073709551616");  // 2^64

  m_moduliQ.resize(sizeQ);
  for (size_t i = 0; i < sizeQ; i++) {
    moduliQ[i] = GetElementParams()->GetParams()[i]->GetModulus();
    rootsQ[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
    m_moduliQ[i] = moduliQ[i];
  }

  // compute the CRT delta table floor(Q/p) mod qi - used for encryption

  const BigInteger modulusQ = GetElementParams()->GetModulus();

  const BigInteger QDivt = modulusQ.DividedBy(GetPlaintextModulus());

  std::vector<NativeInteger> QDivtModq(sizeQ);

  for (size_t i = 0; i < sizeQ; i++) {
    BigInteger qi = BigInteger(moduliQ[i].ConvertToInt());
    BigInteger QDivtModqi = QDivt.Mod(qi);
    QDivtModq[i] = NativeInteger(QDivtModqi.ConvertToInt());
  }

  m_QDivtModq = QDivtModq;

  m_modqBarrettMu.resize(sizeQ);
  for (uint32_t i = 0; i < m_modqBarrettMu.size(); i++) {
    BigInteger mu = BarrettBase128Bit / BigInteger(m_moduliQ[i]);
    uint64_t val[2];
    val[0] = (mu % TwoPower64).ConvertToInt();
    val[1] = mu.RShift(64).ConvertToInt();

    memcpy(&m_modqBarrettMu[i], val, sizeof(DoubleNativeInt));
  }

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsQ, 2 * ringDim,
                                                         moduliQ);

  // Compute Bajard's et al. RNS variant lookup tables

  // Populate EvalMulrns tables
  // find the a suitable size of B
  m_numq = sizeQ;

  BigInteger t = BigInteger(GetPlaintextModulus());
  BigInteger Q(GetElementParams()->GetModulus());

  BigInteger B = 1;
  BigInteger maxConvolutionValue =
      BigInteger(2) * BigInteger(ringDim) * Q * Q * t;

  m_moduliB.push_back(
      PreviousPrime<NativeInteger>(moduliQ[m_numq - 1], 2 * ringDim));
  m_rootsBsk.push_back(RootOfUnity<NativeInteger>(2 * ringDim, m_moduliB[0]));
  B = B * BigInteger(m_moduliB[0]);

  for (usint i = 1; i < m_numq; i++) {  // we already added one prime
    m_moduliB.push_back(
        PreviousPrime<NativeInteger>(m_moduliB[i - 1], 2 * ringDim));
    m_rootsBsk.push_back(RootOfUnity<NativeInteger>(2 * ringDim, m_moduliB[i]));

    B = B * BigInteger(m_moduliB[i]);
  }

  m_numb = m_numq;

  m_msk = PreviousPrime<NativeInteger>(m_moduliB[m_numq - 1], 2 * ringDim);

  usint s = 0;
  NativeInteger tmp = m_msk;
  while (tmp > 0) {
    tmp >>= 1;
    s++;
  }

  // check msk is large enough
  while (Q * B * BigInteger(m_msk) < maxConvolutionValue) {
    NativeInteger firstInteger = FirstPrime<NativeInteger>(s + 1, 2 * ringDim);

    m_msk = NextPrime<NativeInteger>(firstInteger, 2 * ringDim);
    s++;
    if (s >= 60) PALISADE_THROW(math_error, "msk is larger than 60 bits");
  }
  m_rootsBsk.push_back(RootOfUnity<NativeInteger>(2 * ringDim, m_msk));

  m_moduliBsk = m_moduliB;
  m_moduliBsk.push_back(m_msk);

  m_paramsBsk = std::make_shared<ILDCRTParams<BigInteger>>(
      2 * ringDim, m_moduliBsk, m_rootsBsk);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(
      m_rootsBsk, 2 * ringDim, m_moduliBsk);

  // populate Barrett constant for m_BskModuli
  m_modbskBarrettMu.resize(m_moduliBsk.size());
  for (uint32_t i = 0; i < m_modbskBarrettMu.size(); i++) {
    BigInteger mu = BarrettBase128Bit / BigInteger(m_moduliBsk[i]);
    uint64_t val[2];
    val[0] = (mu % TwoPower64).ConvertToInt();
    val[1] = mu.RShift(64).ConvertToInt();

    memcpy(&m_modbskBarrettMu[i], val, sizeof(DoubleNativeInt));
  }

  // Populate [(Q/q_i)^-1]_{q_i}
  m_QHatInvModq.resize(m_numq);
  for (uint32_t i = 0; i < m_QHatInvModq.size(); i++) {
    BigInteger QHatInvModqi;
    QHatInvModqi = Q.DividedBy(moduliQ[i]);
    QHatInvModqi = QHatInvModqi.Mod(moduliQ[i]);
    QHatInvModqi = QHatInvModqi.ModInverse(moduliQ[i]);
    m_QHatInvModq[i] = QHatInvModqi.ConvertToInt();
  }

  // Populate [t*(Q/q_i)^-1]_{q_i}
  m_tQHatInvModq.resize(m_numq);
  m_tQHatInvModqPrecon.resize(m_numq);
  for (uint32_t i = 0; i < m_tQHatInvModq.size(); i++) {
    BigInteger tQHatInvModqi;
    tQHatInvModqi = Q.DividedBy(moduliQ[i]);
    tQHatInvModqi = tQHatInvModqi.Mod(moduliQ[i]);
    tQHatInvModqi = tQHatInvModqi.ModInverse(moduliQ[i]);
    tQHatInvModqi = tQHatInvModqi.ModMul(t.ConvertToInt(), moduliQ[i]);
    m_tQHatInvModq[i] = tQHatInvModqi.ConvertToInt();
    m_tQHatInvModqPrecon[i] = m_tQHatInvModq[i].PrepModMulConst(moduliQ[i]);
  }

  // Populate [Q/q_i]_{bsk_j, mtilde}
  m_QHatModbsk.resize(m_numq);
  m_QHatModmtilde.resize(m_numq);
  for (uint32_t i = 0; i < m_QHatModbsk.size(); i++) {
    m_QHatModbsk[i].resize(m_numb + 1);

    BigInteger QHati = Q.DividedBy(moduliQ[i]);
    for (uint32_t j = 0; j < m_QHatModbsk[i].size(); j++) {
      BigInteger QHatiModbskj = QHati.Mod(m_moduliBsk[j]);
      m_QHatModbsk[i][j] = QHatiModbskj.ConvertToInt();
    }
    m_QHatModmtilde[i] = QHati.Mod(m_mtilde).ConvertToInt();
  }

  // Populate [1/q_i]_{bsk_j}
  m_qInvModbsk.resize(m_numq);
  for (uint32_t i = 0; i < m_qInvModbsk.size(); i++) {
    m_qInvModbsk[i].resize(m_numb + 1);
    for (uint32_t j = 0; j < m_qInvModbsk[i].size(); j++)
      m_qInvModbsk[i][j] = moduliQ[i].ModInverse(m_moduliBsk[j]);
  }

  // Populate [mtilde*(Q/q_i)^{-1}]_{q_i}
  m_mtildeQHatInvModq.resize(m_numq);
  m_mtildeQHatInvModqPrecon.resize(m_numq);

  BigInteger bmtilde(m_mtilde);
  for (uint32_t i = 0; i < m_mtildeQHatInvModq.size(); i++) {
    BigInteger mtildeQHatInvModqi = Q.DividedBy(moduliQ[i]);
    mtildeQHatInvModqi = mtildeQHatInvModqi.Mod(moduliQ[i]);
    mtildeQHatInvModqi = mtildeQHatInvModqi.ModInverse(moduliQ[i]);
    mtildeQHatInvModqi = mtildeQHatInvModqi * bmtilde;
    mtildeQHatInvModqi = mtildeQHatInvModqi.Mod(moduliQ[i]);
    m_mtildeQHatInvModq[i] = mtildeQHatInvModqi.ConvertToInt();
    m_mtildeQHatInvModqPrecon[i] =
        m_mtildeQHatInvModq[i].PrepModMulConst(moduliQ[i]);
  }

  // Populate [-Q^{-1}]_{mtilde}
  BigInteger negQInvModmtilde =
      (BigInteger(m_mtilde - 1) * Q.ModInverse(m_mtilde));
  negQInvModmtilde = negQInvModmtilde.Mod(m_mtilde);
  m_negQInvModmtilde = negQInvModmtilde.ConvertToInt();

  // Populate [Q]_{bski_j}
  m_QModbsk.resize(m_numq + 1);
  m_QModbskPrecon.resize(m_numq + 1);

  for (uint32_t j = 0; j < m_QModbsk.size(); j++) {
    BigInteger QModbskij = Q.Mod(m_moduliBsk[j]);
    m_QModbsk[j] = QModbskij.ConvertToInt();
    m_QModbskPrecon[j] = m_QModbsk[j].PrepModMulConst(m_moduliBsk[j]);
  }

  // Populate [mtilde^{-1}]_{bsk_j}
  m_mtildeInvModbsk.resize(m_numb + 1);
  m_mtildeInvModbskPrecon.resize(m_numb + 1);
  for (uint32_t j = 0; j < m_mtildeInvModbsk.size(); j++) {
    BigInteger mtildeInvModbskij = m_mtilde % m_moduliBsk[j];
    mtildeInvModbskij = mtildeInvModbskij.ModInverse(m_moduliBsk[j]);
    m_mtildeInvModbsk[j] = mtildeInvModbskij.ConvertToInt();
    m_mtildeInvModbskPrecon[j] =
        m_mtildeInvModbsk[j].PrepModMulConst(m_moduliBsk[j]);
  }

  // Populate {t/Q}_{bsk_j}
  m_tQInvModbsk.resize(m_numb + 1);
  m_tQInvModbskPrecon.resize(m_numb + 1);

  for (uint32_t i = 0; i < m_tQInvModbsk.size(); i++) {
    BigInteger tDivqModBski = Q.ModInverse(m_moduliBsk[i]);
    tDivqModBski.ModMulEq(t.ConvertToInt(), m_moduliBsk[i]);
    m_tQInvModbsk[i] = tDivqModBski.ConvertToInt();
    m_tQInvModbskPrecon[i] = m_tQInvModbsk[i].PrepModMulConst(m_moduliBsk[i]);
  }

  // Populate [(B/b_j)^{-1}]_{b_j}
  m_BHatInvModb.resize(m_numb);
  m_BHatInvModbPrecon.resize(m_numb);

  for (uint32_t i = 0; i < m_BHatInvModb.size(); i++) {
    BigInteger BDivBi;
    BDivBi = B.DividedBy(m_moduliB[i]);
    BDivBi = BDivBi.Mod(m_moduliB[i]);
    BDivBi = BDivBi.ModInverse(m_moduliB[i]);
    m_BHatInvModb[i] = BDivBi.ConvertToInt();
    m_BHatInvModbPrecon[i] = m_BHatInvModb[i].PrepModMulConst(m_moduliB[i]);
  }

  // Populate [B/b_j]_{q_i}
  m_BHatModq.resize(m_numb);
  for (uint32_t i = 0; i < m_BHatModq.size(); i++) {
    m_BHatModq[i].resize(m_numq);
    BigInteger BDivBi = B.DividedBy(m_moduliB[i]);
    for (uint32_t j = 0; j < m_BHatModq[i].size(); j++) {
      BigInteger BDivBiModqj = BDivBi.Mod(moduliQ[j]);
      m_BHatModq[i][j] = BDivBiModqj.ConvertToInt();
    }
  }

  // Populate [B/b_j]_{msk}
  m_BHatModmsk.resize(m_numb);
  for (uint32_t i = 0; i < m_BHatModmsk.size(); i++) {
    BigInteger BDivBi = B.DividedBy(m_moduliB[i]);
    m_BHatModmsk[i] = (BDivBi.Mod(m_msk)).ConvertToInt();
  }

  // Populate [B^{-1}]_{msk}
  m_BInvModmsk = (B.ModInverse(m_msk)).ConvertToInt();
  m_BInvModmskPrecon = m_BInvModmsk.PrepModMulConst(m_msk);

  // Populate [B]_{q_i}
  m_BModq.resize(m_numq);
  m_BModqPrecon.resize(m_numq);
  for (uint32_t i = 0; i < m_BModq.size(); i++) {
    m_BModq[i] = (B.Mod(moduliQ[i])).ConvertToInt();
    m_BModqPrecon[i] = m_BModq[i].PrepModMulConst(moduliQ[i]);
  }

  // Populate Decrns lookup tables

  NativeInteger tgamma = NativeInteger(t.ConvertToInt() * m_gamma);  // t*gamma

  m_tgamma = tgamma;

  // Populate [-1/q_i]_{t*gamma} (t*gamma < 2^58)
  m_negInvqModtgamma.resize(m_numq);
  m_negInvqModtgammaPrecon.resize(m_numq);
  for (uint32_t i = 0; i < m_negInvqModtgamma.size(); i++) {
    BigInteger imod(moduliQ[i]);
    BigInteger negInvqi = BigInteger((tgamma - 1)) * imod.ModInverse(tgamma);

    BigInteger negInvqiModtgamma = negInvqi.Mod(tgamma);
    m_negInvqModtgamma[i] = negInvqiModtgamma.ConvertToInt();
    m_negInvqModtgammaPrecon[i] = m_negInvqModtgamma[i].PrepModMulConst(tgamma);
  }

  // populate [t*gamma*(Q/q_i)^(-1)]_{q_i}
  m_tgammaQHatInvModq.resize(m_numq);
  m_tgammaQHatInvModqPrecon.resize(m_numq);

  BigInteger bmgamma(m_gamma);
  for (uint32_t i = 0; i < m_tgammaQHatInvModq.size(); i++) {
    BigInteger qDivqi = Q.DividedBy(moduliQ[i]);
    BigInteger imod(moduliQ[i]);
    qDivqi = qDivqi.ModInverse(moduliQ[i]);
    BigInteger gammaqDivqi = (qDivqi * bmgamma) % imod;
    BigInteger tgammaqDivqi = (gammaqDivqi * t) % imod;
    m_tgammaQHatInvModq[i] = tgammaqDivqi.ConvertToInt();
    m_tgammaQHatInvModqPrecon[i] =
        m_tgammaQHatInvModq[i].PrepModMulConst(moduliQ[i]);
  }

  return true;
}

// Parameter generation for BFV-RNS
template <>
bool LPAlgorithmParamsGenBFVrnsB<DCRTPoly>::ParamsGen(
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

  const auto cryptoParamsBFVrnsB =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
          cryptoParams);

  double sigma = cryptoParamsBFVrnsB->GetDistributionParameter();
  double alpha = cryptoParamsBFVrnsB->GetAssuranceMeasure();
  double hermiteFactor = cryptoParamsBFVrnsB->GetSecurityLevel();
  double p = static_cast<double>(cryptoParamsBFVrnsB->GetPlaintextModulus());
  uint32_t relinWindow = cryptoParamsBFVrnsB->GetRelinWindow();
  SecurityLevel stdLevel = cryptoParamsBFVrnsB->GetStdLevel();

  // Bound of the Gaussian error polynomial
  double Berr = sigma * sqrt(alpha);

  // Bound of the key polynomial
  double Bkey;

  DistributionType distType;

  // supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases
  if (cryptoParamsBFVrnsB->GetMode() == RLWE) {
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

  cryptoParamsBFVrnsB->SetElementParams(params);

  const EncodingParams encodingParams = cryptoParamsBFVrnsB->GetEncodingParams();
  if (encodingParams->GetBatchSize() > n)
    PALISADE_THROW(config_error,
                   "The batch size cannot be larger than the ring dimension.");

  // if no batch size was specified, we set batchSize = n by default (for full
  // packing)
  if (encodingParams->GetBatchSize() == 0) {
    uint32_t batchSize = n;
    EncodingParams encodingParamsNew(std::make_shared<EncodingParamsImpl>(
        encodingParams->GetPlaintextModulus(), batchSize));
    cryptoParamsBFVrnsB->SetEncodingParams(encodingParamsNew);
  }

  return cryptoParamsBFVrnsB->PrecomputeCRTTables();
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrnsB<DCRTPoly>::Encrypt(
    const LPPublicKey<DCRTPoly> publicKey, DCRTPoly ptxt) const {
  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
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
DecryptResult LPAlgorithmBFVrnsB<DCRTPoly>::Decrypt(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext, NativePoly *plaintext) const {
  // TimeVar t_total;

  // TIC(t_total);

  const auto cryptoParamsBFVrnsB =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
          privateKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams =
      cryptoParamsBFVrnsB->GetElementParams();

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

  // Converts back to Format::COEFFICIENT representation
  b.SetFormat(Format::COEFFICIENT);

  auto &t = cryptoParamsBFVrnsB->GetPlaintextModulus();
  auto &tgamma = cryptoParamsBFVrnsB->Gettgamma();
  const std::vector<NativeInteger> &moduliQ = cryptoParamsBFVrnsB->GetModuliQ();
  const std::vector<NativeInteger> &tgammaQHatInvModq =
      cryptoParamsBFVrnsB->GettgammaQHatInvModq();
  const std::vector<NativeInteger> &tgammaQHatInvModqPrecon =
      cryptoParamsBFVrnsB->GettgammaQHatInvModqPrecon();
  const std::vector<NativeInteger> &negInvqModtgamma =
      cryptoParamsBFVrnsB->GetNegInvqModtgamma();
  const std::vector<NativeInteger> &negInvqModtgammaPrecon =
      cryptoParamsBFVrnsB->GetNegInvqModtgammaPrecon();

  // this is the resulting vector of coefficients;
  *plaintext = b.ScaleAndRound(moduliQ, t, tgamma, tgammaQHatInvModq,
                               tgammaQHatInvModqPrecon, negInvqModtgamma,
                               negInvqModtgammaPrecon);

  // std::cout << "Decryption time (internal): " << TOC_US(t_total) << " us" <<
  // std::endl;

  return DecryptResult(plaintext->GetLength());
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrnsB<DCRTPoly>::Encrypt(
    const LPPrivateKey<DCRTPoly> privateKey, DCRTPoly ptxt) const {
  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
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
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::EvalAdd(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetDepth(ciphertext->GetDepth());

  const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

  const DCRTPoly &ptElement = plaintext->GetElement<DCRTPoly>();

  std::vector<DCRTPoly> c(cipherTextElements.size());

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
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
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::EvalSub(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetDepth(ciphertext->GetDepth());

  const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

  plaintext->SetFormat(Format::EVALUATION);
  const DCRTPoly &ptElement = plaintext->GetElement<DCRTPoly>();

  std::vector<DCRTPoly> c(cipherTextElements.size());

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
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
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  if (!(ciphertext1->GetCryptoParameters() ==
        ciphertext2->GetCryptoParameters())) {
    std::string errMsg =
        "LPAlgorithmSHEBFVrnsB::EvalMult crypto parameters are not the same";
    PALISADE_THROW(config_error, errMsg);
  }

  Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

  const auto cryptoParamsBFVrnsB =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
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
      cryptoParamsBFVrnsB->GetElementParams();
  const shared_ptr<ILDCRTParams<BigInteger>> paramsBsk =
      cryptoParamsBFVrnsB->GetParamsBsk();
  const std::vector<NativeInteger> &moduliQ = cryptoParamsBFVrnsB->GetModuliQ();
  const std::vector<DoubleNativeInt> &modqBarrettMu =
      cryptoParamsBFVrnsB->GetModqBarrettMu();
  const std::vector<NativeInteger> &moduliBsk =
      cryptoParamsBFVrnsB->GetModuliBsk();
  const std::vector<DoubleNativeInt> &modbskBarrettMu =
      cryptoParamsBFVrnsB->GetModbskBarrettMu();
  const std::vector<NativeInteger> &mtildeQHatInvModq =
      cryptoParamsBFVrnsB->GetmtildeQHatInvModq();
  const std::vector<NativeInteger> &mtildeQHatInvModqPrecon =
      cryptoParamsBFVrnsB->GetmtildeQHatInvModqPrecon();
  const std::vector<std::vector<NativeInteger>> &QHatModbsk =
      cryptoParamsBFVrnsB->GetQHatModbsk();
  const std::vector<uint16_t> &QHatModmtilde =
      cryptoParamsBFVrnsB->GetQHatModmtilde();
  const std::vector<NativeInteger> &QModbsk = cryptoParamsBFVrnsB->GetQModbsk();
  const std::vector<NativeInteger> &QModbskPrecon =
      cryptoParamsBFVrnsB->GetQModbskPrecon();
  const uint16_t &negQInvModmtilde = cryptoParamsBFVrnsB->GetNegQInvModmtilde();
  // const NativeInteger &negQInvModmtildePrecon =
  //     cryptoParamsBFVrnsB->GetNegQInvModmtildePrecon();
  const std::vector<NativeInteger> &mtildeInvModbsk =
      cryptoParamsBFVrnsB->GetmtildeInvModbsk();
  const std::vector<NativeInteger> &mtildeInvModbskPrecon =
      cryptoParamsBFVrnsB->GetmtildeInvModbskPrecon();

  // Expands the CRT basis to q*Bsk; Outputs the polynomials in coeff
  // representation

  for (size_t i = 0; i < cipherText1ElementsSize; i++) {
    cipherText1Elements[i].FastBaseConvqToBskMontgomery(
        paramsBsk, moduliQ, moduliBsk, modbskBarrettMu, mtildeQHatInvModq,
        mtildeQHatInvModqPrecon, QHatModbsk, QHatModmtilde, QModbsk,
        QModbskPrecon, negQInvModmtilde, mtildeInvModbsk,
        mtildeInvModbskPrecon);

    cipherText1Elements[i].SetFormat(Format::EVALUATION);
  }

  for (size_t i = 0; i < cipherText2ElementsSize; i++) {
    cipherText2Elements[i].FastBaseConvqToBskMontgomery(
        paramsBsk, moduliQ, moduliBsk, modbskBarrettMu, mtildeQHatInvModq,
        mtildeQHatInvModqPrecon, QHatModbsk, QHatModmtilde, QModbsk,
        QModbskPrecon, negQInvModmtilde, mtildeInvModbsk,
        mtildeInvModbskPrecon);

    cipherText2Elements[i].SetFormat(Format::EVALUATION);
  }

  // Performs the multiplication itself

#ifdef USE_KARATSUBA

  if (cipherText1ElementsSize == 2 && cipherText2ElementsSize == 2) {
    // size of each ciphertxt = 2, use Karatsuba
    c[0] = cipherText1Elements[0] * cipherText2Elements[0];  // a
    c[2] = cipherText1Elements[1] * cipherText2Elements[1];  // b

    c[1] = cipherText1Elements[0] + cipherText1Elements[1];
    c[1] *= (cipherText2Elements[0] + cipherText2Elements[1]);
    c[1] -= c[2];
    c[1] -= c[0];

  } else {  // if size of any of the ciphertexts > 2
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
  }

#else
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
#endif

  // perfrom RNS approximate Flooring
  const NativeInteger &t = cryptoParamsBFVrnsB->GetPlaintextModulus();
  const std::vector<NativeInteger> &tQHatInvModq =
      cryptoParamsBFVrnsB->GettQHatInvModq();
  const std::vector<NativeInteger> &tQHatInvModqPrecon =
      cryptoParamsBFVrnsB->GettQHatInvModqPrecon();
  const std::vector<std::vector<NativeInteger>> &qInvModbsk =
      cryptoParamsBFVrnsB->GetqInvModbsk();
  const std::vector<NativeInteger> &tQInvModbsk =
      cryptoParamsBFVrnsB->GettQInvModbsk();
  const std::vector<NativeInteger> &tQInvModbskPrecon =
      cryptoParamsBFVrnsB->GettQInvModbskPrecon();

  // perform FastBaseConvSK
  const std::vector<NativeInteger> &BHatInvModb =
      cryptoParamsBFVrnsB->GetBHatInvModb();
  const std::vector<NativeInteger> &BHatInvModbPrecon =
      cryptoParamsBFVrnsB->GetBHatInvModbPrecon();
  const std::vector<NativeInteger> &BHatModmsk =
      cryptoParamsBFVrnsB->GetBHatModmsk();
  const NativeInteger &BInvModmsk = cryptoParamsBFVrnsB->GetBInvModmsk();
  const NativeInteger &BInvModmskPrecon =
      cryptoParamsBFVrnsB->GetBInvModmskPrecon();
  const std::vector<std::vector<NativeInteger>> &BHatModq =
      cryptoParamsBFVrnsB->GetBHatModq();
  const std::vector<NativeInteger> &BModq = cryptoParamsBFVrnsB->GetBModq();
  const std::vector<NativeInteger> &BModqPrecon =
      cryptoParamsBFVrnsB->GetBModqPrecon();

  for (size_t i = 0; i < cipherTextRElementsSize; i++) {
    // converts to Format::COEFFICIENT representation before rounding
    c[i].SetFormat(Format::COEFFICIENT);
    // Performs the scaling by t/Q followed by rounding; the result is in the
    // CRT basis {Bsk}
    c[i].FastRNSFloorq(t, moduliQ, moduliBsk, modbskBarrettMu, tQHatInvModq,
                       tQHatInvModqPrecon, QHatModbsk, qInvModbsk, tQInvModbsk,
                       tQInvModbskPrecon);

    // Converts from the CRT basis {Bsk} to {Q}
    c[i].FastBaseConvSK(moduliQ, modqBarrettMu, moduliBsk, modbskBarrettMu,
                        BHatInvModb, BHatInvModbPrecon, BHatModmsk, BInvModmsk,
                        BInvModmskPrecon, BHatModq, BModq, BModqPrecon);
  }

  newCiphertext->SetElements(std::move(c));
  newCiphertext->SetDepth((ciphertext1->GetDepth() + ciphertext2->GetDepth()));

  return newCiphertext;
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::KeySwitchGen(
    const LPPrivateKey<DCRTPoly> originalPrivateKey,
    const LPPrivateKey<DCRTPoly> newPrivateKey) const {
  LPEvalKey<DCRTPoly> ek(std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(
      newPrivateKey->GetCryptoContext()));

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
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

        // Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
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

      // Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
      DCRTPoly e(dgg, elementParams, Format::EVALUATION);
      evalKeyElements.push_back(filtered - (a * s + e));
    }
  }

  ek->SetAVector(std::move(evalKeyElements));
  ek->SetBVector(std::move(evalKeyElementsGenerated));

  return ek;
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmMultipartyBFVrnsB<DCRTPoly>::MultiKeySwitchGen(
    const LPPrivateKey<DCRTPoly> originalPrivateKey,
    const LPPrivateKey<DCRTPoly> newPrivateKey,
    const LPEvalKey<DCRTPoly> ek) const {
  LPEvalKeyRelin<DCRTPoly> keySwitchHintRelin(
      new LPEvalKeyRelinImpl<DCRTPoly>(newPrivateKey->GetCryptoContext()));

  const shared_ptr<LPCryptoParametersRLWE<DCRTPoly>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersRLWE<DCRTPoly>>(
          newPrivateKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams =
      cryptoParamsLWE->GetElementParams();

  // Getting a reference to the polynomials of new private key.
  const DCRTPoly &sNew = newPrivateKey->GetPrivateElement();

  // Getting a reference to the polynomials of original private key.
  const DCRTPoly &s = originalPrivateKey->GetPrivateElement();

  const DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
  DugType dug;

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
void LPAlgorithmSHEBFVrnsB<DCRTPoly>::KeySwitchInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly>& cipherText) const {

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
          ek->GetCryptoParameters());

  LPEvalKeyRelin<DCRTPoly> evalKey =
      std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

  std::vector<DCRTPoly> &c = cipherText->GetElements();

  const std::vector<DCRTPoly> &b = evalKey->GetAVector();
  const std::vector<DCRTPoly> &a = evalKey->GetBVector();

  uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

  std::vector<DCRTPoly> digitsC2;


  // in the case of EvalMult, c[0] is initially in Format::COEFFICIENT format
  // and needs to be switched to Format::EVALUATION format
  if (c.size() > 2) c[0].SetFormat(Format::EVALUATION);

  if (c.size() == 2) {  // case of automorphism
    digitsC2 = c[1].CRTDecompose(relinWindow);
    c[1] = digitsC2[0] * a[0];
  } else {  // case of EvalMult
    digitsC2 = c[2].CRTDecompose(relinWindow);
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
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsB<DCRTPoly>::EvalMultAndRelinearize(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2,
    const vector<LPEvalKey<DCRTPoly>> &ek) const {
  Ciphertext<DCRTPoly> cipherText = this->EvalMult(ciphertext1, ciphertext2);

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
          ek[0]->GetCryptoParameters());

  Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

  std::vector<DCRTPoly> c = cipherText->GetElements();
  for (size_t i = 0; i < c.size(); i++) c[i].SetFormat(Format::EVALUATION);

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
LPEvalKey<DCRTPoly> LPAlgorithmPREBFVrnsB<DCRTPoly>::ReKeyGen(
    const LPPublicKey<DCRTPoly> newPK,
    const LPPrivateKey<DCRTPoly> origPrivateKey) const {
  // Get crypto context of new public key.
  auto cc = newPK->GetCryptoContext();

  // Create an Format::EVALUATION key that will contain all the re-encryption
  // key elements.
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
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
Ciphertext<DCRTPoly> LPAlgorithmPREBFVrnsB<DCRTPoly>::ReEncrypt(
    const LPEvalKey<DCRTPoly> ek, ConstCiphertext<DCRTPoly> ciphertext,
    const LPPublicKey<DCRTPoly> publicKey) const {
  if (publicKey == nullptr) {  // Sender PK is not provided - CPA-secure PRE
    return ciphertext->GetCryptoContext()->KeySwitch(ek, ciphertext);
  }

  // Sender PK provided - HRA-secure PRE
  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
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

template <>
DecryptResult LPAlgorithmMultipartyBFVrnsB<DCRTPoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<DCRTPoly>> &ciphertextVec,
    NativePoly *plaintext) const {
  const auto cryptoParamsBFVrnsB =
      std::static_pointer_cast<LPCryptoParametersBFVrnsB<DCRTPoly>>(
          ciphertextVec[0]->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams =
      cryptoParamsBFVrnsB->GetElementParams();

  const std::vector<DCRTPoly> &cElem = ciphertextVec[0]->GetElements();
  DCRTPoly b = cElem[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<DCRTPoly> &c2 = ciphertextVec[i]->GetElements();
    b += c2[0];
  }

  auto &t = cryptoParamsBFVrnsB->GetPlaintextModulus();
  auto &tgamma = cryptoParamsBFVrnsB->Gettgamma();

  // Invoke BFVrnsB DecRNS

  const std::vector<NativeInteger> &moduliQ = cryptoParamsBFVrnsB->GetModuliQ();
  const std::vector<NativeInteger> &tgammaQHatInvModq =
      cryptoParamsBFVrnsB->GettgammaQHatInvModq();
  const std::vector<NativeInteger> &tgammaQHatInvModqPrecon =
      cryptoParamsBFVrnsB->GettgammaQHatInvModqPrecon();
  const std::vector<NativeInteger> &negInvqModtgamma =
      cryptoParamsBFVrnsB->GetNegInvqModtgamma();
  const std::vector<NativeInteger> &negInvqModtgammaPrecon =
      cryptoParamsBFVrnsB->GetNegInvqModtgammaPrecon();

  // this is the resulting vector of coefficients;
  *plaintext = b.ScaleAndRound(moduliQ, t, tgamma, tgammaQHatInvModq,
                               tgammaQHatInvModqPrecon, negInvqModtgamma,
                               negInvqModtgammaPrecon);

  return DecryptResult(plaintext->GetLength());
}

template class LPCryptoParametersBFVrnsB<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeBFVrnsB<DCRTPoly>;
template class LPAlgorithmBFVrnsB<DCRTPoly>;
template class LPAlgorithmSHEBFVrnsB<DCRTPoly>;
template class LPAlgorithmMultipartyBFVrnsB<DCRTPoly>;
template class LPAlgorithmParamsGenBFVrnsB<DCRTPoly>;

}  // namespace lbcrypto
