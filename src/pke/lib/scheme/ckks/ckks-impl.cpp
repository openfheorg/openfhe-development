// @file ckks-dcrtpoly-impl.cpp - CKKS dcrtpoly implementation.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
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

This code implements RNS variants of the Cheon-Kim-Kim-Song scheme.

The CKKS scheme is introduced in the following paper:
- Jung Hee Cheon, Andrey Kim, Miran Kim, and Yongsoo Song. Homomorphic
encryption for arithmetic of approximate numbers. Cryptology ePrint Archive,
Report 2016/421, 2016. https://eprint.iacr.org/2016/421.

 Our implementation builds from the designs here:
 - Marcelo Blatt, Alexander Gusev, Yuriy Polyakov, Kurt Rohloff, and Vinod
Vaikuntanathan. Optimized homomorphic encryption solution for secure genomewide
association studies. Cryptology ePrint Archive, Report 2019/223, 2019.
https://eprint.iacr.org/2019/223.
 - Andrey Kim, Antonis Papadimitriou, and Yuriy Polyakov. Approximate homomorphic
encryption with reduced approximation error. Cryptology ePrint
Archive, Report 2020/1118, 2020. https://eprint.iacr.org/2020/
1118.
 */

#define PROFILE

#include "cryptocontext.h"

#include "ckks.cpp"

namespace lbcrypto {

#if NATIVEINT == 128
const size_t AUXMODSIZE = 119;
#else
const size_t AUXMODSIZE = 60;
#endif

template class LPCryptoParametersCKKS<Poly>;
template class LPPublicKeyEncryptionSchemeCKKS<Poly>;
template class LPAlgorithmCKKS<Poly>;

template class LPCryptoParametersCKKS<NativePoly>;
template class LPPublicKeyEncryptionSchemeCKKS<NativePoly>;
template class LPAlgorithmCKKS<NativePoly>;

template class LPCryptoParametersCKKS<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeCKKS<DCRTPoly>;
template class LPAlgorithmCKKS<DCRTPoly>;

#define NOPOLY                                                              \
  std::string errMsg = "CKKS does not support Poly. Use DCRTPoly instead."; \
  PALISADE_THROW(not_implemented_error, errMsg);

#define NONATIVEPOLY                                             \
  std::string errMsg =                                           \
      "CKKS does not support NativePoly. Use DCRTPoly instead."; \
  PALISADE_THROW(not_implemented_error, errMsg);

#define NODCRTPOLY                                                    \
  std::string errMsg =                                                \
      "CKKS does not support DCRTPoly. Use NativePoly/Poly instead."; \
  PALISADE_THROW(not_implemented_error, errMsg);

template <>
bool LPCryptoParametersCKKS<Poly>::PrecomputeCRTTables(
    KeySwitchTechnique ksTech, RescalingTechnique rsTech, uint32_t dnum) {
  NOPOLY
}

template <>
bool LPCryptoParametersCKKS<NativePoly>::PrecomputeCRTTables(
    KeySwitchTechnique ksTech, RescalingTechnique rsTech, uint32_t dnum) {
  NONATIVEPOLY
}

// Precomputation of CRT tables encryption, decryption, and  homomorphic
// multiplication
template <>
bool LPCryptoParametersCKKS<DCRTPoly>::PrecomputeCRTTables(
    KeySwitchTechnique ksTech, RescalingTechnique rsTech,
    uint32_t numLargeDigits) {
  // Set the key switching technique. This determines what CRT values we
  // need to precompute.
  this->m_ksTechnique = ksTech;
  this->m_rsTechnique = rsTech;
  this->m_numPartQ = numLargeDigits;

  // Get ring dimension (n) and number of moduli in main CRT basis
  // (sizeQ)
  size_t sizeQ = GetElementParams()->GetParams().size();
  size_t n = GetElementParams()->GetRingDimension();

  // Construct moduliQ and rootsQ from crypto parameters
  vector<NativeInteger> moduliQ(sizeQ);
  vector<NativeInteger> rootsQ(sizeQ);
  for (size_t i = 0; i < sizeQ; i++) {
    moduliQ[i] = GetElementParams()->GetParams()[i]->GetModulus();
    rootsQ[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
  }
  BigInteger modulusQ = GetElementParams()->GetModulus();

  // Pre-compute CRT::FFT values for Q
  DiscreteFourierTransform::Initialize(n * 2, n / 2);
  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsQ, 2 * n,
                                                         moduliQ);

  // Pre-compute omega values for rescaling in RNS
  // modulusQ holds Q^(l) = \prod_{i=0}^{i=l}(q_i).
  m_QlQlInvModqlDivqlModq.resize(sizeQ - 1);
  m_QlQlInvModqlDivqlModqPrecon.resize(sizeQ - 1);
  m_qInvModq.resize(sizeQ - 1);
  m_qInvModqPrecon.resize(sizeQ - 1);
  for (size_t k = 0; k < sizeQ - 1; k++) {
    size_t l = sizeQ - (k + 1);
    modulusQ = modulusQ / BigInteger(moduliQ[l]);
    m_QlQlInvModqlDivqlModq[k].resize(l);
    m_QlQlInvModqlDivqlModqPrecon[k].resize(l);
    m_qInvModq[k].resize(l);
    m_qInvModqPrecon[k].resize(l);
    BigInteger QlInvModql = modulusQ.ModInverse(moduliQ[l]);
    BigInteger result = (QlInvModql * modulusQ) / BigInteger(moduliQ[l]);
    for (usint i = 0; i < l; i++) {
      m_QlQlInvModqlDivqlModq[k][i] = result.Mod(moduliQ[i]).ConvertToInt();
      m_QlQlInvModqlDivqlModqPrecon[k][i] =
          m_QlQlInvModqlDivqlModq[k][i].PrepModMulConst(moduliQ[i]);
      m_qInvModq[k][i] = moduliQ[l].ModInverse(moduliQ[i]);
      m_qInvModqPrecon[k][i] = m_qInvModq[k][i].PrepModMulConst(moduliQ[i]);
    }
  }

  if (m_ksTechnique == HYBRID) {
    // Compute alpha = ceil(sizeQ/m_numPartQ), the # of towers per digit
    uint32_t a = ceil(static_cast<double>(sizeQ) / m_numPartQ);
    if ((int32_t)(sizeQ - a * (m_numPartQ - 1)) <= 0) {
      auto str =
          "LLPCryptoParametersCKKS<DCRTPoly>::PrecomputeCRTTables - HYBRID key "
          "switching parameters: Can't appropriately distribute " +
          std::to_string(sizeQ) + " towers into " +
          std::to_string(this->m_numPartQ) +
          " digits. Please select different number of digits.";
      PALISADE_THROW(config_error, str);
    }

    m_numPerPartQ = a;

    // Compute the composite big moduli Q_j
    BigInteger bigQ = BigInteger(1);
    m_moduliPartQ.resize(m_numPartQ);
    for (usint j = 0; j < m_numPartQ; j++) {
      m_moduliPartQ[j] = BigInteger(1);
      for (usint i = a * j; i < (j + 1) * a; i++) {
        if (i < moduliQ.size()) m_moduliPartQ[j] *= moduliQ[i];
      }
      bigQ *= m_moduliPartQ[j];
    }

    // Compute PartQHat_i = Q/Q_j
    m_PartQHat.resize(m_numPartQ);
    for (size_t i = 0; i < m_numPartQ; i++) {
      m_PartQHat[i] = BigInteger(1);
      for (size_t j = 0; j < m_numPartQ; j++) {
        if (j != i) m_PartQHat[i] *= m_moduliPartQ[j];
      }
    }

    // Compute [QHat_j]_{q_i} and [QHat_j^{-1}]_{q_i}
    // used in fast basis conversion
    m_PartQHatModq.resize(m_numPartQ);
    m_PartQHatInvModq.resize(m_numPartQ);
    for (uint32_t j = 0; j < m_numPartQ; j++) {
      m_PartQHatModq[j].resize(sizeQ);
      m_PartQHatInvModq[j].resize(sizeQ);
      for (uint32_t i = 0; i < sizeQ; i++) {
        m_PartQHatModq[j][i] = m_PartQHat[j].Mod(moduliQ[i]).ConvertToInt();
        if (i >= j * a && i <= ((j + 1) * a - 1)) {
          m_PartQHatInvModq[j][i] =
              m_PartQHat[j].ModInverse(moduliQ[i]).ConvertToInt();
        }
      }
    }

    // Compute partitions of Q into numPartQ digits
    m_paramsPartQ.resize(m_numPartQ);
    for (uint32_t j = 0; j < m_numPartQ; j++) {
      auto startTower = j * a;
      auto endTower = ((j + 1) * a - 1 < sizeQ) ? (j + 1) * a - 1 : sizeQ - 1;
      vector<shared_ptr<ILNativeParams>> params =
          GetElementParams()->GetParamPartition(startTower, endTower);
      vector<NativeInteger> moduli(params.size());
      vector<NativeInteger> roots(params.size());
      for (uint32_t i = 0; i < params.size(); i++) {
        moduli[i] = params[i]->GetModulus();
        roots[i] = params[i]->GetRootOfUnity();
      }
      m_paramsPartQ[j] = std::make_shared<ILDCRTParams<BigInteger>>(
          ILDCRTParams<BigInteger>(params[0]->GetCyclotomicOrder(), moduli,
                                   roots, {}, {}, BigInteger(0)));
    }
  }

  // Reset modulusQ to Q = q_1*...*q_L. This is because
  // the code following this statement requires modulusQ.
  modulusQ = GetElementParams()->GetModulus();

  size_t PModSize = AUXMODSIZE;
  uint32_t sizeP = 1;

  if (m_ksTechnique == GHS) {
    // Select number and size of special primes in auxiliary CRT basis
    PModSize = AUXMODSIZE;
    uint32_t qBits = modulusQ.GetLengthForBase(2);
    sizeP = ceil(static_cast<double>(qBits) / PModSize);
  }
  if (m_ksTechnique == HYBRID) {
    // Find number and size of individual special primes.
    uint32_t maxBits = m_moduliPartQ[0].GetLengthForBase(2);
    for (usint j = 1; j < m_numPartQ; j++) {
      uint32_t bits = m_moduliPartQ[j].GetLengthForBase(2);
      if (bits > maxBits) maxBits = bits;
    }
    // Select number of primes in auxiliary CRT basis
    PModSize = AUXMODSIZE;
    sizeP = ceil(static_cast<double>(maxBits) / PModSize);
  }

  if (this->m_ksTechnique == GHS || this->m_ksTechnique == HYBRID) {
    // Choose special primes in auxiliary basis and compute their roots
    // moduliP holds special primes p1, p2, ..., pk
    // m_modulusP holds the product of special primes P = p1*p2*...pk
    vector<NativeInteger> moduliP(sizeP);
    vector<NativeInteger> rootsP(sizeP);
    // firstP contains a prime whose size is PModSize.
    NativeInteger firstP = FirstPrime<NativeInteger>(PModSize, 2 * n);
    NativeInteger pPrev = firstP;
    m_modulusP = BigInteger(1);
    for (usint i = 0; i < sizeP; i++) {
      // The following loop makes sure that moduli in
      // P and Q are different
      bool foundInQ = false;
      do {
        moduliP[i] = PreviousPrime<NativeInteger>(pPrev, 2 * n);
        foundInQ = false;
        for (usint j = 0; j < sizeQ; j++)
          if (moduliP[i] == moduliQ[j]) foundInQ = true;
        pPrev = moduliP[i];
      } while (foundInQ);
      rootsP[i] = RootOfUnity<NativeInteger>(2 * n, moduliP[i]);
      m_modulusP *= moduliP[i];
      pPrev = moduliP[i];
    }

    // Store the created moduli and roots in m_paramsP
    m_paramsP =
        std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliP, rootsP);

    // Create the moduli and roots for the extended CRT basis QP
    vector<NativeInteger> moduliExpanded(sizeQ + sizeP);
    vector<NativeInteger> rootsExpanded(sizeQ + sizeP);
    for (size_t i = 0; i < sizeQ; i++) {
      moduliExpanded[i] = moduliQ[i];
      rootsExpanded[i] = rootsQ[i];
    }
    for (size_t i = 0; i < sizeP; i++) {
      moduliExpanded[sizeQ + i] = moduliP[i];
      rootsExpanded[sizeQ + i] = rootsP[i];
    }

    m_paramsQP = std::make_shared<ILDCRTParams<BigInteger>>(
        2 * n, moduliExpanded, rootsExpanded);

    // Pre-compute CRT::FFT values for P
    ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsP, 2 * n,
                                                           moduliP);

    // Pre-compute values [P]_{q_i}
    m_PModq.resize(sizeQ);
    for (usint i = 0; i < sizeQ; i++) {
      m_PModq[i] = m_modulusP.Mod(moduliQ[i]).ConvertToInt();
    }

    // Pre-compute values [P^{-1}]_{q_i}
    m_PInvModq.resize(sizeQ);
    m_PInvModqPrecon.resize(sizeQ);
    for (size_t i = 0; i < sizeQ; i++) {
      BigInteger PInvModqi = m_modulusP.ModInverse(moduliQ[i]);
      m_PInvModq[i] = PInvModqi.ConvertToInt();
      m_PInvModqPrecon[i] = m_PInvModq[i].PrepModMulConst(moduliQ[i]);
    }

    // Pre-compute values [(P/p_j)^{-1}]_{p_j}
    // Pre-compute values [P/p_j]_{q_i}
    m_PHatInvModp.resize(sizeP);
    m_PHatInvModpPrecon.resize(sizeP);
    m_PHatModq.resize(sizeP);
    for (size_t j = 0; j < sizeP; j++) {
      BigInteger PHatj = m_modulusP / BigInteger(moduliP[j]);
      BigInteger PHatInvModpj = PHatj.ModInverse(moduliP[j]);
      m_PHatInvModp[j] = PHatInvModpj.ConvertToInt();
      m_PHatInvModpPrecon[j] = m_PHatInvModp[j].PrepModMulConst(moduliP[j]);
      m_PHatModq[j].resize(sizeQ);
      for (size_t i = 0; i < sizeQ; i++) {
        BigInteger PHatModqji = PHatj.Mod(moduliQ[i]);
        m_PHatModq[j][i] = PHatModqji.ConvertToInt();
      }
    }

    // Pre-compute values [(Q/q_i)^{-1}]_{q_i}
    // Pre-compute values [Q/q_i]_{p_j}
    m_LvlQHatInvModq.resize(sizeQ);
    m_LvlQHatInvModqPrecon.resize(sizeQ);
    m_LvlQHatModp.resize(sizeQ);
    // l will run from 0 to size-2, but modulusQ values
    // run from Q^(l-1) to Q^(0)
    for (size_t l = 0; l < sizeQ; l++) {
      if (l > 0) modulusQ = modulusQ / BigInteger(moduliQ[sizeQ - l]);

      m_LvlQHatInvModq[sizeQ - l - 1].resize(sizeQ - l);
      m_LvlQHatInvModqPrecon[sizeQ - l - 1].resize(sizeQ - l);
      m_LvlQHatModp[sizeQ - l - 1].resize(sizeQ - l);
      for (size_t i = 0; i < sizeQ - l; i++) {
        m_LvlQHatModp[sizeQ - l - 1][i].resize(sizeP);
        BigInteger QHati = modulusQ / BigInteger(moduliQ[i]);
        BigInteger QHatInvModqi = QHati.ModInverse(moduliQ[i]);
        m_LvlQHatInvModq[sizeQ - l - 1][i] = QHatInvModqi.ConvertToInt();
        m_LvlQHatInvModqPrecon[sizeQ - l - 1][i] =
            m_LvlQHatInvModq[sizeQ - l - 1][i].PrepModMulConst(moduliQ[i]);
        for (size_t j = 0; j < sizeP; j++) {
          BigInteger QHatModpij = QHati.Mod(moduliP[j]);
          m_LvlQHatModp[sizeQ - l - 1][i][j] = QHatModpij.ConvertToInt();
        }
      }
    }

    // Pre-compute Barrett mu
    const BigInteger BarrettBase128Bit(
        "340282366920938463463374607431768211456");       // 2^128
    const BigInteger TwoPower64("18446744073709551616");  // 2^64
    m_modpBarrettMu.resize(sizeP);
    for (uint32_t i = 0; i < sizeP; i++) {
      BigInteger mu = BarrettBase128Bit / BigInteger(moduliP[i]);
      uint64_t val[2];
      val[0] = (mu % TwoPower64).ConvertToInt();
      val[1] = mu.RShift(64).ConvertToInt();

      memcpy(&m_modpBarrettMu[i], val, sizeof(DoubleNativeInt));
    }
    m_modqBarrettMu.resize(sizeQ);
    for (uint32_t i = 0; i < sizeQ; i++) {
      BigInteger mu = BarrettBase128Bit / BigInteger(moduliQ[i]);
      uint64_t val[2];
      val[0] = (mu % TwoPower64).ConvertToInt();
      val[1] = mu.RShift(64).ConvertToInt();

      memcpy(&m_modqBarrettMu[i], val, sizeof(DoubleNativeInt));
    }

    if (m_ksTechnique == HYBRID) {
      // Pre-compute compementary partitions for ModUp
      uint32_t alpha = ceil(static_cast<double>(sizeQ) / m_numPartQ);
      m_paramsComplPartQ.resize(sizeQ);
      m_modComplPartqBarrettMu.resize(sizeQ);
      for (int32_t l = sizeQ - 1; l >= 0; l--) {
        uint32_t beta = ceil(static_cast<double>(l + 1) / alpha);
        m_paramsComplPartQ[l].resize(beta);
        m_modComplPartqBarrettMu[l].resize(beta);
        for (uint32_t j = 0; j < beta; j++) {
          const shared_ptr<ILDCRTParams<BigInteger>> digitPartition =
              GetParamsPartQ(j);
          auto cyclOrder = digitPartition->GetCyclotomicOrder();

          uint32_t sizePartQj = digitPartition->GetParams().size();
          if (j == beta - 1) sizePartQj = (l + 1) - j * alpha;
          uint32_t sizeComplPartQj = (l + 1) - sizePartQj + sizeP;

          vector<NativeInteger> moduli(sizeComplPartQj);
          vector<NativeInteger> roots(sizeComplPartQj);

          for (uint32_t k = 0; k < sizeComplPartQj; k++) {
            if (k < (l + 1) - sizePartQj) {
              uint32_t currDigit = k / alpha;
              if (currDigit >= j) currDigit++;
              moduli[k] = GetParamsPartQ(currDigit)
                              ->GetParams()[k % alpha]
                              ->GetModulus();
              roots[k] = GetParamsPartQ(currDigit)
                             ->GetParams()[k % alpha]
                             ->GetRootOfUnity();
            } else {
              moduli[k] = moduliP[k - ((l + 1) - sizePartQj)];
              roots[k] = rootsP[k - ((l + 1) - sizePartQj)];
            }
          }
          m_paramsComplPartQ[l][j] = std::make_shared<ParmType>(
              DCRTPoly::Params(cyclOrder, moduli, roots, {}, {}, 0));

          // Pre-compute Barrett mu for 128-bit by 64-bit reduction
          const BigInteger BarrettBase128Bit(
              "340282366920938463463374607431768211456");       // 2^128
          const BigInteger TwoPower64("18446744073709551616");  // 2^64
          m_modComplPartqBarrettMu[l][j].resize(moduli.size());
          for (uint32_t i = 0; i < moduli.size(); i++) {
            BigInteger mu = BarrettBase128Bit / BigInteger(moduli[i]);
            uint64_t val[2];
            val[0] = (mu % TwoPower64).ConvertToInt();
            val[1] = mu.RShift(64).ConvertToInt();

            memcpy(&m_modComplPartqBarrettMu[l][j][i], val,
                   sizeof(DoubleNativeInt));
          }
        }
      }

      // Pre-compute values [Q^(l)_j/q_i)^{-1}]_{q_i}
      m_LvlPartQHatInvModq.resize(m_numPartQ);
      m_LvlPartQHatInvModqPrecon.resize(m_numPartQ);
      for (uint32_t k = 0; k < m_numPartQ; k++) {
        auto params = m_paramsPartQ[k]->GetParams();
        uint32_t sizePartQk = params.size();
        m_LvlPartQHatInvModq[k].resize(sizePartQk);
        m_LvlPartQHatInvModqPrecon[k].resize(sizePartQk);
        auto modulusPartQ = m_paramsPartQ[k]->GetModulus();
        for (size_t l = 0; l < sizePartQk; l++) {
          if (l > 0)
            modulusPartQ =
                modulusPartQ / BigInteger(params[sizePartQk - l]->GetModulus());

          m_LvlPartQHatInvModq[k][sizePartQk - l - 1].resize(sizePartQk - l);
          m_LvlPartQHatInvModqPrecon[k][sizePartQk - l - 1].resize(sizePartQk -
                                                                   l);
          for (size_t i = 0; i < sizePartQk - l; i++) {
            BigInteger QHat =
                modulusPartQ / BigInteger(params[i]->GetModulus());
            BigInteger QHatInvModqi = QHat.ModInverse(params[i]->GetModulus());
            m_LvlPartQHatInvModq[k][sizePartQk - l - 1][i] =
                QHatInvModqi.ConvertToInt();
            m_LvlPartQHatInvModqPrecon[k][sizePartQk - l - 1][i] =
                m_LvlPartQHatInvModq[k][sizePartQk - l - 1][i].PrepModMulConst(
                    params[i]->GetModulus());
          }
        }
      }

      // Pre-compute QHat mod complementary partition qi's
      m_LvlPartQHatModp.resize(sizeQ);
      for (uint32_t l = 0; l < sizeQ; l++) {
        uint32_t alpha = ceil(static_cast<double>(sizeQ) / m_numPartQ);
        uint32_t beta = ceil(static_cast<double>(l + 1) / alpha);
        m_LvlPartQHatModp[l].resize(beta);
        for (uint32_t k = 0; k < beta; k++) {
          auto paramsPartQ = GetParamsPartQ(k)->GetParams();
          auto partQ = GetParamsPartQ(k)->GetModulus();
          uint32_t digitSize = paramsPartQ.size();
          if (k == beta - 1) {
            digitSize = l + 1 - k * alpha;
            for (uint32_t idx = digitSize; idx < paramsPartQ.size(); idx++) {
              partQ = partQ / BigInteger(paramsPartQ[idx]->GetModulus());
            }
          }

          m_LvlPartQHatModp[l][k].resize(digitSize);
          for (uint32_t i = 0; i < digitSize; i++) {
            BigInteger partQHat =
                partQ / BigInteger(paramsPartQ[i]->GetModulus());
            auto complBasis = GetParamsComplPartQ(l, k);
            m_LvlPartQHatModp[l][k][i].resize(complBasis->GetParams().size());
            for (size_t j = 0; j < complBasis->GetParams().size(); j++) {
              BigInteger QHatModpj =
                  partQHat.Mod(complBasis->GetParams()[j]->GetModulus());
              m_LvlPartQHatModp[l][k][i][j] = QHatModpj.ConvertToInt();
            }
          }
        }
      }
    }
  }

  // Pre-compute scaling factors for each level (used in EXACT rescaling
  // technique)
  if (m_rsTechnique == EXACTRESCALE) {
    m_scalingFactors.resize(sizeQ);

    m_scalingFactors[0] = moduliQ[sizeQ - 1].ConvertToDouble();

    for (uint32_t k = 1; k < sizeQ; k++) {
      double prevSF = m_scalingFactors[k - 1];
      m_scalingFactors[k] =
          prevSF * prevSF / moduliQ[sizeQ - k].ConvertToDouble();
      double ratio = m_scalingFactors[k] / m_scalingFactors[0];
      if (ratio <= 0.5 || ratio >= 2.0)
        PALISADE_THROW(config_error,
                       "LPCryptoParametersCKKS<DCRTPoly>::PrecomputeCRTTables "
                       "- EXACTRESCALE cannot support this "
                       "number of levels in this parameter setting. Please use "
                       "APPROXRESCALE.");
    }

    m_dmoduliQ.resize(sizeQ);
    for (uint32_t i = 0; i < sizeQ; ++i) {
      m_dmoduliQ[i] = moduliQ[i].ConvertToDouble();
    }
  } else {
    const auto p = GetPlaintextModulus();
    m_approxSF = pow(2, p);
  }

  return true;
}

template <>
bool LPAlgorithmParamsGenCKKS<Poly>::ParamsGen(
    shared_ptr<LPCryptoParameters<Poly>> cryptoParams, usint cyclOrder,
    usint numPrimes, usint scaleExp, usint relinWindow, MODE mode,
    KeySwitchTechnique ksTech, usint firstModSize, RescalingTechnique rsTech,
    uint32_t numLargeDigits) const {
  NOPOLY
}

template <>
bool LPAlgorithmParamsGenCKKS<NativePoly>::ParamsGen(
    shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams, usint cyclOrder,
    usint numPrimes, usint scaleExp, usint relinWindow, MODE mode,
    KeySwitchTechnique ksTech, usint firstModSize, RescalingTechnique rsTech,
    uint32_t numLargeDigits) const {
  NONATIVEPOLY
}

template <>
bool LPAlgorithmParamsGenCKKS<DCRTPoly>::ParamsGen(
    shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams, usint cyclOrder,
    usint numPrimes, usint scaleExp, usint relinWindow, MODE mode,
    KeySwitchTechnique ksTech, usint firstModSize, RescalingTechnique rsTech,
    uint32_t numLargeDigits) const {
  const auto cryptoParamsCKKS =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(cryptoParams);

  //// HE Standards compliance logic/check
  SecurityLevel stdLevel = cryptoParamsCKKS->GetStdLevel();
  uint32_t PModSize = AUXMODSIZE;
  uint32_t n = cyclOrder / 2;
  uint32_t qBound = 0;
  // Estimate ciphertext modulus Q bound (in case of GHS/HYBRID P*Q)
  if (ksTech == BV) {
    qBound = firstModSize + (numPrimes - 1) * scaleExp;
  } else if (ksTech == GHS) {
    qBound = firstModSize + (numPrimes - 1) * scaleExp;
    qBound += ceil(static_cast<double>(qBound) / PModSize) * PModSize;
  } else if (ksTech == HYBRID) {
    qBound = firstModSize + (numPrimes - 1) * scaleExp;
    qBound +=
        ceil(ceil(static_cast<double>(qBound) / numLargeDigits) / PModSize) *
        AUXMODSIZE;
  }

  // RLWE security constraint
  DistributionType distType =
      (cryptoParamsCKKS->GetMode() == RLWE) ? HEStd_error : HEStd_ternary;
  auto nRLWE = [&](usint q) -> uint32_t {
    return StdLatticeParm::FindRingDim(distType, stdLevel, q);
  };

  // Case 1: SecurityLevel specified as HEStd_NotSet -> Do nothing
  if (stdLevel != HEStd_NotSet) {
    if (n == 0) {
      // Case 2: SecurityLevel specified, but ring dimension not specified

      // Choose ring dimension based on security standards
      n = nRLWE(qBound);
      cyclOrder = 2 * n;
    } else {  // if (n!=0)
      // Case 3: Both SecurityLevel and ring dimension specified

      // Check whether particular selection is standards-compliant
      auto he_std_n = nRLWE(qBound);
      if (he_std_n > n) {
        PALISADE_THROW(
            config_error,
            "The specified ring dimension (" + std::to_string(n) +
                ") does not comply with HE standards recommendation (" +
                std::to_string(he_std_n) + ").");
      }
    }
  } else if (n == 0) {
    PALISADE_THROW(
        config_error,
        "Please specify the ring dimension or desired security level.");
  }
  //// End HE Standards compliance logic/check

  usint dcrtBits = scaleExp;

  vector<NativeInteger> moduliQ(numPrimes);
  vector<NativeInteger> rootsQ(numPrimes);

  NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, cyclOrder);
  moduliQ[numPrimes - 1] = q;
  rootsQ[numPrimes - 1] = RootOfUnity(cyclOrder, moduliQ[numPrimes - 1]);

  NativeInteger qNext = q;
  NativeInteger qPrev = q;
  if (numPrimes > 1) {
    if (rsTech != EXACTRESCALE) {
      uint32_t cnt = 0;
      for (usint i = numPrimes - 2; i >= 1; i--) {
        if ((cnt % 2) == 0) {
          qPrev = lbcrypto::PreviousPrime(qPrev, cyclOrder);
          q = qPrev;
        } else {
          qNext = lbcrypto::NextPrime(qNext, cyclOrder);
          q = qNext;
        }

        moduliQ[i] = q;
        rootsQ[i] = RootOfUnity(cyclOrder, moduliQ[i]);
        cnt++;
      }
    } else {  // EXACTRESCALE
      /* Scaling factors in EXACTRESCALE are a bit fragile,
       * in the sense that once one scaling factor gets far enough from the
       * original scaling factor, subsequent level scaling factors quickly
       * diverge to either 0 or infinity. To mitigate this problem to a certain
       * extend, we have a special prime selection process in place. The goal is
       * to maintain the scaling factor of all levels as close to the original
       * scale factor of level 0 as possible.
       */

      double sf = moduliQ[numPrimes - 1].ConvertToDouble();
      uint32_t cnt = 0;
      for (usint i = numPrimes - 2; i >= 1; i--) {
        sf = static_cast<double>(pow(sf, 2) / moduliQ[i + 1].ConvertToDouble());
        if ((cnt % 2) == 0) {
          NativeInteger sfInt = std::llround(sf);
          NativeInteger sfRem = sfInt.Mod(cyclOrder);
          NativeInteger qPrev =
              sfInt - NativeInteger(cyclOrder) - sfRem + NativeInteger(1);

          bool hasSameMod = true;
          while (hasSameMod) {
            hasSameMod = false;
            qPrev = lbcrypto::PreviousPrime(qPrev, cyclOrder);
            for (uint32_t j = i + 1; j < numPrimes; j++) {
              if (qPrev == moduliQ[j]) {
                hasSameMod = true;
              }
            }
          }
          moduliQ[i] = qPrev;

        } else {
          NativeInteger sfInt = std::llround(sf);
          NativeInteger sfRem = sfInt.Mod(cyclOrder);
          NativeInteger qNext =
              sfInt + NativeInteger(cyclOrder) - sfRem + NativeInteger(1);
          bool hasSameMod = true;
          while (hasSameMod) {
            hasSameMod = false;
            qNext = lbcrypto::NextPrime(qNext, cyclOrder);
            for (uint32_t j = i + 1; j < numPrimes; j++) {
              if (qNext == moduliQ[j]) {
                hasSameMod = true;
              }
            }
          }
          moduliQ[i] = qNext;
        }

        rootsQ[i] = RootOfUnity(cyclOrder, moduliQ[i]);
        cnt++;
      }
    }
  }

  if (firstModSize == dcrtBits) {  // this requires dcrtBits < 60
    moduliQ[0] = PreviousPrime<NativeInteger>(qPrev, cyclOrder);
  } else {
    NativeInteger firstInteger =
        FirstPrime<NativeInteger>(firstModSize, cyclOrder);
    moduliQ[0] = PreviousPrime<NativeInteger>(firstInteger, cyclOrder);
  }
  rootsQ[0] = RootOfUnity(cyclOrder, moduliQ[0]);

  auto paramsDCRT =
      std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliQ, rootsQ);

  cryptoParamsCKKS->SetElementParams(paramsDCRT);

  const EncodingParams encodingParams = cryptoParamsCKKS->GetEncodingParams();
  if (encodingParams->GetBatchSize() > n / 2)
    PALISADE_THROW(config_error,
                   "The batch size cannot be larger than ring dimension / 2.");

  // if no batch size was specified, we set batchSize = n/2 by default (for full
  // packing)
  if (encodingParams->GetBatchSize() == 0) {
    uint32_t batchSize = n / 2;
    EncodingParams encodingParamsNew(std::make_shared<EncodingParamsImpl>(
        encodingParams->GetPlaintextModulus(), batchSize));
    cryptoParamsCKKS->SetEncodingParams(encodingParamsNew);
  }

  return cryptoParamsCKKS->PrecomputeCRTTables(ksTech, rsTech, numLargeDigits);
}

template <>
Ciphertext<NativePoly> LPAlgorithmCKKS<NativePoly>::Encrypt(
    const LPPublicKey<NativePoly> publicKey, NativePoly ptxt) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmCKKS<Poly>::Encrypt(
    const LPPublicKey<Poly> publicKey, Poly ptxt) const {
  NOPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmCKKS<DCRTPoly>::Encrypt(
    const LPPublicKey<DCRTPoly> publicKey, DCRTPoly ptxt) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          publicKey->GetCryptoParameters());

  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

  const shared_ptr<ParmType> ptxtParams = ptxt.GetParams();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

  TugType tug;

  ptxt.SetFormat(Format::EVALUATION);

  std::vector<DCRTPoly> cv;

  DCRTPoly v;

  // Supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases
  if (cryptoParams->GetMode() == RLWE)
    v = DCRTPoly(dgg, ptxtParams, Format::EVALUATION);
  else
    v = DCRTPoly(tug, ptxtParams, Format::EVALUATION);

  DCRTPoly e0(dgg, ptxtParams, Format::EVALUATION);
  DCRTPoly e1(dgg, ptxtParams, Format::EVALUATION);

  const std::vector<DCRTPoly> &pk = publicKey->GetPublicElements();
  uint32_t sizeQl = ptxtParams->GetParams().size();
  uint32_t sizeQ = pk[0].GetParams()->GetParams().size();

  DCRTPoly c0, c1;
  if (sizeQl != sizeQ) {
    // Clone public keys because we need to drop towers.
    DCRTPoly b = pk[0].Clone();
    DCRTPoly a = pk[1].Clone();

    uint32_t diffQl = sizeQ - sizeQl;
    b.DropLastElements(diffQl);
    a.DropLastElements(diffQl);

    c0 = b * v + e0 + ptxt;
    c1 = a * v + e1;
  } else {
    // Use public keys as they are
    const DCRTPoly &b = pk[0];
    const DCRTPoly &a = pk[1];

    c0 = b * v + e0 + ptxt;
    c1 = a * v + e1;
  }

  cv.push_back(std::move(c0));
  cv.push_back(std::move(c1));

  ciphertext->SetElements(std::move(cv));

  // Ciphertext depth, level, and scaling factor should be
  // equal to that of the plaintext. However, Encrypt does
  // not take Plaintext as input (only DCRTPoly), so we
  // don't have access to these here, and we set them in
  // the crypto context Encrypt method.
  ciphertext->SetDepth(1);

  return ciphertext;
}

template <>
Ciphertext<NativePoly> LPAlgorithmCKKS<NativePoly>::Encrypt(
    const LPPrivateKey<NativePoly> privateKey, NativePoly ptxt) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmCKKS<Poly>::Encrypt(
    const LPPrivateKey<Poly> privateKey, Poly ptxt) const {
  NOPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmCKKS<DCRTPoly>::Encrypt(
    const LPPrivateKey<DCRTPoly> privateKey, DCRTPoly ptxt) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          privateKey->GetCryptoParameters());

  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));

  const shared_ptr<ParmType> ptxtParams = ptxt.GetParams();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

  ptxt.SetFormat(Format::EVALUATION);

  std::vector<DCRTPoly> cv;

  DCRTPoly e(dgg, ptxtParams, Format::EVALUATION);

  const DCRTPoly &s = privateKey->GetPrivateElement();
  uint32_t sizeQl = ptxtParams->GetParams().size();
  uint32_t sizeQ = s.GetParams()->GetParams().size();

  DugType dug;
  DCRTPoly a(dug, ptxtParams, Format::EVALUATION);

  DCRTPoly c0, c1;
  if (sizeQl != sizeQ) {
    uint32_t diffQl = sizeQ - sizeQl;

    DCRTPoly scopy(s);
    scopy.DropLastElements(diffQl);

    c0 = a * scopy + e + ptxt;
    c1 = -a;
  } else {
    // Use secret key as is
    c0 = a * s + e + ptxt;
    c1 = -a;
  }

  cv.push_back(std::move(c0));
  cv.push_back(std::move(c1));

  ciphertext->SetElements(std::move(cv));

  // Ciphertext depth, level, and scaling factor should be
  // equal to that of the plaintext. However, Encrypt does
  // not take Plaintext as input (only DCRTPoly), so we
  // don't have access to these here, and we set them in
  // the crypto context Encrypt method.
  ciphertext->SetDepth(1);

  return ciphertext;
}

template <>
DecryptResult LPAlgorithmCKKS<NativePoly>::Decrypt(
    const LPPrivateKey<NativePoly> privateKey,
    ConstCiphertext<NativePoly> ciphertext, Poly *plaintext) const {
  std::string errMsg =
      "CKKS: Decryption to Poly from NativePoly is not supported as it may "
      "lead to incorrect results.";
  PALISADE_THROW(not_available_error, errMsg);
}

template <>
DecryptResult LPAlgorithmCKKS<Poly>::Decrypt(
    const LPPrivateKey<Poly> privateKey, ConstCiphertext<Poly> ciphertext,
    Poly *plaintext) const {
  const shared_ptr<LPCryptoParameters<Poly>> cryptoParams =
      privateKey->GetCryptoParameters();

  const std::vector<Poly> &cv = ciphertext->GetElements();
  const Poly &s = privateKey->GetPrivateElement();

  Poly sPower(s);

  Poly b(cv[0]);
  b.SetFormat(Format::EVALUATION);

  Poly ci;
  for (size_t i = 1; i < cv.size(); i++) {
    ci = cv[i];
    ci.SetFormat(Format::EVALUATION);

    b += sPower * ci;
    sPower *= s;
  }

  b.SwitchFormat();

  *plaintext = std::move(b);

  return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmCKKS<Poly>::Decrypt(
    const LPPrivateKey<Poly> privateKey, ConstCiphertext<Poly> ciphertext,
    NativePoly *plaintext) const {
  const shared_ptr<LPCryptoParameters<Poly>> cryptoParams =
      privateKey->GetCryptoParameters();

  const std::vector<Poly> &cv = ciphertext->GetElements();
  const Poly &s = privateKey->GetPrivateElement();

  Poly sPower(s);

  Poly b(cv[0]);
  b.SetFormat(Format::EVALUATION);

  Poly ci;
  for (size_t i = 1; i < cv.size(); i++) {
    ci = cv[i];
    ci.SetFormat(Format::EVALUATION);

    b += sPower * ci;
    sPower *= s;
  }

  b.SetFormat(Format::COEFFICIENT);

  *plaintext = b.ToNativePoly();

  return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmCKKS<NativePoly>::Decrypt(
    const LPPrivateKey<NativePoly> privateKey,
    ConstCiphertext<NativePoly> ciphertext, NativePoly *plaintext) const {
  const shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams =
      privateKey->GetCryptoParameters();

  const std::vector<NativePoly> &cv = ciphertext->GetElements();
  const NativePoly &s = privateKey->GetPrivateElement();

  NativePoly sPower(s);

  NativePoly b(cv[0]);
  b.SetFormat(Format::EVALUATION);

  NativePoly ci;
  for (size_t i = 1; i < cv.size(); i++) {
    ci = cv[i];
    ci.SetFormat(Format::EVALUATION);

    b += sPower * ci;
    sPower *= s;
  }

  b.SetFormat(Format::COEFFICIENT);

  *plaintext = std::move(b);

  return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmCKKS<DCRTPoly>::Decrypt(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext, Poly *plaintext) const {
  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      privateKey->GetCryptoParameters();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  const DCRTPoly &s = privateKey->GetPrivateElement();

  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t sizeQ = s.GetParams()->GetParams().size();

  size_t diffQl = sizeQ - sizeQl;

  auto scopy(s);
  scopy.DropLastElements(diffQl);

  DCRTPoly sPower(scopy);

  DCRTPoly b(cv[0]);
  b.SetFormat(Format::EVALUATION);

  DCRTPoly ci;
  for (size_t i = 1; i < cv.size(); i++) {
    ci = cv[i];
    ci.SetFormat(Format::EVALUATION);

    b += sPower * ci;
    sPower *= scopy;
  }

  b.SetFormat(Format::COEFFICIENT);

  if (sizeQl > 1) {
    *plaintext = b.CRTInterpolate();
  } else if (sizeQl == 1) {
    *plaintext = Poly(b.GetElementAtIndex(0), Format::COEFFICIENT);
  } else {
    PALISADE_THROW(
        math_error,
        "Decryption failure: No towers left; consider increasing the depth.");
  }

  return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmCKKS<DCRTPoly>::Decrypt(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext, NativePoly *plaintext) const {
  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      privateKey->GetCryptoParameters();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  const DCRTPoly &s = privateKey->GetPrivateElement();

  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t sizeQ = s.GetParams()->GetParams().size();

  size_t diffQl = sizeQ - sizeQl;

  auto scopy(s);
  scopy.DropLastElements(diffQl);

  DCRTPoly sPower(scopy);

  DCRTPoly b(cv[0]);
  b.SetFormat(Format::EVALUATION);

  DCRTPoly ci;
  for (size_t i = 1; i < cv.size(); i++) {
    ci = cv[i];
    ci.SetFormat(Format::EVALUATION);

    b += sPower * ci;
    sPower *= scopy;
  }

  b.SetFormat(Format::COEFFICIENT);

  if (sizeQl == 1)
    *plaintext = b.GetElementAtIndex(0);
  else
    PALISADE_THROW(
        math_error,
        "Decryption failure: No towers left; consider increasing the depth.");

  return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmMultipartyCKKS<NativePoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<NativePoly>> &ciphertextVec,
    Poly *plaintext) const {
  std::string errMsg =
      "CKKS: Decryption to Poly from NativePoly is not supported as it may "
      "lead to incorrect results.";
  PALISADE_THROW(not_available_error, errMsg);
}

template <>
DecryptResult LPAlgorithmMultipartyCKKS<Poly>::MultipartyDecryptFusion(
    const vector<Ciphertext<Poly>> &ciphertextVec, Poly *plaintext) const {
  const shared_ptr<LPCryptoParameters<Poly>> cryptoParams =
      ciphertextVec[0]->GetCryptoParameters();
  // const auto p = cryptoParams->GetPlaintextModulus();

  const std::vector<Poly> &cv0 = ciphertextVec[0]->GetElements();
  Poly b = cv0[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<Poly> &cvi = ciphertextVec[i]->GetElements();
    b += cvi[0];
  }

  b.SwitchFormat();

  *plaintext = b.CRTInterpolate();

  return DecryptResult(plaintext->GetLength());
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchHybridGen(
    const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  auto cc = newKey->GetCryptoContext();
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          newKey->GetCryptoParameters());

  const shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
  const shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

  usint sizeQ = paramsQ->GetParams().size();
  usint sizeQP = paramsQP->GetParams().size();

  DCRTPoly sOld = oldKey->GetPrivateElement();
  DCRTPoly sNew = newKey->GetPrivateElement().Clone();

  // skNew is currently in basis Q. This extends it to basis QP.
  sNew.SetFormat(Format::COEFFICIENT);

  DCRTPoly sNewExt(paramsQP, Format::COEFFICIENT, true);

  // The part with basis Q
  for (usint i = 0; i < sizeQ; i++) {
    sNewExt.SetElementAtIndex(i, sNew.GetElementAtIndex(i));
  }

  // The part with basis P
  for (usint j = sizeQ; j < sizeQP; j++) {
    const NativeInteger &pj = paramsQP->GetParams()[j]->GetModulus();
    const NativeInteger &rootj = paramsQP->GetParams()[j]->GetRootOfUnity();
    auto sNew0 = sNew.GetElementAtIndex(0);
    sNew0.SwitchModulus(pj, rootj);
    sNewExt.SetElementAtIndex(j, std::move(sNew0));
  }

  sNewExt.SetFormat(Format::EVALUATION);

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;

  auto numPartQ = cryptoParams->GetNumPartQ();
  vector<DCRTPoly> av(numPartQ);
  vector<DCRTPoly> bv(numPartQ);

  vector<NativeInteger> PModq = cryptoParams->GetPModq();
  vector<vector<NativeInteger>> PartQHatModq = cryptoParams->GetPartQHatModq();

  for (usint part = 0; part < numPartQ; part++) {
    DCRTPoly a;
    if (ekPrev == nullptr) {  // single-key HE
      a = DCRTPoly(dug, paramsQP, Format::EVALUATION);
    } else {  // threshold HE
      a = ekPrev->GetAVector()[part];
    }
    DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
    DCRTPoly b(paramsQP, Format::EVALUATION, true);

    // The part with basis Q
    for (usint i = 0; i < sizeQ; i++) {
      const NativeInteger &qi = paramsQ->GetParams()[i]->GetModulus();
      auto ai = a.GetElementAtIndex(i);
      auto ei = e.GetElementAtIndex(i);
      auto sNewi = sNewExt.GetElementAtIndex(i);
      auto sOldi = sOld.GetElementAtIndex(i);
      auto factor = PModq[i].ModMulFast(PartQHatModq[part][i], qi);
      b.SetElementAtIndex(i, -ai * sNewi + factor * sOldi + ei);
    }

    // The part with basis P
    for (usint j = sizeQ; j < sizeQP; j++) {
      auto aj = a.GetElementAtIndex(j);
      auto ej = e.GetElementAtIndex(j);
      auto sNewExtj = sNewExt.GetElementAtIndex(j);
      b.SetElementAtIndex(j, -aj * sNewExtj + ej);
    }

    av[part] = a;
    bv[part] = b;
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <>
void LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchHybridInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly> &ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ek->GetCryptoParameters());

  LPEvalKeyRelin<DCRTPoly> evalKey =
      std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  const std::vector<DCRTPoly> &bv = evalKey->GetBVector();
  const std::vector<DCRTPoly> &av = evalKey->GetAVector();

  const shared_ptr<ParmType> paramsQl = cv[0].GetParams();
  const shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
  const shared_ptr<ParmType> paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);

  size_t sizeQl = paramsQl->GetParams().size();
  size_t sizeP = paramsP->GetParams().size();
  size_t sizeQlP = sizeQl + sizeP;
  size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();

  // size = 2 : case of PRE or automorphism
  // size = 3 : case of EvalMult
  DCRTPoly c(cv[cv.size() - 1]);

  uint32_t alpha = cryptoParams->GetNumPerPartQ();
  uint32_t numPartQl = ceil((static_cast<double>(sizeQl)) / alpha);
  // The number of digits of the current ciphertext
  // uint32_t digits = cryptoParamsLWE->GetNumberOfDigits();
  if (numPartQl > cryptoParams->GetNumberOfQPartitions())
    numPartQl = cryptoParams->GetNumberOfQPartitions();

  vector<DCRTPoly> partsCt(numPartQl);

  // Digit decomposition
  // Zero-padding and split
  for (uint32_t part = 0; part < numPartQl; part++) {
    if (part == numPartQl - 1) {
      auto paramsPartQj = cryptoParams->GetParamsPartQ(numPartQl - 1);

      uint32_t sizeLastPartQl = sizeQl - alpha * part;

      vector<NativeInteger> moduli(sizeLastPartQl);
      vector<NativeInteger> roots(sizeLastPartQl);

      for (uint32_t i = 0; i < sizeLastPartQl; i++) {
        moduli[i] = paramsPartQj->GetParams()[i]->GetModulus();
        roots[i] = paramsPartQj->GetParams()[i]->GetRootOfUnity();
      }

      auto params = DCRTPoly::Params(paramsPartQj->GetCyclotomicOrder(), moduli,
                                     roots, {}, {}, 0);

      partsCt[part] = DCRTPoly(std::make_shared<ParmType>(params),
                               Format::EVALUATION, true);
    } else {
      partsCt[part] = DCRTPoly(cryptoParams->GetParamsPartQ(part),
                               Format::EVALUATION, true);
    }

    const vector<NativeInteger> &QHatInvModq =
        cryptoParams->GetPartQHatInvModq(part);

    usint sizePartQl = partsCt[part].GetNumOfElements();
    usint startPartIdx = alpha * part;
    for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; i++, idx++) {
      auto tmp = c.GetElementAtIndex(idx).Times(QHatInvModq[idx]);
      partsCt[part].SetElementAtIndex(i, std::move(tmp));
    }
  }

  vector<DCRTPoly> partsCtCompl(numPartQl);
  vector<DCRTPoly> partsCtExt(numPartQl);
  for (uint32_t part = 0; part < numPartQl; part++) {
    auto partCtClone = partsCt[part].Clone();
    partCtClone.SetFormat(Format::COEFFICIENT);

    const shared_ptr<ParmType> paramsComplPartQ =
        cryptoParams->GetParamsComplPartQ(sizeQl - 1, part);

    usint sizePartQl = partsCt[part].GetNumOfElements();
    partsCtCompl[part] = partCtClone.ApproxSwitchCRTBasis(
        cryptoParams->GetParamsPartQ(part), paramsComplPartQ,
        cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1),
        cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1),
        cryptoParams->GetPartQlHatModp(sizeQl - 1, part),
        cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part));

    partsCtCompl[part].SetFormat(Format::EVALUATION);

    partsCtExt[part] = DCRTPoly(paramsQlP, Format::EVALUATION, true);

    usint startPartIdx = alpha * part;
    usint endPartIdx = startPartIdx + sizePartQl;
    for (usint i = 0; i < startPartIdx; i++) {
      partsCtExt[part].SetElementAtIndex(
          i, partsCtCompl[part].GetElementAtIndex(i));
    }
    for (usint i = startPartIdx, idx = 0; i < endPartIdx; i++, idx++) {
      partsCtExt[part].SetElementAtIndex(i,
                                         partsCt[part].GetElementAtIndex(idx));
    }
    for (usint i = endPartIdx; i < sizeQlP; ++i) {
      partsCtExt[part].SetElementAtIndex(
          i, partsCtCompl[part].GetElementAtIndex(i - sizePartQl));
    }
  }

  DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
  DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);

  for (uint32_t j = 0; j < numPartQl; j++) {
    const DCRTPoly &cj = partsCtExt[j];
    const DCRTPoly &bj = bv[j];
    const DCRTPoly &aj = av[j];

    for (usint i = 0; i < sizeQl; i++) {
      const auto &cji = cj.GetElementAtIndex(i);
      const auto &aji = aj.GetElementAtIndex(i);
      const auto &bji = bj.GetElementAtIndex(i);

      cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
      cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
    }

    for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; i++, idx++) {
      const auto &cji = cj.GetElementAtIndex(i);
      const auto &aji = aj.GetElementAtIndex(idx);
      const auto &bji = bj.GetElementAtIndex(idx);

      cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
      cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
    }
  }

  // cTilda0.SetFormat(Format::COEFFICIENT);
  // cTilda1.SetFormat(Format::COEFFICIENT);

  DCRTPoly ct0 = cTilda0.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu());

  DCRTPoly ct1 = cTilda1.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu());

  // ct0.SetFormat(Format::EVALUATION);
  // ct1.SetFormat(Format::EVALUATION);

  ct0 += cv[0];
  // case of EvalMult
  if (cv.size() > 2) {
    ct1 += cv[1];
  }

  ciphertext->SetElements({std::move(ct0), std::move(ct1)});
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchGHSGen(
    const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  auto cc = newKey->GetCryptoContext();
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          newKey->GetCryptoParameters());

  const shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
  const shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

  usint sizeQ = paramsQ->GetParams().size();
  usint sizeQP = paramsQP->GetParams().size();

  DCRTPoly sOld = oldKey->GetPrivateElement();
  DCRTPoly sNew = newKey->GetPrivateElement().Clone();

  // skNew is currently in basis Q. This extends it to basis QP.
  sNew.SetFormat(Format::COEFFICIENT);
  DCRTPoly sNewExt(paramsQP, Format::COEFFICIENT, true);

  // The part with basis Q
  for (usint i = 0; i < sizeQ; i++) {
    sNewExt.SetElementAtIndex(i, sNew.GetElementAtIndex(i));
  }

  // The part with basis P
  for (usint i = sizeQ; i < sizeQP; i++) {
    NativeInteger qi = paramsQP->GetParams()[i]->GetModulus();
    NativeInteger rooti = paramsQP->GetParams()[i]->GetRootOfUnity();
    auto sNew0 = sNew.GetElementAtIndex(0);
    sNew0.SwitchModulus(qi, rooti);
    sNewExt.SetElementAtIndex(i, std::move(sNew0));
  }

  sNewExt.SetFormat(Format::EVALUATION);

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;

  DCRTPoly a;
  if (ekPrev == nullptr) {  // single-key HE
    a = DCRTPoly(dug, paramsQP, Format::EVALUATION);
  } else {  // threshold FHE
    a = ekPrev->GetAVector()[0];
  }

  const DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
  DCRTPoly b(paramsQP, Format::EVALUATION, true);

  vector<NativeInteger> PModq = cryptoParams->GetPModq();

  // The part with basis Q
  for (usint i = 0; i < sizeQ; i++) {
    auto ai = a.GetElementAtIndex(i);
    auto ei = e.GetElementAtIndex(i);
    auto sNewi = sNewExt.GetElementAtIndex(i);
    auto sOldi = sOld.GetElementAtIndex(i);
    b.SetElementAtIndex(i, -ai * sNewi + PModq[i] * sOldi + ei);
  }

  // The part with basis P
  for (usint i = sizeQ; i < sizeQP; i++) {
    auto ai = a.GetElementAtIndex(i);
    auto ei = e.GetElementAtIndex(i);
    auto sNewExti = sNewExt.GetElementAtIndex(i);
    b.SetElementAtIndex(i, -ai * sNewExti + ei);
  }

  vector<DCRTPoly> av = {a};
  vector<DCRTPoly> bv = {b};

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <>
void LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchGHSInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly> &ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ek->GetCryptoParameters());

  LPEvalKeyRelin<DCRTPoly> evalKey =
      std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  const std::vector<DCRTPoly> &bv = evalKey->GetBVector();
  const std::vector<DCRTPoly> &av = evalKey->GetAVector();

  const shared_ptr<ParmType> paramsQl = cv[0].GetParams();
  const shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
  const shared_ptr<ParmType> paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);

  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t sizeQlP = paramsQlP->GetParams().size();
  size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();

  // size = 2 : case of PRE or automorphism
  // size = 3 : case of EvalMult
  DCRTPoly cExt(cv[cv.size() - 1]);

  size_t lvl = sizeQl - 1;
  cExt.ApproxModUp(
      paramsQl, paramsP, paramsQlP, cryptoParams->GetQlHatInvModq(lvl),
      cryptoParams->GetQlHatInvModqPrecon(lvl), cryptoParams->GetQlHatModp(lvl),
      cryptoParams->GetModpBarrettMu());

  DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
  DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);

  const auto &b0 = bv[0];
  const auto &a0 = av[0];

  for (usint i = 0; i < sizeQl; i++) {
    const auto &b0i = b0.GetElementAtIndex(i);
    const auto &a0i = a0.GetElementAtIndex(i);
    const auto &ci = cExt.GetElementAtIndex(i);

    cTilda0.SetElementAtIndex(i, ci * b0i);
    cTilda1.SetElementAtIndex(i, ci * a0i);
  }

  for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; i++, idx++) {
    const auto &b0i = b0.GetElementAtIndex(idx);
    const auto &a0i = a0.GetElementAtIndex(idx);
    const auto &ci = cExt.GetElementAtIndex(i);

    cTilda0.SetElementAtIndex(i, ci * b0i);
    cTilda1.SetElementAtIndex(i, ci * a0i);
  }

  // cTilda0.SetFormat(Format::COEFFICIENT);
  // cTilda1.SetFormat(Format::COEFFICIENT);

  DCRTPoly ct0 = cTilda0.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu());

  DCRTPoly ct1 = cTilda1.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu());

  // ct0.SetFormat(Format::EVALUATION);
  // ct1.SetFormat(Format::EVALUATION);

  ct0 += cv[0];
  // case of EvalMult
  if (cv.size() > 2) {
    ct1 += cv[1];
  }

  ciphertext->SetElements({std::move(ct0), std::move(ct1)});
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchBVGen(
    const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  LPEvalKeyRelin<DCRTPoly> ek(std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(
      newKey->GetCryptoContext()));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          newKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  const DCRTPoly &sNew = newKey->GetPrivateElement();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

  DCRTPoly sOld = oldKey->GetPrivateElement();

  sOld.DropLastElements(oldKey->GetCryptoContext()->GetKeyGenLevel());

  usint sizeSOld = sOld.GetNumOfElements();
  usint nWindows = 0;
  uint32_t relinWindow = cryptoParams->GetRelinWindow();

  // used to store the number of digits for each small modulus
  std::vector<usint> arrWindows;

  if (relinWindow > 0) {
    // creates an array of digits up to a certain tower
    for (usint i = 0; i < sizeSOld; i++) {
      usint sOldMSB =
          sOld.GetElementAtIndex(i).GetModulus().GetLengthForBase(2);
      usint curWindows = sOldMSB / relinWindow;
      if (sOldMSB % relinWindow > 0) curWindows++;
      arrWindows.push_back(nWindows);
      nWindows += curWindows;
    }
  } else {
    nWindows = sizeSOld;
  }

  std::vector<DCRTPoly> av(nWindows);
  std::vector<DCRTPoly> bv(nWindows);

#pragma omp parallel for
  for (usint i = 0; i < sizeSOld; i++) {
    DugType dug;

    if (relinWindow > 0) {
      vector<typename DCRTPoly::PolyType> sOldDecomposed =
          sOld.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (size_t k = 0; k < sOldDecomposed.size(); k++) {
        // Creates an element with all zeroes
        DCRTPoly filtered(elementParams, Format::EVALUATION, true);

        filtered.SetElementAtIndex(i, sOldDecomposed[k]);

        if (ekPrev == nullptr) {  // single-key HE
          // Generate a_i vectors
          DCRTPoly a(dug, elementParams, Format::EVALUATION);
          av[k + arrWindows[i]] = a;
        } else {  // threshold HE
          av[k + arrWindows[i]] = ekPrev->GetAVector()[k + arrWindows[i]];
        }

        // Generate a_i * skNew + e - skOld_k
        DCRTPoly e(dgg, elementParams, Format::EVALUATION);
        bv[k + arrWindows[i]] = filtered - (av[k + arrWindows[i]] * sNew + e);
      }
    } else {
      // Creates an element with all zeroes
      DCRTPoly filtered(elementParams, Format::EVALUATION, true);

      filtered.SetElementAtIndex(i, sOld.GetElementAtIndex(i));

      if (ekPrev == nullptr) {  // single-key HE
        // Generate a_i vectors
        DCRTPoly a(dug, elementParams, Format::EVALUATION);
        av[i] = a;
      } else {  // threshold HE
        av[i] = ekPrev->GetAVector()[i];
      }

      // Generate a_i * skNew + e - skOld
      DCRTPoly e(dgg, elementParams, Format::EVALUATION);
      bv[i] = filtered - (av[i] * sNew + e);
    }
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <>
void LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchBVInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly> &ciphertext) const {
  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ek->GetCryptoParameters());

  LPEvalKeyRelin<DCRTPoly> evalKey =
      std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

  std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  std::vector<DCRTPoly> bv = evalKey->GetBVector();
  std::vector<DCRTPoly> av = evalKey->GetAVector();

  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t sizeQ = bv[0].GetParams()->GetParams().size();

  size_t diffQl = sizeQ - sizeQl;

  for (size_t k = 0; k < bv.size(); k++) {
    av[k].DropLastElements(diffQl);
    bv[k].DropLastElements(diffQl);
  }

  uint32_t relinWindow = cryptoParams->GetRelinWindow();

  cv[0].SetFormat(Format::EVALUATION);

  std::vector<DCRTPoly> digitsC2;
  if (cv.size() == 2) {
    // case of PRE or automorphism
    digitsC2 = cv[1].CRTDecompose(relinWindow);
    cv[1] = (av[0] *= digitsC2[0]);
  } else {
    // case of EvalMult
    digitsC2 = cv[2].CRTDecompose(relinWindow);
    cv[1].SetFormat(Format::EVALUATION);
    cv[1] += (av[0] *= digitsC2[0]);
  }

  cv[0] += (bv[0] *= digitsC2[0]);
  for (usint i = 1; i < digitsC2.size(); ++i) {
    cv[0] += (bv[i] *= digitsC2[i]);
    cv[1] += (av[i] *= digitsC2[i]);
  }
  cv.resize(2);
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchGen(
    const LPPrivateKey<DCRTPoly> oldKey,
    const LPPrivateKey<DCRTPoly> newKey) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          newKey->GetCryptoParameters());

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    return KeySwitchBVGen(oldKey, newKey);
  } else if (cryptoParams->GetKeySwitchTechnique() == GHS) {
    return KeySwitchGHSGen(oldKey, newKey);
  } else {  // Hybrid
    return KeySwitchHybridGen(oldKey, newKey);
  }
}

template <>
void LPAlgorithmSHECKKS<DCRTPoly>::KeySwitchInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly> &ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    KeySwitchBVInPlace(ek, ciphertext);
  } else if (cryptoParams->GetKeySwitchTechnique() == GHS) {
    KeySwitchGHSInPlace(ek, ciphertext);
  } else {  // Hybrid
    KeySwitchHybridInPlace(ek, ciphertext);
  }
}

template <>
void LPLeveledSHEAlgorithmCKKS<Poly>::ModReduceInternalInPlace(
    Ciphertext<Poly> &ciphertext, size_t levels) const {
  NOPOLY
}

template <>
void LPLeveledSHEAlgorithmCKKS<NativePoly>::ModReduceInternalInPlace(
    Ciphertext<NativePoly> &ciphertext, size_t levels) const {
  NONATIVEPOLY
}

template <>
void LPLeveledSHEAlgorithmCKKS<DCRTPoly>::ModReduceInternalInPlace(
    Ciphertext<DCRTPoly> &ciphertext, size_t levels) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
  size_t sizeQl = cv[0].GetNumOfElements();
  size_t diffQl = sizeQ - sizeQl;

  const vector<NativeInteger> &QlQlInvModqlDivqlModq =
      cryptoParams->GetQlQlInvModqlDivqlModq(diffQl);
  const vector<NativeInteger> &QlQlInvModqlDivqlModqPrecon =
      cryptoParams->GetQlQlInvModqlDivqlModqPrecon(diffQl);
  const vector<NativeInteger> &qInvModq = cryptoParams->GetqInvModq(diffQl);
  const vector<NativeInteger> &qInvModqPrecon =
      cryptoParams->GetqInvModqPrecon(diffQl);

  for (size_t i = 0; i < cv.size(); i++) {
    cv[i].DropLastElementAndScale(QlQlInvModqlDivqlModq,
                                  QlQlInvModqlDivqlModqPrecon, qInvModq,
                                  qInvModqPrecon);
  }
  ciphertext->SetDepth(ciphertext->GetDepth() - 1);
  double modReduceFactor = cryptoParams->GetModReduceFactor(sizeQl - 1);
  ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() /
                               modReduceFactor);
  ciphertext->SetLevel(ciphertext->GetLevel() + 1);
}

template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmCKKS<Poly>::ModReduceInternal(
    ConstCiphertext<Poly> ciphertext, size_t levels) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPLeveledSHEAlgorithmCKKS<NativePoly>::ModReduceInternal(
    ConstCiphertext<NativePoly> ciphertext, size_t levels) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmCKKS<DCRTPoly>::ModReduceInternal(
    ConstCiphertext<DCRTPoly> ciphertext, size_t levels) const {
  Ciphertext<DCRTPoly> result = ciphertext->Clone();
  ModReduceInternalInPlace(result, levels);
  return result;
}

template <>
void LPLeveledSHEAlgorithmCKKS<DCRTPoly>::ModReduceInPlace(
    Ciphertext<DCRTPoly> &ciphertext, size_t levels) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    ModReduceInternalInPlace(ciphertext, levels);
  }
  // In EXACTRESCALE & APPROXAUTO rescaling is performed automatically
}

template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmCKKS<Poly>::Compress(
    ConstCiphertext<Poly> ciphertext, size_t towersLeft) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPLeveledSHEAlgorithmCKKS<NativePoly>::Compress(
    ConstCiphertext<NativePoly> ciphertext, size_t towersLeft) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmCKKS<DCRTPoly>::Compress(
    ConstCiphertext<DCRTPoly> ciphertext, size_t towersLeft) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  Ciphertext<DCRTPoly> result =
      std::make_shared<CiphertextImpl<DCRTPoly>>(*ciphertext);

  while (result->GetDepth() > 1) {
    ModReduceInternalInPlace(result);
  }

  const std::vector<DCRTPoly> &cv = result->GetElements();
  usint sizeQl = cv[0].GetNumOfElements();

  if (towersLeft >= sizeQl) {
    return result;
  }

  CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
  auto algo = cc->GetEncryptionAlgorithm();
  if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE) {
    const shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
    usint sizeQ = paramsQ->GetParams().size();
    result = algo->AdjustLevelWithRescale(result, sizeQ - towersLeft);
    return result;
  }

  result = algo->LevelReduceInternal(result, nullptr, sizeQl - towersLeft);
  return result;
}

template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmCKKS<Poly>::LevelReduceInternal(
    ConstCiphertext<Poly> ciphertext, const LPEvalKey<Poly> linearKeySwitchHint,
    size_t levels) const {
  NOPOLY
}

template <>
void LPLeveledSHEAlgorithmCKKS<Poly>::LevelReduceInternalInPlace(
    Ciphertext<Poly> &ciphertext, const LPEvalKey<Poly> linearKeySwitchHint,
    size_t levels) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly>
LPLeveledSHEAlgorithmCKKS<NativePoly>::LevelReduceInternal(
    ConstCiphertext<NativePoly> ciphertext,
    const LPEvalKey<NativePoly> linearKeySwitchHint, size_t levels) const {
  NONATIVEPOLY
}

template <>
void LPLeveledSHEAlgorithmCKKS<NativePoly>::LevelReduceInternalInPlace(
    Ciphertext<NativePoly> &ciphertext,
    const LPEvalKey<NativePoly> linearKeySwitchHint, size_t levels) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmCKKS<DCRTPoly>::LevelReduceInternal(
    ConstCiphertext<DCRTPoly> ciphertext,
    const LPEvalKey<DCRTPoly> linearKeySwitchHint, size_t levels) const {
  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  vector<DCRTPoly> cvLevelReduced(ciphertext->GetElements());

  for (size_t i = 0; i < cvLevelReduced.size(); i++) {
    cvLevelReduced[i].DropLastElements(levels);
  }

  result->SetElements(std::move(cvLevelReduced));

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel() + levels);
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <>
void LPLeveledSHEAlgorithmCKKS<DCRTPoly>::LevelReduceInternalInPlace(
    Ciphertext<DCRTPoly> &ciphertext,
    const LPEvalKey<DCRTPoly> linearKeySwitchHint, size_t levels) const {
  size_t new_level = ciphertext->GetLevel() + levels;

  std::vector<DCRTPoly> &elements = ciphertext->GetElements();
  for (auto &element : elements) {
    element.DropLastElements(levels);
  }
  ciphertext->SetLevel(new_level);
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmCKKS<DCRTPoly>::LevelReduce(
    ConstCiphertext<DCRTPoly> ciphertext,
    const LPEvalKey<DCRTPoly> linearKeySwitchHint, size_t levels) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return LevelReduceInternal(ciphertext, linearKeySwitchHint, levels);
  }

  // In EXACTRESCALE & APPROXAUTO level reduce is performed automatically
  return std::make_shared<CiphertextImpl<DCRTPoly>>(*ciphertext);
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmCKKS<DCRTPoly>::EvalPoly(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients) const {
  if (coefficients[coefficients.size() - 1] == 0)
    PALISADE_THROW(
        math_error,
        "EvalPoly: The highest-order coefficient cannot be set to 0.");

  std::vector<Ciphertext<DCRTPoly>> powers(coefficients.size() - 1);
  std::vector<int32_t> indices(coefficients.size() - 1, 0);

  // set the indices for the powers of x that need to be computed to 1
  for (size_t i = coefficients.size() - 1; i > 0; i--) {
    if (IsPowerOfTwo(i)) {
      indices[i - 1] = 1;
    } else {  // non-power of 2
      if (coefficients[i] != 0) {
        indices[i - 1] = 1;
        int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
        int64_t rem = i % powerOf2;
        if (indices[rem - 1] == 0) indices[rem - 1] = 1;
        // while rem is not a power of 2, set indices required to compute rem to
        // 1
        while (!IsPowerOfTwo(rem)) {
          powerOf2 = 1 << (int64_t)std::floor(std::log2(rem));
          rem = rem % powerOf2;
          if (indices[rem - 1] == 0) indices[rem - 1] = 1;
        }
      }
    }
  }

  powers[0] = Ciphertext<DCRTPoly>(new CiphertextImpl<DCRTPoly>(*x));

  auto cc = x->GetCryptoContext();

  // computes all powers for x
  for (size_t i = 2; i < coefficients.size(); i++) {
    if (IsPowerOfTwo(i)) {
      powers[i - 1] = cc->EvalMult(powers[i / 2 - 1], powers[i / 2 - 1]);
      cc->ModReduceInPlace(powers[i - 1]);
    } else {  // non-power of 2
      if (indices[i - 1] == 1) {
        int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
        int64_t rem = i % powerOf2;

        int levelDiff =
            powers[powerOf2 - 1]->GetElements()[0].GetNumOfElements() -
            powers[rem - 1]->GetElements()[0].GetNumOfElements();
        for (int idx = 0; idx < levelDiff; idx++) {
          powers[rem - 1] = cc->LevelReduce(powers[rem - 1], nullptr);
        }

        powers[i - 1] = cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]);
        cc->ModReduceInPlace(powers[i - 1]);
      }
    }
  }

  // gets the highest depth (lowest number of CRT limbs)
  int64_t limbs =
      powers[coefficients.size() - 2]->GetElements()[0].GetNumOfElements();

  // brings all powers of x to the same level
  for (size_t i = 1; i < coefficients.size() - 1; i++) {
    if (indices[i - 1] == 1) {
      int levelDiff =
          limbs - powers[i - 1]->GetElements()[0].GetNumOfElements();
      for (int idx = 0; idx < levelDiff; idx++) {
        powers[i - 1] = cc->LevelReduce(powers[i - 1], nullptr);
      }
    }
  }

  // perform scalar multiplication for the highest-order term
  auto result = cc->EvalMult(powers[coefficients.size() - 2],
                             coefficients[coefficients.size() - 1]);

  // perform scalar multiplication for all other terms and sum them up
  for (size_t i = 0; i < coefficients.size() - 2; i++) {
    if (coefficients[i + 1] != 0) {
      result =
          cc->EvalAdd(result, cc->EvalMult(powers[i], coefficients[i + 1]));
    }
  }

  // Do rescaling after scalar multiplication
  result = cc->ModReduce(result);

  // adds the free term (at x^0)
  if (coefficients[0] != 0) {
    if (coefficients[0] < 0)
      result = cc->EvalSub(result, std::fabs(coefficients[0]));
    else
      result = cc->EvalAdd(result, coefficients[0]);
  }

  return result;
}

#if NATIVEINT == 128
template <>
vector<DCRTPoly::Integer>
LPAlgorithmSHECKKS<DCRTPoly>::GetElementForEvalAddOrSub(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
      std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  uint32_t precision = 52;
  double powP = std::pow(2, precision);

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  usint numTowers = cv[0].GetNumOfElements();
  vector<DCRTPoly::Integer> moduli(numTowers);

  for (usint i = 0; i < numTowers; i++) {
    moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
  }

  // the idea is to break down real numbers
  // expressed as input_mantissa * 2^input_exponent
  // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
  // to preserve 52-bit precision of doubles
  // when converting to 128-bit numbers
  int32_t n1 = 0;
  int64_t scaled64 =
      std::llround(static_cast<double>(std::frexp(constant, &n1)) * powP);

  int32_t pCurrent = cryptoParams->GetPlaintextModulus() - precision;
  int32_t pRemaining = pCurrent + n1;

  DCRTPoly::Integer scaledConstant;
  if (pRemaining < 0) {
    scaledConstant =
        NativeInteger(((unsigned __int128)scaled64) >> (-pRemaining));
  } else {
    __int128 ppRemaining = ((__int128)1) << pRemaining;
    scaledConstant = NativeInteger((unsigned __int128)scaled64 * ppRemaining);
  }

  DCRTPoly::Integer intPowP;
  int64_t powp64 = ((int64_t)1) << precision;
  if (pCurrent < 0) {
    intPowP = NativeInteger((unsigned __int128)powp64 >> (-pCurrent));
  } else {
    intPowP = NativeInteger((unsigned __int128)powp64 << pCurrent);
  }

  vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);
  vector<DCRTPoly::Integer> currPowP(numTowers, scaledConstant);

  // multiply c*powP with powP a total of (depth-1) times to get c*powP^d
  for (size_t i = 0; i < ciphertext->GetDepth() - 1; i++) {
    currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
  }

  return currPowP;
}
#else  // NATIVEINT == 64
template <>
vector<DCRTPoly::Integer>
LPAlgorithmSHECKKS<DCRTPoly>::GetElementForEvalAddOrSub(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  usint sizeQl = cv[0].GetNumOfElements();
  vector<DCRTPoly::Integer> moduli(sizeQl);
  for (usint i = 0; i < sizeQl; i++) {
    moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
  }

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());
  double scFactor =
      cryptoParams->GetScalingFactorOfLevel(ciphertext->GetLevel());

  DCRTPoly::Integer intScFactor = static_cast<uint64_t>(scFactor + 0.5);
  DCRTPoly::Integer scConstant =
      static_cast<uint64_t>(constant * scFactor + 0.5);

  vector<DCRTPoly::Integer> crtScFactor(sizeQl, intScFactor);
  vector<DCRTPoly::Integer> crtConstant(sizeQl, scConstant);

  for (usint i = 0; i < ciphertext->GetDepth() - 1; i++) {
    crtConstant = CKKSPackedEncoding::CRTMult(crtConstant, crtScFactor, moduli);
  }

  return crtConstant;
}
#endif

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAdd(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  std::vector<DCRTPoly> cNew(ciphertext->GetElements());
  cNew[0] = cNew[0] + GetElementForEvalAddOrSub(ciphertext, constant);

  Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetElements(std::move(cNew));
  newCiphertext->SetDepth(ciphertext->GetDepth());
  newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());
  newCiphertext->SetLevel(ciphertext->GetLevel());

  return newCiphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSub(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  std::vector<DCRTPoly> cNew(ciphertext->GetElements());
  cNew[0] = cNew[0] - GetElementForEvalAddOrSub(ciphertext, constant);

  Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetElements(std::move(cNew));
  newCiphertext->SetDepth(ciphertext->GetDepth());
  newCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());
  newCiphertext->SetLevel(ciphertext->GetLevel());

  return newCiphertext;
}

#if NATIVEINT == 128
template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultApprox(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
      std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  uint32_t precision = 52;
  double powP = std::pow(2, precision);

  // the idea is to break down real numbers
  // expressed as input_mantissa * 2^input_exponent
  // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
  // to preserve 52-bit precision of doubles
  // when converting to 128-bit numbers
  int32_t n1 = 0;
  int64_t scaled64 =
      std::llround(static_cast<double>(std::frexp(constant, &n1)) * powP);
  int32_t pCurrent = cryptoParams->GetPlaintextModulus() - precision;
  int32_t pRemaining = pCurrent + n1;
  __int128 scaled128 = 0;

  if (pRemaining < 0) {
    scaled128 = scaled64 >> (-pRemaining);
  } else {
    __int128 ppRemaining = ((__int128)1) << pRemaining;
    scaled128 = ppRemaining * scaled64;
  }

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  std::vector<DCRTPoly> cNew(cv.size());
  std::transform(
      cv.begin(), cv.end(), cNew.begin(),
      [scaled128](const DCRTPoly &elem) { return elem.Times(scaled128); });

  Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetElements(std::move(cNew));
  newCiphertext->SetDepth(ciphertext->GetDepth() + 1);
  newCiphertext->SetScalingFactor(
      ciphertext->GetScalingFactor() *
      std::pow(2, cryptoParams->GetPlaintextModulus()));
  newCiphertext->SetLevel(ciphertext->GetLevel());

  return newCiphertext;
}
#else
template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultApprox(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());
  double scFactor =
      cryptoParams->GetScalingFactorOfLevel(ciphertext->GetLevel());
  int64_t scConstant = static_cast<int64_t>(constant * scFactor + 0.5);

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  std::vector<DCRTPoly> cNew(cv.size());
  std::transform(
      cv.begin(), cv.end(), cNew.begin(),
      [scConstant](const DCRTPoly &elem) { return elem * scConstant; });

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
  result->SetElements(std::move(cNew));
  result->SetDepth(ciphertext->GetDepth() + 1);
  result->SetScalingFactor(ciphertext->GetScalingFactor() * scFactor);
  result->SetLevel(ciphertext->GetLevel());

  return result;
}
#endif

#if NATIVEINT == 128
template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultMutable(
    Ciphertext<DCRTPoly> &ciphertext, double constant) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalMultApprox(ciphertext, constant);
  }

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  /*
  To implement EvalMult in EXACTRESCALE & APPROXAUTO , we first have to
  rescale the input ciphertext to depth 1, if it's not already there. Then, we
  scale the input constant by the scaling factor of the ciphertext and
  multiply. No need to take special care for scaling constants to greater
  depths in CRT, because all the input will always get brought down to
  depth 1.
  */

  // EXACTRESCALE & APPROXAUTO expects all ciphertexts to be either of
  // depth 1 or 2.
  if (ciphertext->GetDepth() > 2) {
    PALISADE_THROW(not_available_error,
                   "APPROXAUTO rescaling works for ciphertexts "
                   "of depth 1 and 2 only, and depth of 1 is allowed only "
                   "for fresh ciphertexts");
  }

  auto cc = ciphertext->GetCryptoContext();
  auto algo = cc->GetEncryptionAlgorithm();

  // Rescale to bring ciphertext to depth 1
  if (ciphertext->GetDepth() == 2) {
    ciphertext = algo->ModReduceInternal(ciphertext);
  }

  uint32_t precision = 52;
  double powP = std::pow(2, precision);

  // the idea is to break down real numbers
  // expressed as input_mantissa * 2^input_exponent
  // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
  // to preserve 52-bit precision of doubles
  // when converting to 128-bit numbers
  int32_t n1 = 0;
  int64_t scaled64 =
      std::llround(static_cast<double>(std::frexp(constant, &n1)) * powP);
  int32_t pCurrent = cryptoParams->GetPlaintextModulus() - precision;
  int32_t pRemaining = pCurrent + n1;
  __int128 scaled128 = 0;

  if (pRemaining < 0) {
    scaled128 = scaled64 >> (-pRemaining);
  } else {
    __int128 ppRemaining = ((__int128)1) << pRemaining;
    scaled128 = ppRemaining * scaled64;
  }

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  double scFactor = ciphertext->GetScalingFactor();

  std::vector<DCRTPoly> cvMult(cv.size());
  for (size_t i = 0; i < cv.size(); i++) {
    cvMult[i] = cv[i].Times(scaled128);
  }

  result->SetElements(std::move(cvMult));

  result->SetDepth(ciphertext->GetDepth() + 1);
  result->SetScalingFactor(scFactor * scFactor);
  result->SetLevel(ciphertext->GetLevel());

  return result;
}
#else
template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultMutable(
    Ciphertext<DCRTPoly> &ciphertext, double constant) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalMultApprox(ciphertext, constant);
  }

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  /*
  To implement EvalMult in EXACTRESCALE & APPROXAUTO , we first have to
  rescale the input ciphertext to depth 1, if it's not already there. Then, we
  scale the input constant by the scaling factor of the ciphertext and
  multiply. No need to take special care for scaling constants to greater
  depths in CRT, because all the input will always get brought down to
  depth 1.
  */

  // EXACTRESCALE & APPROXAUTO expects all ciphertexts to be either of
  // depth 1 or 2.
  if (ciphertext->GetDepth() > 2) {
    PALISADE_THROW(not_available_error,
                   "EXACTRESCALE & APPROXAUTO rescaling works for ciphertexts "
                   "of depth 1 and 2 only, and depth of 1 is allowed only "
                   "for fresh ciphertexts");
  }

  auto cc = ciphertext->GetCryptoContext();
  auto algo = cc->GetEncryptionAlgorithm();

  // Rescale to bring ciphertext to depth 1
  if (ciphertext->GetDepth() == 2) {
    ciphertext = algo->ModReduceInternal(ciphertext);
  }

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  double scFactor = ciphertext->GetScalingFactor();
  std::vector<DCRTPoly> cvMult(cv.size());

#if defined(HAVE_INT128)
  typedef int128_t DoubleInteger;
#else
  typedef int64_t DoubleInteger;
#endif

  DCRTPoly::Integer iscFactor = static_cast<int64_t>(scFactor + 0.5);
  DoubleInteger large = static_cast<DoubleInteger>(constant * scFactor + 0.5);
  DoubleInteger large_abs = (large < 0 ? -large : large); 
  DoubleInteger bound = (uint64_t)1 << 63;
  DCRTPoly::Integer scConstant = static_cast<int64_t>(large);

  if (large_abs > bound) {
    uint32_t numTowers = cv[0].GetNumOfElements();

    vector<DCRTPoly::Integer> factors(numTowers);

    for (usint i = 0; i < numTowers; i++) {
      DCRTPoly::Integer modulus = cv[0].GetElementAtIndex(i).GetModulus();
      DoubleInteger reduced = large % modulus.ConvertToInt();
      if (reduced < 0)
        factors[i] = static_cast<uint64_t>(reduced + modulus.ConvertToInt());
      else
        factors[i] = static_cast<uint64_t>(reduced);
    }

    for (size_t i = 0; i < cv.size(); i++) {
      cvMult[i] = cv[i] * factors;
    }
  } else {
    for (size_t i = 0; i < cv.size(); i++) {
      cvMult[i] = cv[i] * scConstant;
    }
  }

  result->SetElements(std::move(cvMult));

  result->SetDepth(ciphertext->GetDepth() + 1);
  result->SetScalingFactor(scFactor * scFactor);
  result->SetLevel(ciphertext->GetLevel());

  return result;
}
#endif

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalMultApprox(ciphertext, constant);
  }

  // EXACTRESCALE & APPROXAUTO
  Ciphertext<DCRTPoly> clone = ciphertext->Clone();
  return EvalMultMutable(clone, constant);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithRescale(
    Ciphertext<DCRTPoly> &ciphertext, uint32_t targetLevel) const {
  if (ciphertext->GetDepth() != 1) {
    PALISADE_THROW(not_available_error,
                   "LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithRescale "
                   "expects a ciphertext that's at depth 1.");
  }

  if (ciphertext->GetLevel() >= targetLevel) {
    PALISADE_THROW(not_available_error,
                   "LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithRescale "
                   "a ciphertext can only be adjusted to a larger level. "
                   "Ciphertext level: " +
                       std::to_string(ciphertext->GetLevel()) +
                       " and target level is: " + std::to_string(targetLevel));
  }

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
  auto algo = cc->GetEncryptionAlgorithm();

  uint32_t sizeQl = ciphertext->GetElements()[0].GetNumOfElements();

  // Multiply with a factor to adjust scaling factor to new level
  double adjustmentFactor = 1.0;
  if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE) {
    // Find the modulus of the last tower, which is to be dropped after
    // rescaling
    double modToDrop = cryptoParams->GetModReduceFactor(sizeQl - 1);
    double targetSF = cryptoParams->GetScalingFactorOfLevel(targetLevel);
    double sourceSF =
        cryptoParams->GetScalingFactorOfLevel(ciphertext->GetLevel());
    adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF);

    // Multiply ciphertext with adjustment (first step to get target scaling
    // factor). and manually update the scaling factor of the result.
    ciphertext = EvalMult(ciphertext, adjustmentFactor);

    // Rescale ciphertext1
    algo->ModReduceInternalInPlace(ciphertext);
  }
  // Drop extra moduli of ciphertext1 to match target level
  uint32_t diffLevel = targetLevel - ciphertext->GetLevel();
  if (diffLevel > 0)
    ciphertext = algo->LevelReduceInternal(ciphertext, nullptr, diffLevel);

  // At this moment, the adjustment factor is interpreted by
  // the library as part of the encrypted message. We manually
  // update the scaling factor to reflect that it was adjusted
  // by multiplying with adjustmentFactor.
  ciphertext->SetScalingFactor(adjustmentFactor *
                               ciphertext->GetScalingFactor());

  return ciphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithoutRescale(
    Ciphertext<DCRTPoly> &ciphertext, uint32_t targetLevel) const {
  if (ciphertext->GetDepth() != 1) {
    PALISADE_THROW(not_available_error,
                   "LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithoutRescale "
                   "expects a ciphertext that's at depth 1.");
  }

  if (ciphertext->GetLevel() >= targetLevel) {
    PALISADE_THROW(not_available_error,
                   "LPAlgorithmSHECKKS<DCRTPoly>::AdjustLevelWithoutRescale "
                   "a ciphertext can only be adjusted to a larger level. "
                   "Ciphertext level: " +
                       std::to_string(ciphertext->GetLevel()) +
                       " and target level is: " + std::to_string(targetLevel));
  }

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

  // Multiply with a factor to adjust scaling factor to new level
  double adjustmentFactor = 1.0;
  if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE) {
    double targetSF = cryptoParams->GetScalingFactorOfLevel(targetLevel);
    double sourceSF =
        cryptoParams->GetScalingFactorOfLevel(ciphertext->GetLevel());
    adjustmentFactor = (targetSF / sourceSF) * (targetSF / sourceSF);
  }

  // Multiply ciphertext with adjustment factor.
  ciphertext = EvalMult(ciphertext, adjustmentFactor);
  // At this moment, the adjustment factor is interpreted by
  // the library as part of the encrypted message. We manually
  // update the scaling factor to reflect that it was adjusted
  // by multiplying with adjustmentFactor.
  ciphertext->SetScalingFactor(adjustmentFactor *
                               ciphertext->GetScalingFactor());

  // Drop extra moduli of ciphertext1 to match target level
  auto algo = cc->GetEncryptionAlgorithm();
  uint32_t diffLevel = targetLevel - ciphertext->GetLevel();
  if (diffLevel > 0)
    ciphertext = algo->LevelReduceInternal(ciphertext, nullptr, diffLevel);

  return ciphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAddCorePlaintext(
    ConstCiphertext<DCRTPoly> ciphertext, DCRTPoly ptxt,
    usint ptxtDepth) const {
  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  // Bring to same depth if not already same
  if (ptxtDepth < ciphertext->GetDepth()) {
    // Find out how many levels to scale plaintext up.
    size_t diffDepth = ciphertext->GetDepth() - ptxtDepth;

    DCRTPoly ptxtClone = ptxt.Clone();

    // Get moduli chain to create CRT representation of powP
    usint sizeQl = cv[0].GetNumOfElements();
    vector<DCRTPoly::Integer> moduli(sizeQl);

    for (usint i = 0; i < sizeQl; i++) {
      moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
    }

    double scFactor = cryptoParams->GetScalingFactorOfLevel();

    DCRTPoly::Integer intSF =
        static_cast<bigintnat::NativeInteger::Integer>(scFactor + 0.5);
    std::vector<DCRTPoly::Integer> crtSF(sizeQl, intSF);
    auto crtPowSF = crtSF;
    for (usint j = 0; j < diffDepth - 1; j++) {
      crtPowSF = CKKSPackedEncoding::CRTMult(crtPowSF, crtSF, moduli);
    }

    // Update ptElem with scaled up element
    ptxt = ptxtClone.Times(crtPowSF);
  } else if (ptxtDepth > ciphertext->GetDepth()) {
    PALISADE_THROW(not_available_error,
                   "LPAlgorithmSHECKKS<DCRTPoly>::EvalAdd "
                   "- plaintext cannot be encoded at a larger depth than that "
                   "of the ciphertext.");
  }

  ptxt.SetFormat(Format::EVALUATION);

  std::vector<DCRTPoly> cvAdd(cv);
  cvAdd[0] = cvAdd[0] + ptxt;

  result->SetElements(std::move(cvAdd));

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSubCorePlaintext(
    ConstCiphertext<DCRTPoly> ciphertext, DCRTPoly ptxt,
    usint ptxtDepth) const {
  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  // Bring to same depth if not already same
  if (ptxtDepth < ciphertext->GetDepth()) {
    // Find out how many levels to scale plaintext up.
    size_t diffDepth = ciphertext->GetDepth() - ptxtDepth;

    DCRTPoly ptxtClone = ptxt.Clone();

    // Get moduli chain to create CRT representation of powP
    usint sizeQl = cv[0].GetNumOfElements();
    vector<DCRTPoly::Integer> moduli(sizeQl);
    for (usint i = 0; i < sizeQl; i++) {
      moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
    }

    double scFactor = cryptoParams->GetScalingFactorOfLevel();

    DCRTPoly::Integer intSF =
        static_cast<bigintnat::NativeInteger::Integer>(scFactor + 0.5);
    std::vector<DCRTPoly::Integer> crtSF(sizeQl, intSF);
    // Compute powP^depthDiff in CRT
    auto crtPowSF = crtSF;
    for (usint j = 1; j < diffDepth; j++) {
      crtPowSF = CKKSPackedEncoding::CRTMult(crtPowSF, crtSF, moduli);
    }

    // Update ptElem with scaled up element
    ptxt = ptxtClone.Times(crtPowSF);
  } else if (ptxtDepth > ciphertext->GetDepth()) {
    PALISADE_THROW(not_available_error,
                   "LPAlgorithmSHECKKS<DCRTPoly>::EvalSub "
                   "- plaintext cannot be encoded at a larger depth than that "
                   "of the ciphertext.");
  }

  ptxt.SetFormat(Format::EVALUATION);

  std::vector<DCRTPoly> cvSub(cv);
  cvSub[0] = cvSub[0] - ptxt;

  result->SetElements(std::move(cvSub));

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <>
vector<shared_ptr<ConstCiphertext<DCRTPoly>>>
LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  auto sizeQl1 = ciphertext1->GetElements()[0].GetNumOfElements();
  auto sizeQl2 = ciphertext2->GetElements()[0].GetNumOfElements();
  vector<shared_ptr<ConstCiphertext<DCRTPoly>>> ct(2);

  if (sizeQl1 < sizeQl2) {
    // First ciphertext remains same
    ct[0] = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext1);

    // Level reduce the second ciphertext
    auto cc = ciphertext1->GetCryptoContext();
    auto algo = cc->GetEncryptionAlgorithm();
    auto reducedCt =
        algo->LevelReduceInternal(ciphertext2, nullptr, sizeQl2 - sizeQl1);
    ct[1] = std::make_shared<ConstCiphertext<DCRTPoly>>(reducedCt);

  } else if (sizeQl1 > sizeQl2) {
    // Second ciphertext remains same
    ct[1] = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext2);

    // Level reduce the first ciphertext
    auto cc = ciphertext1->GetCryptoContext();
    auto algo = cc->GetEncryptionAlgorithm();
    auto reducedCt =
        algo->LevelReduceInternal(ciphertext1, nullptr, sizeQl1 - sizeQl2);
    ct[0] = std::make_shared<ConstCiphertext<DCRTPoly>>(reducedCt);
  } else {
    ct[0] = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext1);
    ct[1] = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext2);
  }

  return ct;
}

template <>
void LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduceInPlace(
    Ciphertext<DCRTPoly> &ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  auto sizeQl1 = ciphertext1->GetElements()[0].GetNumOfElements();
  auto sizeQl2 = ciphertext2->GetElements()[0].GetNumOfElements();

  if (sizeQl1 > sizeQl2) {
    // Second ciphertext remains same
    // Level reduce the first ciphertext
    auto cc = ciphertext1->GetCryptoContext();
    auto algo = cc->GetEncryptionAlgorithm();
    algo->LevelReduceInternalInPlace(ciphertext1, nullptr, sizeQl1 - sizeQl2);
  }
}

template <>
std::pair<shared_ptr<ConstCiphertext<DCRTPoly>>, DCRTPoly>
LPAlgorithmSHECKKS<DCRTPoly>::AutomaticLevelReduce(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  DCRTPoly ptxt = plaintext->GetElement<DCRTPoly>();
  auto sizeQlc = ciphertext->GetElements()[0].GetNumOfElements();
  auto sizeQlp = ptxt.GetNumOfElements();

  std::pair<shared_ptr<ConstCiphertext<DCRTPoly>>, DCRTPoly> resPair;

  if (sizeQlc < sizeQlp) {
    // Ciphertext remains same
    resPair.first = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext);

    // Level reduce the plaintext
    ptxt.DropLastElements(sizeQlp - sizeQlc);
    resPair.second = ptxt;
  } else if (sizeQlc > sizeQlp) {
    // Plaintext remains same
    resPair.second = ptxt;

    // Level reduce the ciphertext
    auto cc = ciphertext->GetCryptoContext();
    auto algo = cc->GetEncryptionAlgorithm();
    auto reducedCt =
        algo->LevelReduceInternal(ciphertext, nullptr, sizeQlc - sizeQlp);
    resPair.first = std::make_shared<ConstCiphertext<DCRTPoly>>(reducedCt);
  } else {
    resPair.first = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext);
    resPair.second = ptxt;
  }

  return resPair;
}

template <>
void LPAlgorithmSHECKKS<DCRTPoly>::EvalAddApproxInPlace(
    Ciphertext<DCRTPoly> &ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
    PALISADE_THROW(config_error, "Depths of two ciphertexts do not match.");
  }

  AutomaticLevelReduceInPlace(ciphertext1, ciphertext2);
  EvalAddCoreInPlace(ciphertext1, ciphertext2);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAddApprox(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  auto ciphertext1_clone = ciphertext1->Clone();
  EvalAddApproxInPlace(ciphertext1_clone, ciphertext2);
  return ciphertext1_clone;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAddMutable(
    Ciphertext<DCRTPoly> &ciphertext1,
    Ciphertext<DCRTPoly> &ciphertext2) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext1->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalAddApprox(ciphertext1, ciphertext2);
  }

  CryptoContext<DCRTPoly> cc = ciphertext1->GetCryptoContext();
  auto algo = cc->GetEncryptionAlgorithm();

  if (ciphertext1->GetLevel() < ciphertext2->GetLevel()) {
    // ciphertext1 gets adjusted
    if (ciphertext1->GetDepth() > 1) {
      algo->ModReduceInternalInPlace(ciphertext1);
    }

    // Adjust only if levels are still different, or if their
    // depths are different (ciphertext2 is always expected to be depth 1
    // here)
    if (ciphertext1->GetLevel() < ciphertext2->GetLevel()) {
      if (ciphertext2->GetDepth() == 1) {
        ciphertext1 =
            AdjustLevelWithRescale(ciphertext1, ciphertext2->GetLevel());
      } else {
        ciphertext1 =
            AdjustLevelWithoutRescale(ciphertext1, ciphertext2->GetLevel());
      }
    } else if (ciphertext2->GetDepth() != ciphertext1->GetDepth()) {
      ciphertext1 = EvalMult(ciphertext1, 1.0);
    }

    return EvalAddCore(ciphertext1, ciphertext2);
  } else if (ciphertext2->GetLevel() < ciphertext1->GetLevel()) {
    // ciphertext2 gets adjusted
    if (ciphertext2->GetDepth() > 1)
      algo->ModReduceInternalInPlace(ciphertext2);

    // Adjust only if levels are still different, or if their
    // depths are different (ciphertext2 is always expected to be depth 1
    // here)
    if (ciphertext2->GetLevel() < ciphertext1->GetLevel()) {
      if (ciphertext1->GetDepth() == 1)
        ciphertext2 =
            AdjustLevelWithRescale(ciphertext2, ciphertext1->GetLevel());
      else
        ciphertext2 =
            AdjustLevelWithoutRescale(ciphertext2, ciphertext1->GetLevel());
    } else if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
      ciphertext2 = EvalMult(ciphertext2, 1.0);
    }

    return EvalAddCore(ciphertext1, ciphertext2);
  } else {  // No need for adjustment - levels are equal
    // If depths are not equal, bring the ciphertext which
    // is of depth 1 to 2.
    if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
      if (ciphertext1->GetDepth() == 1)
        ciphertext1 = EvalMultMutable(ciphertext1, 1.0);
      else
        ciphertext2 = EvalMultMutable(ciphertext2, 1.0);
    }

    return EvalAddCore(ciphertext1, ciphertext2);
  }
}

template <>
void LPAlgorithmSHECKKS<DCRTPoly>::EvalAddInPlace(
    Ciphertext<DCRTPoly> &ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext1->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    EvalAddApproxInPlace(ciphertext1, ciphertext2);
    return;
  }

  // TODO(fboemer): EvalAddMutableInPlace
  Ciphertext<DCRTPoly> ciphertext2_clone = ciphertext2->Clone();
  ciphertext1 = EvalAddMutable(ciphertext1, ciphertext2_clone);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAdd(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() != APPROXRESCALE &&
      (plaintext->GetDepth() != ciphertext->GetDepth() ||
       plaintext->GetLevel() != ciphertext->GetLevel())) {
    // TODO - it's not efficient to re-make the plaintexts
    // Allow for rescaling of plaintexts, and the ability to
    // increase the towers of a plaintext to get better performance.
    // Also refactor after fixing this to avoid duplication of
    // AutomaticLevelReduce and EvalAddCorePlaintext code below.
    CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

    auto values = plaintext->GetCKKSPackedValue();
    Plaintext ptx = cc->MakeCKKSPackedPlaintext(values, ciphertext->GetDepth(),
                                                ciphertext->GetLevel());

    auto inPair = AutomaticLevelReduce(ciphertext, ptx);
    return EvalAddCorePlaintext(*(inPair.first), inPair.second,
                                ptx->GetDepth());

  } else {
    auto inPair = AutomaticLevelReduce(ciphertext, plaintext);
    return EvalAddCorePlaintext(*(inPair.first), inPair.second,
                                plaintext->GetDepth());
  }
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalAddMutable(
    Ciphertext<DCRTPoly> &ciphertext, Plaintext plaintext) const {
  return EvalAdd(ciphertext, plaintext);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSubApprox(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
    PALISADE_THROW(config_error, "Depths of two ciphertexts do not match.");
  }

  // Automatic lever-reduce
  auto ct = AutomaticLevelReduce(ciphertext1, ciphertext2);
  return EvalSubCore(*ct[0], *ct[1]);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSubMutable(
    Ciphertext<DCRTPoly> &ciphertext1,
    Ciphertext<DCRTPoly> &ciphertext2) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext1->GetCryptoParameters());

  // In the case of EXACT RNS rescaling, we automatically rescale ciphertexts
  // that are not at the same level
  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalSubApprox(ciphertext1, ciphertext2);
  }

  CryptoContext<DCRTPoly> cc = ciphertext1->GetCryptoContext();
  auto algo = cc->GetEncryptionAlgorithm();

  if (ciphertext1->GetLevel() < ciphertext2->GetLevel()) {
    // ciphertext1 gets adjusted
    if (ciphertext1->GetDepth() > 1)
      algo->ModReduceInternalInPlace(ciphertext1);

    // Adjust only if levels are still different
    if (ciphertext1->GetLevel() < ciphertext2->GetLevel()) {
      if (ciphertext2->GetDepth() == 1) {
        ciphertext1 =
            AdjustLevelWithRescale(ciphertext1, ciphertext2->GetLevel());
      } else {
        ciphertext1 =
            AdjustLevelWithoutRescale(ciphertext1, ciphertext2->GetLevel());
      }
    } else if (ciphertext2->GetDepth() != ciphertext1->GetDepth()) {
      ciphertext1 = EvalMult(ciphertext1, 1.0);
    }
  } else if (ciphertext2->GetLevel() < ciphertext1->GetLevel()) {
    // ciphertext2 gets adjusted
    if (ciphertext2->GetDepth() > 1)
      algo->ModReduceInternalInPlace(ciphertext2);

    // Adjust only if levels are still different
    if (ciphertext2->GetLevel() < ciphertext1->GetLevel()) {
      if (ciphertext1->GetDepth() == 1) {
        ciphertext2 =
            AdjustLevelWithRescale(ciphertext2, ciphertext1->GetLevel());
      } else {
        ciphertext2 =
            AdjustLevelWithoutRescale(ciphertext2, ciphertext1->GetLevel());
      }
    } else if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
      ciphertext2 = EvalMult(ciphertext2, 1.0);
    }
  } else {
    // No need for adjustment - levels are equal
    // If depths are not equal, bring the ciphertext which
    // is of depth 1 to 2.
    if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
      if (ciphertext1->GetDepth() == 1) {
        ciphertext1 = EvalMultMutable(ciphertext1, 1.0);
      } else {
        ciphertext2 = EvalMultMutable(ciphertext2, 1.0);
      }
    }
  }

  return EvalSubCore(ciphertext1, ciphertext2);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSub(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext1->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalSubApprox(ciphertext1, ciphertext2);
  }

  Ciphertext<DCRTPoly> c1 = ciphertext1->Clone();
  Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();

  return EvalSubMutable(c1, c2);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSub(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  // In the case of EXACT RNS rescaling, we automatically rescale ciphertexts
  // that are not at the same level
  if (cryptoParams->GetRescalingTechnique() != APPROXRESCALE &&
      (plaintext->GetDepth() != ciphertext->GetDepth() ||
       plaintext->GetLevel() != ciphertext->GetLevel())) {
    // TODO - it's not efficient to re-make the plaintexts
    // Allow for rescaling of plaintexts, and the ability to
    // increase the towers of a plaintext to get better performance.
    // Also refactor after fixing this to avoid duplication of
    // AutomaticLevelReduce and EvalSubCorePlaintext code below.
    CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();

    auto values = plaintext->GetCKKSPackedValue();
    Plaintext ptx = cc->MakeCKKSPackedPlaintext(values, ciphertext->GetDepth(),
                                                ciphertext->GetLevel());

    auto inPair = AutomaticLevelReduce(ciphertext, ptx);
    return EvalSubCorePlaintext(*(inPair.first), inPair.second,
                                ptx->GetDepth());
  }

  auto inPair = AutomaticLevelReduce(ciphertext, plaintext);
  return EvalSubCorePlaintext(*(inPair.first), inPair.second,
                              plaintext->GetDepth());
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalSubMutable(
    Ciphertext<DCRTPoly> &ciphertext, Plaintext plaintext) const {
  return EvalSub(ciphertext, plaintext);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultApprox(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  auto ct = AutomaticLevelReduce(ciphertext1, ciphertext2);
  return EvalMultCore(*ct[0], *ct[1]);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultMutable(
    Ciphertext<DCRTPoly> &ciphertext1,
    Ciphertext<DCRTPoly> &ciphertext2) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext1->GetCryptoParameters());

  // In the case of EXACT RNS rescaling, we automatically rescale ciphertexts
  // that are not at the same level
  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalMultApprox(ciphertext1, ciphertext2);
  }

  CryptoContext<DCRTPoly> cc = ciphertext1->GetCryptoContext();
  auto algo = cc->GetEncryptionAlgorithm();

  // First bring both inputs to depth 1 (by rescaling)
  if (ciphertext1->GetDepth() > 1) algo->ModReduceInternalInPlace(ciphertext1);
  if (ciphertext2->GetDepth() > 1) algo->ModReduceInternalInPlace(ciphertext2);

  if (ciphertext1->GetLevel() < ciphertext2->GetLevel()) {
    AdjustLevelWithRescale(ciphertext1, ciphertext2->GetLevel());
  } else if (ciphertext1->GetLevel() > ciphertext2->GetLevel()) {
    AdjustLevelWithRescale(ciphertext2, ciphertext1->GetLevel());
  }

  return EvalMultCore(ciphertext1, ciphertext2);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext1->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalMultApprox(ciphertext1, ciphertext2);
  }

  Ciphertext<DCRTPoly> c1 = ciphertext1->Clone();
  Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();

  return EvalMultMutable(c1, c2);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultApprox(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  DCRTPoly pt = plaintext->GetElement<DCRTPoly>();

  usint sizeQlc = cv[0].GetParams()->GetParams().size();
  usint sizeQlp = pt.GetParams()->GetParams().size();
  if (sizeQlp >= sizeQlc) {
    pt.DropLastElements(sizeQlp - sizeQlc);
  } else {
    PALISADE_THROW(not_available_error,
                   "In APPROXRESCALE EvalMult, ciphertext "
                   "cannot have more towers than the plaintext");
  }

  pt.SetFormat(Format::EVALUATION);

  std::vector<DCRTPoly> cvMult;

  for (size_t i = 0; i < cv.size(); i++) {
    cvMult.push_back((cv[i] * pt));
  }

  result->SetElements(std::move(cvMult));

  result->SetDepth(ciphertext->GetDepth() + plaintext->GetDepth());
  result->SetScalingFactor(ciphertext->GetScalingFactor() *
                           plaintext->GetScalingFactor());
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultMutable(
    Ciphertext<DCRTPoly> &ciphertext, Plaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  // In the case of EXACT RNS rescaling, we automatically rescale ciphertexts
  // that are not at the same level
  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalMultApprox(ciphertext, plaintext);
  }

  CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
  auto algo = cc->GetEncryptionAlgorithm();

  // First bring input to depth 1 (by rescaling)
  if (ciphertext->GetDepth() > 1) algo->ModReduceInternalInPlace(ciphertext);

  DCRTPoly pt;
  double ptxSF = 1.0;
  uint32_t ptxDepth = 1;
  std::vector<DCRTPoly> cvMult;

  if (plaintext->GetDepth() != ciphertext->GetDepth() ||
      plaintext->GetLevel() != ciphertext->GetLevel()) {
    // TODO - it's not efficient to re-make the plaintexts
    // Allow for rescaling of plaintexts, and the ability to
    // increase the towers of a plaintext to get better performance.

    vector<std::complex<double>> values = plaintext->GetCKKSPackedValue();

    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(values, ciphertext->GetDepth(),
                                                 ciphertext->GetLevel());

    pt = ptxt->GetElement<DCRTPoly>();
    ptxSF = ptxt->GetScalingFactor();
    ptxDepth = ptxt->GetDepth();

  } else {
    pt = plaintext->GetElement<DCRTPoly>();
    ptxSF = plaintext->GetScalingFactor();
    ptxDepth = plaintext->GetDepth();
  }

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  pt.SetFormat(Format::EVALUATION);

  for (size_t i = 0; i < cv.size(); i++) {
    cvMult.push_back((cv[i] * pt));
  }

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  result->SetElements(std::move(cvMult));
  result->SetDepth(ciphertext->GetDepth() + ptxDepth);
  result->SetScalingFactor(ciphertext->GetScalingFactor() * ptxSF);
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    return EvalMultApprox(ciphertext, plaintext);
  }

  Ciphertext<DCRTPoly> ctx = ciphertext->Clone();

  Plaintext ptxt = std::make_shared<CKKSPackedEncoding>(
      *std::dynamic_pointer_cast<const CKKSPackedEncoding>(plaintext));

  return EvalMultMutable(ctx, ptxt);
}

template <>
Ciphertext<DCRTPoly>
LPAlgorithmSHECKKS<DCRTPoly>::EvalLinearWSumInternalMutable(
    vector<Ciphertext<DCRTPoly>> ciphertexts, vector<double> constants) const {
  uint32_t n = ciphertexts.size();

  if (n != constants.size() || n == 0)
    PALISADE_THROW(math_error,
                   "LPAlgorithmSHECKKS<DCRTPoly>::EvalLinearWSum input vector "
                   "sizes do not match.");

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertexts[0]->GetCryptoParameters());

  Ciphertext<DCRTPoly> weightedSum;

  for (uint32_t i = 0; i < n; i++) {
    double adjustedConstant = 1.0;

    if (cryptoParams->GetRescalingTechnique() != APPROXRESCALE) {
      if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE) {
        uint32_t numTowers =
            ciphertexts[i]->GetElements()[0].GetNumOfElements();
        double modToDrop = cryptoParams->GetModReduceFactor(numTowers - 1);
        double targetSF = cryptoParams->GetScalingFactorOfLevel(
            ciphertexts[i]->GetLevel() + 1);
        double sourceSF =
            cryptoParams->GetScalingFactorOfLevel(ciphertexts[i]->GetLevel());
        double adjFactor = (targetSF / sourceSF) * (targetSF / sourceSF) *
                           (modToDrop / sourceSF);
        adjustedConstant = adjFactor * constants[i];
      } else {
        adjustedConstant = constants[i];
      }

      if (i == 0 && ciphertexts[i]->GetDepth() == 1) {
        auto tmp = EvalMultMutable(ciphertexts[i], 1.0);
        weightedSum = EvalMultApprox(tmp, adjustedConstant);
      } else if (i == 0 && ciphertexts[i]->GetDepth() == 2) {
        weightedSum = EvalMultApprox(ciphertexts[i], adjustedConstant);
      } else if (i > 0 && ciphertexts[i]->GetDepth() == 1) {
        auto tmp = EvalMultMutable(ciphertexts[i], 1.0);
        auto tmp2 = EvalMultApprox(tmp, adjustedConstant);
        EvalAddApproxInPlace(weightedSum, tmp2);
      } else {
        auto tmp = EvalMultApprox(ciphertexts[i], adjustedConstant);
        EvalAddApproxInPlace(weightedSum, tmp);
      }

    } else {
      adjustedConstant = constants[i];

      if (i == 0)
        weightedSum = EvalMultApprox(ciphertexts[i], adjustedConstant);
      else
        EvalAddApproxInPlace(weightedSum,
                             EvalMultApprox(ciphertexts[i], adjustedConstant));
    }
  }

  if (cryptoParams->GetRescalingTechnique() != APPROXRESCALE) {
    CryptoContext<DCRTPoly> cc = weightedSum->GetCryptoContext();

    auto algo = cc->GetEncryptionAlgorithm();

    while (weightedSum->GetDepth() > 2) {
      algo->ModReduceInternalInPlace(weightedSum);
    }

    double sf = cryptoParams->GetScalingFactorOfLevel(weightedSum->GetLevel());
    double d = weightedSum->GetDepth();
    weightedSum->SetScalingFactor(pow(sf, d));
  }

  return weightedSum;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalLinearWSumMutable(
    vector<Ciphertext<DCRTPoly>> ciphertexts, vector<double> constants) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertexts[0]->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() != APPROXRESCALE) {
    // Check to see if input ciphertexts are of same level
    // and adjust if needed to the max level among them
    uint32_t minLevel = ciphertexts[0]->GetLevel();
    uint32_t maxLevel = minLevel;
    for (uint32_t i = 1; i < ciphertexts.size(); i++) {
      if (ciphertexts[i]->GetLevel() > maxLevel)
        maxLevel = ciphertexts[i]->GetLevel();
      if (ciphertexts[i]->GetLevel() < minLevel)
        minLevel = ciphertexts[i]->GetLevel();
    }

    if (maxLevel != minLevel) {
      // Not all inputs are of same level, and all should be brought to maxLevel
      for (uint32_t i = 0; i < ciphertexts.size(); i++) {
        if (ciphertexts[i]->GetLevel() != maxLevel) {
          CryptoContext<DCRTPoly> cc = ciphertexts[i]->GetCryptoContext();

          auto algo = cc->GetEncryptionAlgorithm();

          if (ciphertexts[i]->GetDepth() == 2) {
            algo->ModReduceInternalInPlace(ciphertexts[i]);
          }

          // Here, cts are all depth 1 and we adjust them to the correct
          // level (i.e., maxLevel, and they become depth 2).
          if (ciphertexts[i]->GetLevel() != maxLevel) {
            AdjustLevelWithoutRescale(ciphertexts[i], maxLevel);
          }
        }
      }
    }
  }

  return EvalLinearWSumInternalMutable(ciphertexts, constants);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalLinearWSum(
    vector<Ciphertext<DCRTPoly>> ciphertexts, vector<double> constants) const {
  vector<Ciphertext<DCRTPoly>> cts(ciphertexts.size());

  for (uint32_t i = 0; i < ciphertexts.size(); i++) {
    cts[i] = ciphertexts[i]->Clone();
  }

  return EvalLinearWSumMutable(cts, constants);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalMultAndRelinearize(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2,
    const vector<LPEvalKey<DCRTPoly>> &ek) const {
  Ciphertext<DCRTPoly> ciphertext = this->EvalMult(ciphertext1, ciphertext2);

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ek[0]->GetCryptoParameters());

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
  result->SetDepth(ciphertext->GetDepth());

  std::vector<DCRTPoly> c = ciphertext->GetElements();

  // Do not change the format of the elements to decompose
  c[0].SetFormat(Format::EVALUATION);
  c[1].SetFormat(Format::EVALUATION);

  DCRTPoly ct0(c[0]);
  DCRTPoly ct1(c[1]);

  // Perform a keyswitching operation to result of the multiplication. It does
  // it until it reaches to 2 elements.
  // TODO: Maybe we can change the number of keyswitching and terminate early.
  // For instance; perform keyswitching until 4 elements left.
  usint depth = c.size() - 1;

  DCRTPoly zero = c[0].CloneParametersOnly();
  zero.SetValuesToZero();

  for (size_t j = 0, index = (depth - 2); j <= depth - 2; j++, --index) {

    LPEvalKeyRelin<DCRTPoly> evalKey =
        std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

    // Create a ciphertext with 3 components (0, 0, c[index+2])
    // so KeySwitch returns only the switched parts of c[index+2]
    vector<DCRTPoly> tmp = {zero, zero, c[index + 2]};
    Ciphertext<DCRTPoly> cTmp = ciphertext->CloneEmpty();
    cTmp->SetElements(std::move(tmp));
    cTmp->SetDepth(ciphertext->GetDepth());
    cTmp->SetLevel(ciphertext->GetLevel());
    cTmp->SetScalingFactor(ciphertext->GetScalingFactor());

    KeySwitchInPlace(evalKey, cTmp);

    ct0 += cTmp->GetElements()[0];
    ct1 += cTmp->GetElements()[1];
  }

  result->SetElements({std::move(ct0), std::move(ct1)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetScalingFactor(ciphertext->GetScalingFactor());
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::Relinearize(
    ConstCiphertext<DCRTPoly> ciphertext,
    const vector<LPEvalKey<DCRTPoly>> &ek) const {

  if (ciphertext->GetElements().size() == 3) {

      LPEvalKeyRelin<DCRTPoly> evalKey =
          std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[0]);

      Ciphertext<DCRTPoly> result = ciphertext->Clone();

      KeySwitchInPlace(evalKey, result);

      return result;

  } else {

    const auto cryptoParams =
	std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
	    ek[0]->GetCryptoParameters());

    Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
    result->SetDepth(ciphertext->GetDepth());

    const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

    DCRTPoly ct0(cv[0]);
    DCRTPoly ct1(cv[1]);
    // Perform a keyswitching operation to result of the multiplication. It does
    // it until it reaches to 2 elements.
    // TODO: Maybe we can change the number of keyswitching and terminate early.
    // For instance; perform keyswitching until 4 elements left.
    usint depth = cv.size() - 1;

    DCRTPoly zero = cv[0].CloneParametersOnly();
    zero.SetValuesToZero();

    for (size_t j = 0, index = (depth - 2); j <= depth - 2; j++, --index) {

      LPEvalKeyRelin<DCRTPoly> evalKey =
	  std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

      // Create a ciphertext with 3 components (0, 0, c[index+2])
      // so KeySwitch returns only the switched parts of c[index+2]
      vector<DCRTPoly> tmp = {zero, zero, cv[index + 2]};
      Ciphertext<DCRTPoly> cTmp = ciphertext->CloneEmpty();
      cTmp->SetElements(std::move(tmp));
      cTmp->SetDepth(ciphertext->GetDepth());
      cTmp->SetLevel(ciphertext->GetLevel());
      cTmp->SetScalingFactor(ciphertext->GetScalingFactor());

      KeySwitchInPlace(evalKey, cTmp);

      ct0 += cTmp->GetElements()[0];
      ct1 += cTmp->GetElements()[1];
    }

    result->SetElements({std::move(ct0), std::move(ct1)});
    result->SetLevel(ciphertext->GetLevel());
    result->SetScalingFactor(ciphertext->GetScalingFactor());

    return result;
  }
}

template <>
void LPAlgorithmSHECKKS<DCRTPoly>::RelinearizeInPlace(
    Ciphertext<DCRTPoly> &ciphertext,
    const vector<LPEvalKey<DCRTPoly>> &ek) const {

  if (ciphertext->GetElements().size() == 3) {

      LPEvalKeyRelin<DCRTPoly> evalKey =
          std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[0]);

      KeySwitchInPlace(evalKey, ciphertext);

  } else {

    const auto cryptoParams =
	std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
	    ek[0]->GetCryptoParameters());

    const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

    DCRTPoly ct0(cv[0]);
    DCRTPoly ct1(cv[1]);
    // Perform a keyswitching operation to result of the multiplication. It does
    // it until it reaches to 2 elements.
    // TODO: Maybe we can change the number of keyswitching and terminate early.
    // For instance; perform keyswitching until 4 elements left.
    usint depth = cv.size() - 1;

    DCRTPoly zero = cv[0].CloneParametersOnly();
    zero.SetValuesToZero();

    for (size_t j = 0, index = (depth - 2); j <= depth - 2; j++, --index) {

      LPEvalKeyRelin<DCRTPoly> evalKey =
	  std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

      // Create a ciphertext with 3 components (0, 0, c[index+2])
      // so KeySwitch returns only the switched parts of c[index+2]
      vector<DCRTPoly> tmp = {zero, zero, cv[index + 2]};
      Ciphertext<DCRTPoly> cTmp = ciphertext->CloneEmpty();
      cTmp->SetElements(std::move(tmp));
      cTmp->SetDepth(ciphertext->GetDepth());
      cTmp->SetLevel(ciphertext->GetLevel());
      cTmp->SetScalingFactor(ciphertext->GetScalingFactor());

      KeySwitchInPlace(evalKey, cTmp);

      ct0 += cTmp->GetElements()[0];
      ct1 += cTmp->GetElements()[1];
    }

    ciphertext->SetElements({std::move(ct0), std::move(ct1)});

  }
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmMultipartyCKKS<DCRTPoly>::MultipartyDecryptLead(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      privateKey->GetCryptoParameters();
  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  auto s(privateKey->GetPrivateElement());

  size_t sizeQ = s.GetParams()->GetParams().size();
  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t diffQl = sizeQ - sizeQl;

  s.DropLastElements(diffQl);

  DggType dgg(MP_SD);
  DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);

  // e is added to do noise flooding
  DCRTPoly b = cv[0] + s * cv[1] + e;

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  result->SetElements({std::move(b)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmMultipartyCKKS<DCRTPoly>::MultipartyDecryptMain(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      privateKey->GetCryptoParameters();
  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  auto s(privateKey->GetPrivateElement());

  size_t sizeQ = s.GetParams()->GetParams().size();
  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t diffQl = sizeQ - sizeQl;

  s.DropLastElements(diffQl);

  DggType dgg(MP_SD);
  DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);

  // e is added to do noise flooding
  DCRTPoly b = s * cv[1] + e;

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  result->SetElements({std::move(b)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <>
DecryptResult LPAlgorithmMultipartyCKKS<DCRTPoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<DCRTPoly>> &ciphertextVec, Poly *plaintext) const {
  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      ciphertextVec[0]->GetCryptoParameters();
  // const auto p = cryptoParams->GetPlaintextModulus();

  const std::vector<DCRTPoly> &cv0 = ciphertextVec[0]->GetElements();
  DCRTPoly b = cv0[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<DCRTPoly> &cvi = ciphertextVec[i]->GetElements();
    b += cvi[0];
  }

  b.SwitchFormat();

  *plaintext = b.CRTInterpolate();

  return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmMultipartyCKKS<DCRTPoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<DCRTPoly>> &ciphertextVec,
    NativePoly *plaintext) const {
  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      ciphertextVec[0]->GetCryptoParameters();
  // const auto p = cryptoParams->GetPlaintextModulus();

  const std::vector<DCRTPoly> &cv0 = ciphertextVec[0]->GetElements();
  DCRTPoly b = cv0[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<DCRTPoly> &cvi = ciphertextVec[i]->GetElements();
    b += cvi[0];
  }

  b.SwitchFormat();

  *plaintext = b.GetElementAtIndex(0);

  return DecryptResult(plaintext->GetLength());
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmMultipartyCKKS<DCRTPoly>::MultiKeySwitchGen(
    const LPPrivateKey<DCRTPoly> originalPrivateKey,
    const LPPrivateKey<DCRTPoly> newPrivateKey,
    const LPEvalKey<DCRTPoly> ek) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          newPrivateKey->GetCryptoParameters());

  LPAlgorithmSHECKKS<DCRTPoly> algoSHE;

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    return algoSHE.KeySwitchBVGen(originalPrivateKey, newPrivateKey, ek);
  } else if (cryptoParams->GetKeySwitchTechnique() == GHS) {
    return algoSHE.KeySwitchGHSGen(originalPrivateKey, newPrivateKey, ek);
  } else {  // Hybrid
    return algoSHE.KeySwitchHybridGen(originalPrivateKey, newPrivateKey, ek);
  }
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmMultipartyCKKS<DCRTPoly>::MultiMultEvalKey(
    LPEvalKey<DCRTPoly> evalKey, LPPrivateKey<DCRTPoly> sk) const {
  const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          evalKey->GetCryptoParameters());

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          evalKey->GetCryptoContext()->GetCryptoParameters());
  const typename DCRTPoly::DggType &dgg =
      cryptoParams->GetDiscreteGaussianGenerator();
  const shared_ptr<typename DCRTPoly::Params> elementParams =
      cryptoParams->GetElementParams();

  LPEvalKey<DCRTPoly> evalKeyResult(
      new LPEvalKeyRelinImpl<DCRTPoly>(evalKey->GetCryptoContext()));

  const std::vector<DCRTPoly> &a0 = evalKey->GetAVector();
  const std::vector<DCRTPoly> &b0 = evalKey->GetBVector();

  std::vector<DCRTPoly> a;
  std::vector<DCRTPoly> b;

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    const DCRTPoly &s = sk->GetPrivateElement();

    for (usint i = 0; i < a0.size(); i++) {
      DCRTPoly f1(dgg, elementParams, Format::COEFFICIENT);
      f1.SetFormat(Format::EVALUATION);

      DCRTPoly f2(dgg, elementParams, Format::COEFFICIENT);
      f2.SetFormat(Format::EVALUATION);

      a.push_back(a0[i] * s + f1);
      b.push_back(b0[i] * s + f2);
    }
  } else {  // GHS or Hybrid
    const shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
    const shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

    usint sizeQ = paramsQ->GetParams().size();
    usint sizeQP = paramsQP->GetParams().size();

    DCRTPoly s = sk->GetPrivateElement().Clone();

    // s is currently in basis Q. This extends it to basis QP.
    s.SetFormat(Format::COEFFICIENT);
    DCRTPoly sExt(paramsQP, Format::COEFFICIENT, true);

    // The part with basis Q
    for (usint i = 0; i < sizeQ; i++) {
      sExt.SetElementAtIndex(i, s.GetElementAtIndex(i));
    }

    // The part with basis P
    for (usint j = sizeQ; j < sizeQP; j++) {
      NativeInteger pj = paramsQP->GetParams()[j]->GetModulus();
      NativeInteger rooti = paramsQP->GetParams()[j]->GetRootOfUnity();
      auto sNew0 = s.GetElementAtIndex(0);
      sNew0.SwitchModulus(pj, rooti);
      sExt.SetElementAtIndex(j, std::move(sNew0));
    }

    sExt.SetFormat(Format::EVALUATION);

    for (usint i = 0; i < a0.size(); i++) {
      DCRTPoly f1(dgg, paramsQP, Format::COEFFICIENT);
      f1.SetFormat(Format::EVALUATION);

      DCRTPoly f2(dgg, paramsQP, Format::COEFFICIENT);
      f2.SetFormat(Format::EVALUATION);

      a.push_back(a0[i] * sExt + f1);
      b.push_back(b0[i] * sExt + f2);
    }
  }

  evalKeyResult->SetAVector(std::move(a));

  evalKeyResult->SetBVector(std::move(b));

  return evalKeyResult;
}

template <>
shared_ptr<vector<DCRTPoly>>
LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationPrecomputeBV(
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());
  uint32_t relinWindow = cryptoParams->GetRelinWindow();

  const vector<DCRTPoly> &cv = ciphertext->GetElements();
  auto digitDecomp =
      std::make_shared<vector<DCRTPoly>>(cv[1].CRTDecompose(relinWindow));

  return digitDecomp;
}

template <>
shared_ptr<vector<DCRTPoly>>
LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationPrecomputeGHS(
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  const vector<DCRTPoly> &cv = ciphertext->GetElements();

  const shared_ptr<ParmType> paramsQl = cv[0].GetParams();
  const shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
  const shared_ptr<ParmType> paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);

  size_t sizeQl = paramsQl->GetParams().size();

  DCRTPoly cExt(cv[1]);

  usint l = sizeQl - 1;
  cExt.ApproxModUp(
      paramsQl, paramsP, paramsQlP, cryptoParams->GetQlHatInvModq(l),
      cryptoParams->GetQlHatInvModqPrecon(l), cryptoParams->GetQlHatModp(l),
      cryptoParams->GetModpBarrettMu());

  vector<DCRTPoly> result(1, cExt);

  shared_ptr<vector<DCRTPoly>> resultPtr =
      std::make_shared<vector<DCRTPoly>>(result);

  return resultPtr;
}

template <>
shared_ptr<vector<DCRTPoly>>
LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationPrecomputeHybrid(
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  const shared_ptr<ParmType> paramsQl = cv[0].GetParams();
  const shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
  const shared_ptr<ParmType> paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);

  size_t sizeQl = paramsQl->GetParams().size();
  size_t sizeP = paramsP->GetParams().size();
  size_t sizeQlP = sizeQl + sizeP;

  DCRTPoly c1(cv[1]);

  uint32_t alpha = cryptoParams->GetNumPerPartQ();
  // The number of digits of the current ciphertext
  uint32_t numPartQl = ceil((static_cast<double>(sizeQl)) / alpha);
  if (numPartQl > cryptoParams->GetNumberOfQPartitions())
    numPartQl = cryptoParams->GetNumberOfQPartitions();

  vector<DCRTPoly> partsCt(numPartQl);

  // Digit decomposition
  // Zero-padding and split
  for (uint32_t part = 0; part < numPartQl; part++) {
    if (part == numPartQl - 1) {
      auto paramsPartQ = cryptoParams->GetParamsPartQ(part);

      uint32_t sizePartQl = sizeQl - alpha * part;

      vector<NativeInteger> moduli(sizePartQl);
      vector<NativeInteger> roots(sizePartQl);

      for (uint32_t i = 0; i < sizePartQl; i++) {
        moduli[i] = paramsPartQ->GetParams()[i]->GetModulus();
        roots[i] = paramsPartQ->GetParams()[i]->GetRootOfUnity();
      }

      auto params = DCRTPoly::Params(paramsPartQ->GetCyclotomicOrder(), moduli,
                                     roots, {}, {}, 0);

      partsCt[part] = DCRTPoly(std::make_shared<ParmType>(params),
                               Format::EVALUATION, true);

    } else {
      partsCt[part] = DCRTPoly(cryptoParams->GetParamsPartQ(part),
                               Format::EVALUATION, true);
    }

    const vector<NativeInteger> &QHatInvModq =
        cryptoParams->GetPartQHatInvModq(part);

    usint sizePartQl = partsCt[part].GetNumOfElements();
    usint startPartIdx = alpha * part;
    for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; i++, idx++) {
      auto tmp = c1.GetElementAtIndex(idx).Times(QHatInvModq[idx]);
      partsCt[part].SetElementAtIndex(i, std::move(tmp));
    }
  }

  vector<DCRTPoly> partsCtCompl(numPartQl);
  vector<DCRTPoly> partsCtExt(numPartQl);

  for (uint32_t part = 0; part < numPartQl; part++) {
    auto partCtClone = partsCt[part].Clone();
    partCtClone.SetFormat(Format::COEFFICIENT);

    const shared_ptr<ParmType> paramsComplPartQ =
        cryptoParams->GetParamsComplPartQ(sizeQl - 1, part);

    uint32_t sizePartQl = partsCt[part].GetNumOfElements();
    partsCtCompl[part] = partCtClone.ApproxSwitchCRTBasis(
        cryptoParams->GetParamsPartQ(part), paramsComplPartQ,
        cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1),
        cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1),
        cryptoParams->GetPartQlHatModp(sizeQl - 1, part),
        cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part));

    partsCtCompl[part].SetFormat(Format::EVALUATION);

    partsCtExt[part] = DCRTPoly(paramsQlP, Format::EVALUATION, true);

    usint startPartIdx = alpha * part;
    usint endPartIdx = startPartIdx + sizePartQl;
    for (usint i = 0; i < startPartIdx; i++) {
      partsCtExt[part].SetElementAtIndex(
          i, partsCtCompl[part].GetElementAtIndex(i));
    }
    for (usint i = startPartIdx, idx = 0; i < endPartIdx; i++, idx++) {
      partsCtExt[part].SetElementAtIndex(i,
                                         partsCt[part].GetElementAtIndex(idx));
    }
    for (usint i = endPartIdx; i < sizeQlP; ++i) {
      partsCtExt[part].SetElementAtIndex(
          i, partsCtCompl[part].GetElementAtIndex(i - sizePartQl));
    }
  }

  shared_ptr<vector<DCRTPoly>> resultPtr =
      std::make_shared<vector<DCRTPoly>>(partsCtExt);

  return resultPtr;
}

template <>
shared_ptr<vector<Poly>> LPAlgorithmSHECKKS<Poly>::EvalFastRotationPrecompute(
    ConstCiphertext<Poly> ciphertext) const {
  NOPOLY
}

template <>
shared_ptr<vector<NativePoly>>
LPAlgorithmSHECKKS<NativePoly>::EvalFastRotationPrecompute(
    ConstCiphertext<NativePoly> ciphertext) const {
  NONATIVEPOLY
}

template <>
shared_ptr<vector<DCRTPoly>>
LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationPrecompute(
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  switch (cryptoParams->GetKeySwitchTechnique()) {
    case BV:
      return EvalFastRotationPrecomputeBV(ciphertext);
    case GHS:
      return EvalFastRotationPrecomputeGHS(ciphertext);
    default:  // Hybrid
      return EvalFastRotationPrecomputeHybrid(ciphertext);
  }
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationHybrid(
    ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<DCRTPoly>> expandedCiphertext,
    LPEvalKey<DCRTPoly> evalKey) const {
  // Find the automorphism index that corresponds to rotation index index.
  usint autoIndex = FindAutomorphismIndex2nComplex(index, m);

  // Apply the automorphism to the first component of the ciphertext.
  // DCRTPoly
  // psiC0(ciphertext->GetElements()[0].AutomorphismTransform(autoIndex));
  DCRTPoly psiC0(ciphertext->GetElements()[0]);

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          evalKey->GetCryptoParameters());

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  std::vector<DCRTPoly> bv = evalKey->GetBVector();
  std::vector<DCRTPoly> av = evalKey->GetAVector();

  const shared_ptr<ParmType> paramsQl = psiC0.GetParams();
  const shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
  const shared_ptr<ParmType> paramsQlP = (*expandedCiphertext)[0].GetParams();

  size_t sizeQl = paramsQl->GetParams().size();
  size_t sizeQlP = paramsQlP->GetParams().size();
  size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();

  DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
  DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);

  for (uint32_t j = 0; j < expandedCiphertext->size(); j++) {
    // DCRTPoly cj((*expandedCiphertext)[j].AutomorphismTransform(autoIndex));
    DCRTPoly cj((*expandedCiphertext)[j]);
    const DCRTPoly &bj = bv[j];
    const DCRTPoly &aj = av[j];

    for (usint i = 0; i < sizeQl; i++) {
      const auto &cji = cj.GetElementAtIndex(i);
      const auto &aji = aj.GetElementAtIndex(i);
      const auto &bji = bj.GetElementAtIndex(i);

      cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
      cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
    }
    for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; i++, idx++) {
      const auto &cji = cj.GetElementAtIndex(i);
      const auto &aji = aj.GetElementAtIndex(idx);
      const auto &bji = bj.GetElementAtIndex(idx);

      cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
      cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
    }
  }

  // cTilda0.SetFormat(Format::COEFFICIENT);
  // cTilda1.SetFormat(Format::COEFFICIENT);

  DCRTPoly ct0 = cTilda0.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu());

  DCRTPoly ct1 = cTilda1.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu());

  // ct0.SetFormat(Format::EVALUATION);
  // ct1.SetFormat(Format::EVALUATION);

  ct0 += psiC0;

  usint n = cryptoParams->GetElementParams()->GetRingDimension();
  std::vector<usint> map(n);
  PrecomputeAutoMap(n, autoIndex, &map);

  result->SetElements({ct0.AutomorphismTransform(autoIndex, map),
                       ct1.AutomorphismTransform(autoIndex, map)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationGHS(
    ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<DCRTPoly>> expandedCiphertext,
    LPEvalKey<DCRTPoly> evalKey) const {
  // Find the automorphism index that corresponds to rotation index index.
  usint autoIndex = FindAutomorphismIndex2nComplex(index, m);

  // Apply the automorphism to the first component of the ciphertext.
  // DCRTPoly
  // psiC0(ciphertext->GetElements()[0].AutomorphismTransform(autoIndex));
  DCRTPoly psiC0(ciphertext->GetElements()[0]);

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          evalKey->GetCryptoParameters());

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  std::vector<DCRTPoly> bv = evalKey->GetBVector();
  std::vector<DCRTPoly> av = evalKey->GetAVector();

  // Applying the automorphism to the expanded ciphertext.
  // DCRTPoly
  // expandedC((*expandedCiphertext)[0].AutomorphismTransform(autoIndex));
  DCRTPoly expandedC((*expandedCiphertext)[0]);
  // expandedC is expected to already be in EVAL format. We're doing this to be
  // on the safe side.
  expandedC.SetFormat(Format::EVALUATION);

  const shared_ptr<ParmType> paramsQl = psiC0.GetParams();
  const shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
  const shared_ptr<ParmType> paramsQlP = expandedC.GetParams();

  size_t sizeQl = paramsQl->GetParams().size();
  size_t sizeQlP = paramsQlP->GetParams().size();
  size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();

  DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
  DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);

  const auto &b0 = bv[0];
  const auto &a0 = av[0];

  for (usint i = 0; i < sizeQl; i++) {
    const auto &b0i = b0.GetElementAtIndex(i);
    const auto &a0i = a0.GetElementAtIndex(i);
    const auto &ci = expandedC.GetElementAtIndex(i);

    cTilda0.SetElementAtIndex(i, ci * b0i);
    cTilda1.SetElementAtIndex(i, ci * a0i);
  }
  for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; i++, idx++) {
    const auto &b0i = b0.GetElementAtIndex(idx);
    const auto &a0i = a0.GetElementAtIndex(idx);
    const auto &ci = expandedC.GetElementAtIndex(i);

    cTilda0.SetElementAtIndex(i, ci * b0i);
    cTilda1.SetElementAtIndex(i, ci * a0i);
  }

  // cTilda0.SetFormat(Format::COEFFICIENT);
  // cTilda1.SetFormat(Format::COEFFICIENT);

  DCRTPoly ct0 = cTilda0.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu());

  DCRTPoly ct1 = cTilda1.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu());

  // ct0.SetFormat(Format::EVALUATION);
  // ct1.SetFormat(Format::EVALUATION);

  ct0 += psiC0;

  usint n = cryptoParams->GetElementParams()->GetRingDimension();
  std::vector<usint> map(n);
  PrecomputeAutoMap(n, autoIndex, &map);

  result->SetElements({ct0.AutomorphismTransform(autoIndex, map),
                       ct1.AutomorphismTransform(autoIndex, map)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotationBV(
    ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<DCRTPoly>> digits,
    LPEvalKey<DCRTPoly> evalKey) const {
  /*
   * This method performs a rotation using the algorithm for hoisted
   * automorphisms from paper by Halevi and Shoup, "Faster Homomorphic
   * linear transformations in HELib.", link:
   * https://eprint.iacr.org/2018/244.
   *
   * Overview:
   * 1. Break into digits (done by EvalFastRotationPrecompute)
   * 2. Automorphism step
   * 3. Key switching step
   *
   */

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          evalKey->GetCryptoParameters());

  // Find the automorphism index that corresponds to rotation index index.
  usint autoIndex = FindAutomorphismIndex2nComplex(index, m);

  // Get the parts of the automorphism key
  std::vector<DCRTPoly> bv = evalKey->GetBVector();
  std::vector<DCRTPoly> av = evalKey->GetAVector();

  // Drop the unnecessary moduli to get better performance.
  auto sizeQl = cv[0].GetParams()->GetParams().size();
  auto sizeQ = bv[0].GetParams()->GetParams().size();

  size_t diffQl = sizeQ - sizeQl;
  for (size_t k = 0; k < bv.size(); k++) {
    av[k].DropLastElements(diffQl);
    bv[k].DropLastElements(diffQl);
  }

  // Create a copy of the input digit decomposition to avoid
  // changing the input.
  std::vector<DCRTPoly> digitsCopy(*digits);

  /* (2) Apply the automorphism on the digits and the first
   * component of the input ciphertext p0.
   * p'_0 = psi(p0)
   * q'_k = psi(q_k), where q_k are the digits.
   */
  /*for (size_t i = 0; i < digitsCopy.size(); i++) {
    digitsCopy[i] = digitsCopy[i].AutomorphismTransform(autoIndex);
  }*/
  // DCRTPoly p0Prime(cv[0].AutomorphismTransform(autoIndex));
  DCRTPoly p0Prime(cv[0]);
  DCRTPoly p1DoublePrime;

  /* (3) Do key switching on intermediate ciphertext tmp = (p'_0, p'_1),
   * where p'_1 = Sum_k( q'_k * D_k ), where D_k is the decomposition
   * constants.
   *
   * p''_0 = Sum_k( q'_k * A_k ), for all k.
   * p''_1 = Sum_k( q'_k * B_k ), for all k.
   */
  p1DoublePrime = digitsCopy[0] * av[0];
  auto p0DoublePrime = digitsCopy[0] * bv[0];

  for (usint i = 1; i < digitsCopy.size(); ++i) {
    p0DoublePrime += digitsCopy[i] * bv[i];
    p1DoublePrime += digitsCopy[i] * av[i];
  }

  /* Ciphertext c_out = (p'_0 + p''_0, p''_1) is the result of the
   * automorphism.
   */

  usint n = cryptoParams->GetElementParams()->GetRingDimension();
  std::vector<usint> map(n);
  PrecomputeAutoMap(n, autoIndex, &map);

  result->SetElements(
      {(p0Prime + p0DoublePrime).AutomorphismTransform(autoIndex, map),
       p1DoublePrime.AutomorphismTransform(autoIndex, map)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <>
Ciphertext<Poly> LPAlgorithmSHECKKS<Poly>::EvalFastRotation(
    ConstCiphertext<Poly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<Poly>> digits) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHECKKS<NativePoly>::EvalFastRotation(
    ConstCiphertext<NativePoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<NativePoly>> digits) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHECKKS<DCRTPoly>::EvalFastRotation(
    ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<DCRTPoly>> precomp) const {
  // Return unchanged if no rotation is required
  if (index == 0) {
    CiphertextImpl<DCRTPoly> res(*(ciphertext.get()));
    return std::make_shared<CiphertextImpl<DCRTPoly>>(res);
  }

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  // Find the automorphism index that corresponds to rotation index index.
  usint autoIndex = FindAutomorphismIndex2nComplex(index, m);

  // Retrieve the automorphism key that corresponds to the auto index.
  auto autok = ciphertext->GetCryptoContext()
                   ->GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag())
                   .find(autoIndex)
                   ->second;

  switch (cryptoParams->GetKeySwitchTechnique()) {
    case BV:
      return EvalFastRotationBV(ciphertext, index, m, precomp, autok);
    case GHS:
      return EvalFastRotationGHS(ciphertext, index, m, precomp, autok);
    default:  // Hybrid
      return EvalFastRotationHybrid(ciphertext, index, m, precomp, autok);
  }
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPRECKKS<DCRTPoly>::ReKeyGenBV(
    const LPPublicKey<DCRTPoly> newPk,
    const LPPrivateKey<DCRTPoly> oldSk) const {
  // Get crypto context of new public key.
  auto cc = newPk->GetCryptoContext();

  // Create an Format::EVALUATION key that will contain all the re-encryption
  // key elements.
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          newPk->GetCryptoParameters());
  const shared_ptr<DCRTPoly::Params> elementParams =
      cryptoParams->GetElementParams();

  const DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DCRTPoly::DugType dug;
  DCRTPoly::TugType tug;

  const DCRTPoly &sOld = oldSk->GetPrivateElement();

  std::vector<DCRTPoly> av;
  std::vector<DCRTPoly> bv;

  uint32_t relinWindow = cryptoParams->GetRelinWindow();

  const DCRTPoly &pNew0 = newPk->GetPublicElements().at(0);
  const DCRTPoly &pNew1 = newPk->GetPublicElements().at(1);

  for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
    if (relinWindow > 0) {
      vector<DCRTPoly::PolyType> sOldDecomposed =
          sOld.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (size_t k = 0; k < sOldDecomposed.size(); k++) {
        // Creates an element with all zeroes
        DCRTPoly filtered(elementParams, Format::EVALUATION, true);

        filtered.SetElementAtIndex(i, sOldDecomposed[k]);

        DCRTPoly u;

        if (cryptoParams->GetMode() == RLWE)
          u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
        else
          u = DCRTPoly(tug, elementParams, Format::EVALUATION);

        DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
        DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

        DCRTPoly c0(elementParams);
        DCRTPoly c1(elementParams);

        c0 = pNew0 * u + e0 + filtered;
        c1 = pNew1 * u + e1;

        DCRTPoly a(dug, elementParams, Format::EVALUATION);
        av.push_back(std::move(c1));

        DCRTPoly e(dgg, elementParams, Format::EVALUATION);
        bv.push_back(std::move(c0));
      }
    } else {
      // Creates an element with all zeroes
      DCRTPoly filtered(elementParams, Format::EVALUATION, true);

      filtered.SetElementAtIndex(i, sOld.GetElementAtIndex(i));

      DCRTPoly u;

      if (cryptoParams->GetMode() == RLWE)
        u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
      else
        u = DCRTPoly(tug, elementParams, Format::EVALUATION);

      DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
      DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

      DCRTPoly c0(elementParams);
      DCRTPoly c1(elementParams);

      c0 = pNew0 * u + e0 + filtered;
      c1 = pNew1 * u + e1;

      DCRTPoly a(dug, elementParams, Format::EVALUATION);
      av.push_back(std::move(c1));

      DCRTPoly e(dgg, elementParams, Format::EVALUATION);
      bv.push_back(std::move(c0));
    }
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPRECKKS<DCRTPoly>::ReKeyGenGHS(
    const LPPublicKey<DCRTPoly> newPk,
    const LPPrivateKey<DCRTPoly> oldSk) const {
  auto cc = newPk->GetCryptoContext();
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          newPk->GetCryptoParameters());

  const shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
  const shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

  usint sizeQ = paramsQ->GetParams().size();
  usint sizeQP = paramsQP->GetParams().size();

  const DCRTPoly &sOld = oldSk->GetPrivateElement();
  const DCRTPoly &pNew0 = newPk->GetPublicElements().at(0);
  const DCRTPoly &pNew1 = newPk->GetPublicElements().at(1);

  const DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DCRTPoly::TugType tug;

  DCRTPoly v;
  if (cryptoParams->GetMode() == RLWE)
    v = DCRTPoly(dgg, paramsQP, Format::EVALUATION);
  else
    v = DCRTPoly(tug, paramsQP, Format::EVALUATION);

  const DCRTPoly e0(dgg, paramsQP, Format::EVALUATION);
  const DCRTPoly e1(dgg, paramsQP, Format::EVALUATION);

  DCRTPoly a(paramsQP, Format::EVALUATION, true);
  DCRTPoly b(paramsQP, Format::EVALUATION, true);

  vector<NativeInteger> PModq = cryptoParams->GetPModq();

  for (usint i = 0; i < sizeQ; i++) {
    auto vi = v.GetElementAtIndex(i);
    auto e0i = e0.GetElementAtIndex(i);
    auto e1i = e1.GetElementAtIndex(i);
    auto pNew0i = pNew0.GetElementAtIndex(i);
    auto pNew1i = pNew1.GetElementAtIndex(i);
    auto sOldi = sOld.GetElementAtIndex(i);
    b.SetElementAtIndex(i, vi * pNew0i + PModq[i] * sOldi + e0i);
    a.SetElementAtIndex(i, vi * pNew1i + e1i);
  }

  for (usint i = sizeQ; i < sizeQP; i++) {
    auto vi = v.GetElementAtIndex(i);
    auto e0i = e0.GetElementAtIndex(i);
    auto e1i = e1.GetElementAtIndex(i);
    auto pNew0i = pNew0.GetElementAtIndex(i);
    auto pNew1i = pNew1.GetElementAtIndex(i);
    b.SetElementAtIndex(i, vi * pNew0i + e0i);
    a.SetElementAtIndex(i, vi * pNew1i + e1i);
  }

  vector<DCRTPoly> av = {a};
  vector<DCRTPoly> bv = {b};

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPRECKKS<DCRTPoly>::ReKeyGen(
    const LPPublicKey<DCRTPoly> newPk,
    const LPPrivateKey<DCRTPoly> oldSk) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          newPk->GetCryptoParameters());

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    return ReKeyGenBV(newPk, oldSk);
  } else if (cryptoParams->GetKeySwitchTechnique() == GHS) {
    std::string errMsg =
        "ReKeyGen - Proxy re-encryption not supported when using GHS key "
        "switching.";
    PALISADE_THROW(not_available_error, errMsg);
  } else {  // Hybrid
    std::string errMsg =
        "ReKeyGen - Proxy re-encryption not supported when using HYBRID key "
        "switching.";
    PALISADE_THROW(not_available_error, errMsg);
  }
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmPRECKKS<DCRTPoly>::ReEncrypt(
    const LPEvalKey<DCRTPoly> ek, ConstCiphertext<DCRTPoly> ciphertext,
    const LPPublicKey<DCRTPoly> publicKey) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
          ek->GetCryptoParameters());

  if (cryptoParams->GetKeySwitchTechnique() != BV) {
    std::string errMsg =
        "ReEncrypt - Proxy re-encryption is only supported when using BV key "
        "switching.";
    PALISADE_THROW(not_available_error, errMsg);
  }

  if (publicKey == nullptr) {  // Sender PK is not provided - CPA-secure PRE
    return ciphertext->GetCryptoContext()->KeySwitch(ek, ciphertext);
  } else {  // Sender PK provided - HRA-secure PRE
    // Get crypto and elements parameters
    const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

    const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
    TugType tug;

    PlaintextEncodings encType = ciphertext->GetEncodingType();

    Ciphertext<DCRTPoly> zeroCiphertext(
        std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));
    zeroCiphertext->SetEncodingType(encType);

    const std::vector<DCRTPoly> &pk = publicKey->GetPublicElements();

    const DCRTPoly &b = pk[0];
    const DCRTPoly &a = pk[1];

    DCRTPoly u;

    if (cryptoParams->GetMode() == RLWE)
      u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
    else
      u = DCRTPoly(tug, elementParams, Format::EVALUATION);

    DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
    DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

    DCRTPoly c0 = b * u + e0;
    DCRTPoly c1 = a * u + e1;

    zeroCiphertext->SetElements({std::move(c0), std::move(c1)});

    // Add the encryption of zero for re-randomization purposes
    auto c = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->EvalAdd(
        ciphertext, zeroCiphertext);

    ciphertext->GetCryptoContext()->KeySwitchInPlace(ek, c);
    return c;
  }
}

}  // namespace lbcrypto
