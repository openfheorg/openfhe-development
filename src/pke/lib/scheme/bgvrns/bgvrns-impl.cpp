// @file bgvrns-impl.cpp - BGVrns dcrtpoly implementation.
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

This code implements an RNS variant of the Brakerski-Gentry-Vaikuntanathan scheme.

The BGV scheme is introduced in the following paper:
- Zvika Brakerski, Craig Gentry, and Vinod Vaikuntanathan. (leveled) fully homomorphic
encryption without bootstrapping. ACM Transactions on Computation
Theory (TOCT), 6(3):13, 2014.

 Our implementation builds from the designs here:
 - Craig Gentry, Shai Halevi, and Nigel P Smart. Homomorphic evaluation of the
aes circuit. In Advances in Cryptology–CRYPTO 2012, pages 850–867. Springer,
2012.
 - Andrey Kim, Yuriy Polyakov, and Vincent Zucca. Revisiting homomorphic encryption
schemes for finite fields. Cryptology ePrint Archive, Report 2021/204,
2021. https://eprint.iacr.org/2021/204.
 */

#define PROFILE

#include "bgvrns.cpp"
#include "cryptocontext.h"

namespace lbcrypto {

#define NOPOLY                                                                \
  std::string errMsg = "BGVrns does not support Poly. Use DCRTPoly instead."; \
  PALISADE_THROW(not_implemented_error, errMsg);

#define NONATIVEPOLY                                               \
  std::string errMsg =                                             \
      "BGVrns does not support NativePoly. Use DCRTPoly instead."; \
  PALISADE_THROW(not_implemented_error, errMsg);

template <>
bool LPCryptoParametersBGVrns<Poly>::PrecomputeCRTTables(
    KeySwitchTechnique ksTech, uint32_t dnum) {
  NOPOLY
}

template <>
bool LPCryptoParametersBGVrns<NativePoly>::PrecomputeCRTTables(
    KeySwitchTechnique ksTech, uint32_t dnum) {
  NONATIVEPOLY
}

// Precomputation of CRT tables encryption, decryption, and homomorphic
// multiplication
template <>
bool LPCryptoParametersBGVrns<DCRTPoly>::PrecomputeCRTTables(
    KeySwitchTechnique ksTech, uint32_t numLargeDigits) {
  // Set the key switching technique. This determines what CRT values we
  // need to precompute.
  m_ksTechnique = ksTech;
  m_numPartQ = numLargeDigits;

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
  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsQ, 2 * n,
                                                         moduliQ);

  if (m_ksTechnique == HYBRID) {
    // Compute alpha = ceil(sizeQ / numPartQ)
    uint32_t a = ceil(static_cast<double>(sizeQ) / m_numPartQ);
    if (static_cast<int32_t>(sizeQ - a * (m_numPartQ - 1)) <= 0) {
      auto str =
          "LLPCryptoParametersBGVrns<DCRTPoly>::PrecomputeCRTTables - HYBRID "
          "key "  //  "switching parameters: Can't appropriately distribute
                  // " + to_string(numPrimesQ) +
          " towers into " +
          std::to_string(m_numPartQ) +
          " digits. Please select different number of digits.";
      PALISADE_THROW(math_error, str);
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

  size_t PModSize = 60;
  uint32_t sizeP = 1;

  if (m_ksTechnique == GHS) {
    // Select number and size of special primes in auxiliary CRT basis
    PModSize = 60;
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
    PModSize = 60;
    sizeP = ceil(static_cast<double>(maxBits) / PModSize);
  }

  if (m_ksTechnique == GHS || m_ksTechnique == HYBRID) {
    // For KeySwitching to work we need the moduli to be also congruent to 1
    // modulo ptm
    usint plaintextModulus = GetPlaintextModulus();
    usint cyclOrder = 2 * n;
    usint pow2ptm = 1;

    // The largest power of 2 dividing ptm
    // Check whether it is larger than cyclOrder or not
    while (plaintextModulus % 2 == 0) {
      plaintextModulus >>= 1;
      pow2ptm <<= 1;
    }

    if (pow2ptm < cyclOrder) pow2ptm = cyclOrder;

    uint64_t lcmCyclOrderPtm =
        static_cast<uint64_t>(pow2ptm) * plaintextModulus;

    // Choose special primes in auxiliary basis and compute their roots
    // moduliP holds special primes p1, p2, ..., pk
    // m_modulusP holds the product of special primes P = p1*p2*...pk
    vector<NativeInteger> moduliP(sizeP);
    vector<NativeInteger> rootsP(sizeP);
    // firstP contains a prime whose size is PModSize.
    NativeInteger firstP = FirstPrime<NativeInteger>(PModSize, lcmCyclOrderPtm);
    NativeInteger pPrev = firstP;
    m_modulusP = BigInteger(1);
    for (usint i = 0; i < sizeP; i++) {
      // The following loop makes sure that moduli in
      // P and Q are different
      bool foundInQ = false;
      do {
        moduliP[i] = PreviousPrime<NativeInteger>(pPrev, lcmCyclOrderPtm);
        foundInQ = false;
        for (usint j = 0; j < sizeQ; j++)
          if (moduliP[i] == moduliQ[j]) foundInQ = true;
        pPrev = moduliP[i];
      } while (foundInQ);
      rootsP[i] = RootOfUnity<NativeInteger>(cyclOrder, moduliP[i]);
      m_modulusP *= moduliP[i];
      pPrev = moduliP[i];
    }

    // Store the created moduli and roots in m_paramsP
    m_paramsP =
        std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliP, rootsP);

    // Create the moduli and roots for the extended CRT basis QP
    vector<NativeInteger> moduliQP(sizeQ + sizeP);
    vector<NativeInteger> rootsQP(sizeQ + sizeP);
    for (size_t i = 0; i < sizeQ; i++) {
      moduliQP[i] = moduliQ[i];
      rootsQP[i] = rootsQ[i];
    }
    for (size_t i = 0; i < sizeP; i++) {
      moduliQP[sizeQ + i] = moduliP[i];
      rootsQP[sizeQ + i] = rootsP[i];
    }

    m_paramsQP =
        std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQP, rootsQP);

    // Pre-compute CRT::FFT values for P
    ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsP, 2 * n,
                                                           moduliP);

    NativeInteger t(GetPlaintextModulus());

    // Pre-compute values [t^{-1}]_{q_i}, precomputations for  [t]_{q_i}
    m_tInvModq.resize(sizeQ);
    m_tInvModqPrecon.resize(sizeQ);
    for (usint i = 0; i < sizeQ; i++) {
      m_tInvModq[i] = t.ModInverse(moduliQ[i]);
      m_tInvModqPrecon[i] = m_tInvModq[i].PrepModMulConst(moduliQ[i]);
    }

    // Pre-compute values [t^{-1}]_{p_i}, precomputations for [t]_{q_i}
    m_tInvModp.resize(sizeP);
    m_tInvModpPrecon.resize(sizeP);
    m_tModpPrecon.resize(sizeP);
    for (usint j = 0; j < sizeP; j++) {
      m_tInvModp[j] = t.ModInverse(moduliP[j]);
      m_tInvModpPrecon[j] = m_tInvModp[j].PrepModMulConst(moduliP[j]);
      m_tModpPrecon[j] = t.PrepModMulConst(moduliP[j]);
    }

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

    // Pre-compute values [P/p_j]_{q_i}
    // Pre-compute values [(P/p_j)^{-1}]_{p_j}
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

    // Pre-compute values [Q/q_i]_{p_j}
    // Pre-compute values [(Q/q_i)^{-1}]_{q_i}
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

    // Pre-compute compementary partitions for ModUp
    if (m_ksTechnique == HYBRID) {
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

      // Pre-compute QHat mod complementary partition q_i's
      m_LvlPartQHatModp.resize(sizeQ);
      for (uint32_t l = 0; l < sizeQ; l++) {
        uint32_t alpha = ceil(static_cast<double>(sizeQ) / m_numPartQ);
        uint32_t beta = ceil(static_cast<double>(l + 1) / alpha);
        m_LvlPartQHatModp[l].resize(beta);
        for (uint32_t k = 0; k < beta; k++) {
          auto partition = GetParamsPartQ(k)->GetParams();
          auto Q = GetParamsPartQ(k)->GetModulus();
          uint32_t digitSize = partition.size();
          if (k == beta - 1) {
            digitSize = l + 1 - k * alpha;
            for (uint32_t idx = digitSize; idx < partition.size(); idx++) {
              Q = Q / BigInteger(partition[idx]->GetModulus());
            }
          }

          m_LvlPartQHatModp[l][k].resize(digitSize);
          for (uint32_t i = 0; i < digitSize; i++) {
            BigInteger QHat = Q / BigInteger(partition[i]->GetModulus());
            auto complBasis = GetParamsComplPartQ(l, k);
            m_LvlPartQHatModp[l][k][i].resize(complBasis->GetParams().size());
            for (size_t j = 0; j < complBasis->GetParams().size(); j++) {
              BigInteger QHatModpj =
                  QHat.Mod(complBasis->GetParams()[j]->GetModulus());
              m_LvlPartQHatModp[l][k][i][j] = QHatModpj.ConvertToInt();
            }
          }
        }
      }
    }
  }

  NativeInteger t(GetPlaintextModulus());
  m_negtInvModq.resize(sizeQ);
  m_negtInvModqPrecon.resize(sizeQ);
  m_tModqPrecon.resize(sizeQ);
  m_qInvModq.resize(sizeQ);
  m_qInvModqPrecon.resize(sizeQ);
  for (usint i = 0; i < sizeQ; i++) {
    m_negtInvModq[i] = moduliQ[i] - t.ModInverse(moduliQ[i]);
    m_negtInvModqPrecon[i] = m_negtInvModq[i].PrepModMulConst(moduliQ[i]);
    m_tModqPrecon[i] = t.PrepModMulConst(moduliQ[i]);
    m_qInvModq[i].resize(i);
    m_qInvModqPrecon[i].resize(i);
    for (usint j = 0; j < i; ++j) {
      m_qInvModq[i][j] = moduliQ[i].ModInverse(moduliQ[j]);
      m_qInvModqPrecon[i][j] = m_qInvModq[i][j].PrepModMulConst(moduliQ[j]);
    }
  }

  return true;
}

template <>
bool LPAlgorithmParamsGenBGVrns<Poly>::ParamsGen(
    shared_ptr<LPCryptoParameters<Poly>> cryptoParams, usint cyclOrder,
    usint ptm, usint numPrimes, usint relinWindow, MODE mode,
    KeySwitchTechnique ksTech, usint firstModSize, usint dcrtBits,
    uint32_t numLargeDigits) const {
  NOPOLY
}

template <>
bool LPAlgorithmParamsGenBGVrns<NativePoly>::ParamsGen(
    shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams, usint cyclOrder,
    usint ptm, usint numPrimes, usint relinWindow, MODE mode,
    enum KeySwitchTechnique ksTech, usint firstModSize, usint dcrtBits,
    uint32_t numLargeDigits) const {
  NONATIVEPOLY
}

template <>
bool LPAlgorithmParamsGenBGVrns<DCRTPoly>::ParamsGen(
    shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams, usint cyclOrder,
    usint ptm, usint numPrimes, usint relinWindow, MODE mode,
    enum KeySwitchTechnique ksTech, usint firstModSize, usint dcrtBits,
    uint32_t numLargeDigits) const {
  const auto cryptoParamsBGVrns =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          cryptoParams);
  // Select the size of moduli according to the plaintext modulus (TODO:
  // optimized the bounds).
  if (dcrtBits == 0) {
    dcrtBits = 28 + GetMSB64(ptm);
    if (dcrtBits > 60) {
      dcrtBits = 60;
    }
  }

  // Select firstModSize to be dcrtBits if no indicated otherwise
  if (firstModSize == 0) firstModSize = dcrtBits;

  //// HE Standards compliance logic/check
  SecurityLevel stdLevel = cryptoParamsBGVrns->GetStdLevel();
  uint32_t PModSize = 60;
  uint32_t n = cyclOrder / 2;
  uint32_t qBound = 0;
  // Estimate ciphertext modulus Q bound (in case of GHS/HYBRID P*Q)
  qBound = firstModSize + (numPrimes - 1) * dcrtBits;
  if (ksTech == GHS)
    qBound += ceil(static_cast<double>(qBound) / PModSize) * PModSize;
  else if (ksTech == HYBRID)
    qBound +=
        ceil(ceil(static_cast<double>(qBound) / numLargeDigits) / PModSize) *
        PModSize;

  // RLWE security constraint
  DistributionType distType =
      (cryptoParamsBGVrns->GetMode() == RLWE) ? HEStd_error : HEStd_ternary;
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
            math_error,
            "The specified ring dimension (" + std::to_string(n) +
                ") does not comply with HE standards recommendation (" +
                std::to_string(he_std_n) + ").");
      }
    }
  } else if (n == 0) {
    PALISADE_THROW(
        math_error,
        "Please specify the ring dimension or desired security level.");
  }
  //// End HE Standards compliance logic/check

  vector<NativeInteger> moduliQ(numPrimes);
  vector<NativeInteger> rootsQ(numPrimes);

  // For ModulusSwitching to work we need the moduli to be also congruent to 1
  // modulo ptm
  usint plaintextModulus = ptm;
  usint pow2ptm = 1;  // The largest power of 2 dividing ptm (check whether it
                      // is larger than cyclOrder or not)
  while (plaintextModulus % 2 == 0) {
    plaintextModulus >>= 1;
    pow2ptm <<= 1;
  }

  if (pow2ptm < cyclOrder) pow2ptm = cyclOrder;

  uint64_t lcmCyclOrderPtm = (uint64_t)pow2ptm * plaintextModulus;

  // Get the largest prime with size less or equal to firstModSize bits.
  NativeInteger firstInteger =
      FirstPrime<NativeInteger>(firstModSize, lcmCyclOrderPtm);

  while (firstInteger > ((uint64_t)1 << firstModSize))
    firstInteger = PreviousPrime<NativeInteger>(firstInteger, lcmCyclOrderPtm);

  moduliQ[0] = PreviousPrime<NativeInteger>(firstInteger, lcmCyclOrderPtm);
  rootsQ[0] = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[0]);

  if (numPrimes > 1) {
    NativeInteger q = (firstModSize != dcrtBits)
                          ? FirstPrime<NativeInteger>(dcrtBits, lcmCyclOrderPtm)
                          : moduliQ[0];

    moduliQ[1] = PreviousPrime<NativeInteger>(q, lcmCyclOrderPtm);
    rootsQ[1] = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[1]);

    for (size_t i = 2; i < numPrimes; i++) {
      moduliQ[i] =
          PreviousPrime<NativeInteger>(moduliQ[i - 1], lcmCyclOrderPtm);
      rootsQ[i] = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[i]);
    }
  }

  auto paramsDCRT =
      std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliQ, rootsQ);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootsQ, cyclOrder,
                                                         moduliQ);

  cryptoParamsBGVrns->SetElementParams(paramsDCRT);

  const EncodingParams encodingParams = cryptoParamsBGVrns->GetEncodingParams();
  if (encodingParams->GetBatchSize() > n)
    PALISADE_THROW(config_error,
                   "The batch size cannot be larger than the ring dimension.");

  // if no batch size was specified compute a default value
  if (encodingParams->GetBatchSize() == 0) {
    // Check whether ptm and cyclOrder are coprime
    usint a, b, gcd;
    if (cyclOrder > ptm) {
      a = cyclOrder;
      b = ptm;
    } else {
      b = cyclOrder;
      a = ptm;
    }

    gcd = b;
    while (b != 0) {
      gcd = b;
      b = a % b;
      a = gcd;
    }

    // if ptm and CyclOrder are not coprime we set batchSize = n by default (for
    // full packing)
    uint32_t batchSize;
    if (gcd != 1) {
      batchSize = n;
    } else {  // set batchsize to the actual batchsize i.e. n/d where d is the
              // order of ptm mod CyclOrder
      a = (uint64_t)ptm % cyclOrder;
      b = 1;
      while (a != 1) {
        a = ((uint64_t)(a * ptm)) % cyclOrder;
        b++;
      }

      if (n % b != 0)
        PALISADE_THROW(math_error,
                       "BGVrns.ParamsGen: something went wrong when computing "
                       "the batchSize");

      batchSize = n / b;
    }

    EncodingParams encodingParamsNew(std::make_shared<EncodingParamsImpl>(
        encodingParams->GetPlaintextModulus(), batchSize));
    cryptoParamsBGVrns->SetEncodingParams(encodingParamsNew);
  }

  return cryptoParamsBGVrns->PrecomputeCRTTables(ksTech, numLargeDigits);
}

template <>
Ciphertext<NativePoly> LPAlgorithmBGVrns<NativePoly>::Encrypt(
    const LPPublicKey<NativePoly> publicKey, NativePoly ptxt) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBGVrns<Poly>::Encrypt(
    const LPPublicKey<Poly> publicKey, Poly ptxt) const {
  NOPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmBGVrns<DCRTPoly>::Encrypt(
    const LPPublicKey<DCRTPoly> publicKey, DCRTPoly ptxt) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          publicKey->GetCryptoParameters());
  const auto t = cryptoParams->GetPlaintextModulus();

  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

  const shared_ptr<ParmType> ptxtParams = ptxt.GetParams();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

  TugType tug;

  ptxt.SetFormat(EVALUATION);

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
    DCRTPoly b(pk[0]);
    DCRTPoly a(pk[1]);

    int diffQl = sizeQ - sizeQl;
    b.DropLastElements(diffQl);
    a.DropLastElements(diffQl);

    c0 = b * v + t * e0 + ptxt;
    c1 = a * v + t * e1;
  } else {
    // Use public keys as they are
    const DCRTPoly &b = pk[0];
    const DCRTPoly &a = pk[1];

    c0 = b * v + t * e0 + ptxt;
    c1 = a * v + t * e1;
  }

  cv.push_back(std::move(c0));
  cv.push_back(std::move(c1));

  ciphertext->SetElements(std::move(cv));

  // Ciphertext depth and level, should be equal to that
  // of the plaintext. However, Encrypt does
  // not take Plaintext as input (only DCRTPoly), so we
  // don't have access to these here, and we set them in
  // the crypto context Encrypt method.
  ciphertext->SetDepth(1);
  ciphertext->SetLevel(1);

  return ciphertext;
}

template <>
Ciphertext<NativePoly> LPAlgorithmBGVrns<NativePoly>::Encrypt(
    const LPPrivateKey<NativePoly> privateKey, NativePoly ptxt) const {
  NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBGVrns<Poly>::Encrypt(
    const LPPrivateKey<Poly> privateKey, Poly ptxt) const {
  NOPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmBGVrns<DCRTPoly>::Encrypt(
    const LPPrivateKey<DCRTPoly> privateKey, DCRTPoly ptxt) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          privateKey->GetCryptoParameters());

  const auto t = cryptoParams->GetPlaintextModulus();

  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));

  const shared_ptr<ParmType> ptxtParams = ptxt.GetParams();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

  ptxt.SetFormat(EVALUATION);

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

    c0 = a * scopy + t * e + ptxt;
    c1 = -a;
  } else {
    // Use secret key as is
    c0 = a * s + t * e + ptxt;
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
  ciphertext->SetLevel(1);

  return ciphertext;
}

template <>
DecryptResult LPAlgorithmBGVrns<Poly>::Decrypt(
    const LPPrivateKey<Poly> privateKey, ConstCiphertext<Poly> ciphertext,
    NativePoly *plaintext) const {
  std::string errMsg =
      "BGVrns: Decryption to NativePoly from Poly is not supported as it may "
      "lead to incorrect results.";
  PALISADE_THROW(not_available_error, errMsg);
}

template <>
DecryptResult LPAlgorithmBGVrns<Poly>::Decrypt(
    const LPPrivateKey<Poly> privateKey, ConstCiphertext<Poly> ciphertext,
    Poly *plaintext) const {
  NOPOLY
}

template <>
DecryptResult LPAlgorithmBGVrns<NativePoly>::Decrypt(
    const LPPrivateKey<NativePoly> privateKey,
    ConstCiphertext<NativePoly> ciphertext, Poly *plaintext) const {
  std::string errMsg =
      "BGVrns: Decryption to Poly from NativePoly is not supported as it may "
      "lead to incorrect results.";
  PALISADE_THROW(not_available_error, errMsg);
}

template <>
DecryptResult LPAlgorithmBGVrns<DCRTPoly>::Decrypt(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext, Poly *plaintext) const {
  std::string errMsg =
      "BGVrns: Decryption to Poly from DCRTPoly is not supported as it may "
      "lead to incorrect results.";
  PALISADE_THROW(not_available_error, errMsg);
}

template <>
DecryptResult LPAlgorithmBGVrns<NativePoly>::Decrypt(
    const LPPrivateKey<NativePoly> privateKey,
    ConstCiphertext<NativePoly> ciphertext, NativePoly *plaintext) const {
  NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmBGVrns<DCRTPoly>::Decrypt(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext, NativePoly *plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());
  const NativeInteger t = cryptoParams->GetPlaintextModulus();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  const DCRTPoly &s = privateKey->GetPrivateElement();

  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t sizeQ = s.GetParams()->GetParams().size();

  size_t diffQl = sizeQ - sizeQl;

  auto scopy(s);
  scopy.DropLastElements(diffQl);

  DCRTPoly sPower(scopy);

  DCRTPoly b, ci;

  // If ciphertext in EVALUATION format
  // evaluate on the secret key first then ModReduce
  // otherwise ModReduce first and then evaluate on the secret key.
  if (cv[0].GetFormat() == Format::EVALUATION) {
    b = cv[0];
    for (size_t i = 1; i < cv.size(); i++) {
      ci = cv[i];
      ci.SetFormat(Format::EVALUATION);

      b += sPower * ci;
      sPower *= scopy;
    }
    b.SetFormat(Format::COEFFICIENT);

    // TODO drop all the towers in one ModReduce() (only small expected gain
    // because at this point everything is in COEFFICIENT Format)
    for (usint l = sizeQl - 1; l > 0; l--) {
      const vector<NativeInteger> &tModqPrecon = cryptoParams->GettModqPrecon();
      const NativeInteger &negtInvModq = cryptoParams->GetNegtInvModq(l);
      const NativeInteger &negtInvModqPrecon =
          cryptoParams->GetNegtInvModqPrecon(l);
      const vector<NativeInteger> &qlInvModq = cryptoParams->GetqlInvModq(l);
      const vector<NativeInteger> &qlInvModqPrecon =
          cryptoParams->GetqlInvModqPrecon(l);
      b.ModReduce(t, tModqPrecon, negtInvModq, negtInvModqPrecon, qlInvModq,
                  qlInvModqPrecon);
    }
  } else {
    std::vector<DCRTPoly> ct(cv);
    // TODO drop all the towers in one ModReduce() (only small expected gain
    // because at this point everything is in COEFFICIENT Format)
    for (usint l = sizeQl - 1; l > 0; l--) {
      const vector<NativeInteger> &tModqPrecon = cryptoParams->GettModqPrecon();
      const NativeInteger &negtInvModq = cryptoParams->GetNegtInvModq(l);
      const NativeInteger &negtInvModqPrecon =
          cryptoParams->GetNegtInvModqPrecon(l);
      const vector<NativeInteger> &qlInvModq = cryptoParams->GetqlInvModq(l);
      const vector<NativeInteger> &qlInvModqPrecon =
          cryptoParams->GetqlInvModqPrecon(l);
      for (usint i = 0; i < ct.size(); i++) {
        ct[i].ModReduce(t, tModqPrecon, negtInvModq, negtInvModqPrecon,
                        qlInvModq, qlInvModqPrecon);
      }
    }

    b = ct[1];
    b.SetFormat(Format::EVALUATION);
    for (size_t i = 2; i < ct.size(); i++) {
      ci = ct[i];
      ci.SetFormat(Format::EVALUATION);

      b += sPower * ci;
      sPower *= s;
    }
    b *= s;
    b.SetFormat(Format::COEFFICIENT);
    b += ct[0];
  }

  *plaintext = b.GetElementAtIndex(0).Mod(t);

  return DecryptResult(plaintext->GetLength());
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBGVrns<Poly>::KeySwitchBVGen(
    const LPPrivateKey<Poly> oldKey, const LPPrivateKey<Poly> newKey,
    const LPEvalKey<DCRTPoly> ek) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::KeySwitchBVGen(
    const LPPrivateKey<NativePoly> oldKey,
    const LPPrivateKey<NativePoly> newKey, const LPEvalKey<DCRTPoly> ek) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::KeySwitchBVGen(
    const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  LPEvalKeyRelin<DCRTPoly> ek(std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(
      newKey->GetCryptoContext()));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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
    nWindows = sOld.GetNumOfElements();
  }

  std::vector<DCRTPoly> bv(nWindows);
  std::vector<DCRTPoly> av(nWindows);

  // Get the plaintext modulus
  const auto t = cryptoParams->GetPlaintextModulus();

#pragma omp parallel for
  for (usint i = 0; i < sizeSOld; i++) {
    DugType dug;

    if (relinWindow > 0) {
      vector<typename DCRTPoly::PolyType> sOldDecomposed =
          sOld.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (size_t k = 0; k < sOldDecomposed.size(); k++) {
        // Creates an element with all zeroes
        DCRTPoly filtered(elementParams, EVALUATION, true);

        filtered.SetElementAtIndex(i, sOldDecomposed[k]);

        if (ekPrev == nullptr) {  // single-key HE
          // Generate a_i vectors
          DCRTPoly a(dug, elementParams, Format::EVALUATION);
          av[k + arrWindows[i]] = a;
        } else {  // threshold HE
          av[k + arrWindows[i]] = ekPrev->GetAVector()[k + arrWindows[i]];
        }

        // Generate a_i * skNew + t * e - skOld_k
        DCRTPoly e(dgg, elementParams, Format::EVALUATION);
        bv[k + arrWindows[i]] =
            filtered - (av[k + arrWindows[i]] * sNew + t * e);
      }
    } else {
      // Creates an element with all zeroes
      DCRTPoly filtered(elementParams, EVALUATION, true);

      filtered.SetElementAtIndex(i, sOld.GetElementAtIndex(i));

      if (ekPrev == nullptr) {  // single-key HE
        // Generate a_i vectors
        DCRTPoly a(dug, elementParams, Format::EVALUATION);
        av[i] = a;
      } else {  // threshold HE
        av[i] = ekPrev->GetAVector()[i];
      }

      // Generate a_i * skNew + t * e - skOld
      DCRTPoly e(dgg, elementParams, Format::EVALUATION);
      bv[i] = filtered - (av[i] * sNew + t * e);
    }
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <>
void LPAlgorithmSHEBGVrns<Poly>::KeySwitchBVInPlace(
    const LPEvalKey<Poly> ek, Ciphertext<Poly>& ciphertext) const {
  NOPOLY
}

template <>
void LPAlgorithmSHEBGVrns<NativePoly>::KeySwitchBVInPlace(
    const LPEvalKey<NativePoly> ek,
    Ciphertext<NativePoly>& ciphertext) const {
  NONATIVEPOLY
}

template <>
void LPAlgorithmSHEBGVrns<DCRTPoly>::KeySwitchBVInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly>& ciphertext) const {
  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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

  // in the case of EvalMult, c[0] is initially in coefficient format and needs
  // to be switched to evaluation format
  cv[0].SetFormat(Format::EVALUATION);

  DCRTPoly ct1;

  std::vector<DCRTPoly> digitsC2;
  if (cv.size() == 2) {
    // case of PRE or automorphism
    digitsC2 = cv[1].CRTDecompose(relinWindow);
    cv[1] = digitsC2[0] * av[0];
  } else {
    // case of EvalMult
    digitsC2 = cv[2].CRTDecompose(relinWindow);
    cv[1].SetFormat(EVALUATION);
    cv[1] += digitsC2[0] * av[0];
  }

  cv[0] += digitsC2[0] * bv[0];

  for (usint i = 1; i < digitsC2.size(); ++i) {
    cv[0] += digitsC2[i] * bv[i];
    cv[1] += digitsC2[i] * av[i];
  }
  cv.resize(2);
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBGVrns<Poly>::KeySwitchGHSGen(
    const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::KeySwitchGHSGen(
    const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::KeySwitchGHSGen(
    const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  auto cc = newKey->GetCryptoContext();
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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
    NativeInteger pj = paramsQP->GetParams()[j]->GetModulus();
    NativeInteger rooti = paramsQP->GetParams()[j]->GetRootOfUnity();
    auto sNew0 = sNew.GetElementAtIndex(0);
    sNew0.SwitchModulus(pj, rooti);
    sNewExt.SetElementAtIndex(j, std::move(sNew0));
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

  // Get the plaintext modulus
  const auto t = cryptoParams->GetPlaintextModulus();

  vector<NativeInteger> PModq = cryptoParams->GetPModq();

  // The part with basis Q
  for (usint i = 0; i < sizeQ; i++) {
    auto ai = a.GetElementAtIndex(i);
    auto ei = e.GetElementAtIndex(i);
    auto sNewi = sNewExt.GetElementAtIndex(i);
    auto sOldi = sOld.GetElementAtIndex(i);
    b.SetElementAtIndex(i, -ai * sNewi + PModq[i] * sOldi + t * ei);
  }

  // The part with basis P
  for (usint i = sizeQ; i < sizeQP; i++) {
    auto ai = a.GetElementAtIndex(i);
    auto ei = e.GetElementAtIndex(i);
    auto sNewExti = sNewExt.GetElementAtIndex(i);
    b.SetElementAtIndex(i, -ai * sNewExti + t * ei);
  }

  vector<DCRTPoly> av = {a};
  vector<DCRTPoly> bv = {b};

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <>
void LPAlgorithmSHEBGVrns<Poly>::KeySwitchGHSInPlace(
    const LPEvalKey<Poly> ek, Ciphertext<Poly>& ciphertext) const {
  NOPOLY
}

template <>
void LPAlgorithmSHEBGVrns<NativePoly>::KeySwitchGHSInPlace(
    const LPEvalKey<NativePoly> ek,
    Ciphertext<NativePoly>& ciphertext) const {
  NONATIVEPOLY
}

template <>
void LPAlgorithmSHEBGVrns<DCRTPoly>::KeySwitchGHSInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly>& ciphertext) const {

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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

  //cTilda0.SetFormat(Format::COEFFICIENT);
  //cTilda1.SetFormat(Format::COEFFICIENT);

  // Get the plaintext modulus
  const NativeInteger t(cryptoParams->GetPlaintextModulus());

  DCRTPoly ct0 = cTilda0.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

  DCRTPoly ct1 = cTilda1.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

  //ct0.SetFormat(Format::EVALUATION);
  //ct1.SetFormat(Format::EVALUATION);

  ct0 += cv[0];
  // case of EvalMult
  if (cv.size() > 2) {
    ct1 += cv[1];
  }

  ciphertext->SetElements({std::move(ct0), std::move(ct1)});
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBGVrns<Poly>::KeySwitchHybridGen(
    const LPPrivateKey<Poly> oldKey, const LPPrivateKey<Poly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::KeySwitchHybridGen(
    const LPPrivateKey<NativePoly> oldKey,
    const LPPrivateKey<NativePoly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::KeySwitchHybridGen(
    const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
    const LPEvalKey<DCRTPoly> ekPrev) const {
  auto cc = newKey->GetCryptoContext();
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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

  // Get the plaintext modulus
  const auto t = cryptoParams->GetPlaintextModulus();

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
      b.SetElementAtIndex(i, -ai * sNewi + factor * sOldi + t * ei);
    }

    // The part with basis P
    for (usint j = sizeQ; j < sizeQP; j++) {
      auto aj = a.GetElementAtIndex(j);
      auto ej = e.GetElementAtIndex(j);
      auto sNewExtj = sNewExt.GetElementAtIndex(j);
      b.SetElementAtIndex(j, -aj * sNewExtj + t * ej);
    }

    av[part] = a;
    bv[part] = b;
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <>
void LPAlgorithmSHEBGVrns<Poly>::KeySwitchHybridInPlace(
    const LPEvalKey<Poly> ek, Ciphertext<Poly> &ciphertext) const {
  NOPOLY
}

template <>
void LPAlgorithmSHEBGVrns<NativePoly>::KeySwitchHybridInPlace(
    const LPEvalKey<NativePoly> ek, Ciphertext<NativePoly> &ciphertext) const {
  NONATIVEPOLY
}

template <>
void LPAlgorithmSHEBGVrns<DCRTPoly>::KeySwitchHybridInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly> &ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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

  //cTilda0.SetFormat(Format::COEFFICIENT);
  //cTilda1.SetFormat(Format::COEFFICIENT);

  // Get the plaintext modulus
  const NativeInteger t(cryptoParams->GetPlaintextModulus());

  DCRTPoly ct0 = cTilda0.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

  DCRTPoly ct1 = cTilda1.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

  //ct0.SetFormat(Format::EVALUATION);
  //ct1.SetFormat(Format::EVALUATION);

  ct0 += cv[0];
  // case of EvalMult
  if (cv.size() > 2) {
    ct1 += cv[1];
  }

  ciphertext->SetElements({std::move(ct0), std::move(ct1)});
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBGVrns<Poly>::KeySwitchGen(
    const LPPrivateKey<Poly> oldKey, const LPPrivateKey<Poly> newKey) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::KeySwitchGen(
    const LPPrivateKey<NativePoly> oldKey,
    const LPPrivateKey<NativePoly> newKey) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::KeySwitchGen(
    const LPPrivateKey<DCRTPoly> oldKey,
    const LPPrivateKey<DCRTPoly> newKey) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          newKey->GetCryptoParameters());

  switch (cryptoParams->GetKeySwitchTechnique()) {
    case BV:
      return KeySwitchBVGen(oldKey, newKey);
    case GHS:
      return KeySwitchGHSGen(oldKey, newKey);
    default:  // Hybrid
      return KeySwitchHybridGen(oldKey, newKey);
  }
}

template <>
void LPAlgorithmSHEBGVrns<Poly>::KeySwitchInPlace(
    const LPEvalKey<Poly> ek, Ciphertext<Poly>& ciphertext) const {
  NOPOLY
}

template <>
void LPAlgorithmSHEBGVrns<NativePoly>::KeySwitchInPlace(
    const LPEvalKey<NativePoly> ek,
    Ciphertext<NativePoly>& ciphertext) const {
  NONATIVEPOLY
}

template <>
void LPAlgorithmSHEBGVrns<DCRTPoly>::KeySwitchInPlace(
    const LPEvalKey<DCRTPoly> ek, Ciphertext<DCRTPoly> &ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  switch (cryptoParams->GetKeySwitchTechnique()) {
    case BV:
      KeySwitchBVInPlace(ek, ciphertext);
      break;
    case GHS:
      KeySwitchGHSInPlace(ek, ciphertext);
      break;
    default:  // Hybrid
      KeySwitchHybridInPlace(ek, ciphertext);
      break;
  }
}

template <>
void LPLeveledSHEAlgorithmBGVrns<Poly>::ModReduceInternalInPlace(
    Ciphertext<Poly>& ciphertext, size_t levels) const {
  NOPOLY
}

template <>
void
LPLeveledSHEAlgorithmBGVrns<NativePoly>::ModReduceInternalInPlace(
    Ciphertext<NativePoly>& ciphertext, size_t levels) const {
  NONATIVEPOLY
}

template <>
void LPLeveledSHEAlgorithmBGVrns<DCRTPoly>::ModReduceInternalInPlace(
    Ciphertext<DCRTPoly>& ciphertext, size_t levels) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  std::vector<DCRTPoly>& cv = ciphertext->GetElements();

  const auto t = ciphertext->GetCryptoParameters()->GetPlaintextModulus();
  usint sizeQl = cv[0].GetNumOfElements();

  for (auto &c : cv) {
    for (size_t l = sizeQl - 1; l >= sizeQl - levels; --l) {
      const vector<NativeInteger> &tModqPrecon = cryptoParams->GettModqPrecon();
      const NativeInteger &negtInvModq = cryptoParams->GetNegtInvModq(l);
      const NativeInteger &negtInvModqPrecon =
          cryptoParams->GetNegtInvModqPrecon(l);
      const vector<NativeInteger> &qlInvModq = cryptoParams->GetqlInvModq(l);
      const vector<NativeInteger> &qlInvModqPrecon =
          cryptoParams->GetqlInvModqPrecon(l);
      c.ModReduce(t, tModqPrecon, negtInvModq, negtInvModqPrecon, qlInvModq,
                  qlInvModqPrecon);
    }
  }

  ciphertext->SetLevel(ciphertext->GetLevel() + levels);
  ciphertext->SetDepth(ciphertext->GetDepth() - levels);
}

template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmBGVrns<Poly>::ModReduceInternal(
    ConstCiphertext<Poly> ciphertext, size_t levels) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly>
LPLeveledSHEAlgorithmBGVrns<NativePoly>::ModReduceInternal(
    ConstCiphertext<NativePoly> ciphertext, size_t levels) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmBGVrns<DCRTPoly>::ModReduceInternal(
    ConstCiphertext<DCRTPoly> ciphertext, size_t levels) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  Ciphertext<DCRTPoly> result = ciphertext->Clone();
  ModReduceInternalInPlace(result, levels);
  return result;
}

template <>
void LPLeveledSHEAlgorithmBGVrns<Poly>::ModReduceInPlace(
    Ciphertext<Poly>& ciphertext, size_t levels) const {
  NOPOLY
}

template <>
void LPLeveledSHEAlgorithmBGVrns<NativePoly>::ModReduceInPlace(
    Ciphertext<NativePoly>& ciphertext, size_t levels) const {
  NONATIVEPOLY
}

template <>
void LPLeveledSHEAlgorithmBGVrns<DCRTPoly>::ModReduceInPlace(
    Ciphertext<DCRTPoly>& ciphertext, size_t levels) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());
  if (cryptoParams->GetModSwitchMethod() == MANUAL) {
    ModReduceInternalInPlace(ciphertext, levels);
  }
  // In AUTO, rescaling is performed automatically
}

template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmBGVrns<Poly>::Compress(
    ConstCiphertext<Poly> ciphertext, size_t towersLeft) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPLeveledSHEAlgorithmBGVrns<NativePoly>::Compress(
    ConstCiphertext<NativePoly> ciphertext, size_t towersLeft) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmBGVrns<DCRTPoly>::Compress(
    ConstCiphertext<DCRTPoly> ciphertext, size_t towersLeft) const {
  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  usint sizeQl = cv[0].GetNumOfElements();
  if (towersLeft >= sizeQl) {
    return std::make_shared<CiphertextImpl<DCRTPoly>>(*ciphertext);
  }
  return ModReduceInternal(ciphertext, sizeQl - towersLeft);
}

template <>
vector<shared_ptr<ConstCiphertext<DCRTPoly>>>
LPAlgorithmSHEBGVrns<DCRTPoly>::AdjustLevels(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  usint lvl1 = ciphertext1->GetLevel();
  usint lvl2 = ciphertext2->GetLevel();

  vector<shared_ptr<ConstCiphertext<DCRTPoly>>> ct(2);

  if (lvl1 < lvl2) {
    auto algo = ciphertext1->GetCryptoContext()->GetEncryptionAlgorithm();
    auto ct1 = algo->LevelReduceInternal(ciphertext1, nullptr, lvl2 - lvl1);
    ct[0] = std::make_shared<ConstCiphertext<DCRTPoly>>(ct1);
    ct[1] = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext2);
  } else if (lvl2 < lvl1) {
    auto algo = ciphertext1->GetCryptoContext()->GetEncryptionAlgorithm();
    auto ct2 = algo->LevelReduceInternal(ciphertext2, nullptr, lvl1 - lvl2);
    ct[0] = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext1);
    ct[1] = std::make_shared<ConstCiphertext<DCRTPoly>>(ct2);
  } else {
    ct[0] = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext1);
    ct[1] = std::make_shared<ConstCiphertext<DCRTPoly>>(ciphertext2);
  }

  return ct;
}

template <>
void LPAlgorithmSHEBGVrns<DCRTPoly>::AdjustLevelsEq(
    Ciphertext<DCRTPoly> &ciphertext1,
    Ciphertext<DCRTPoly> &ciphertext2) const {
  auto algo = ciphertext1->GetCryptoContext()->GetEncryptionAlgorithm();

  usint lvl1 = ciphertext1->GetLevel();
  usint lvl2 = ciphertext2->GetLevel();

  if (lvl1 < lvl2) {
    ciphertext1 = algo->LevelReduceInternal(ciphertext1, nullptr, lvl2 - lvl1);
  } else if (lvl2 < lvl1) {
    ciphertext2 = algo->LevelReduceInternal(ciphertext2, nullptr, lvl1 - lvl2);
  }
}

template <>
std::pair<shared_ptr<ConstCiphertext<DCRTPoly>>, DCRTPoly>
LPAlgorithmSHEBGVrns<DCRTPoly>::AdjustLevels(
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
void LPAlgorithmSHEBGVrns<DCRTPoly>::AdjustLevelsEq(
    Ciphertext<DCRTPoly> &ciphertext, Plaintext plaintext) const {

  auto sizeQlc = ciphertext->GetElements()[0].GetNumOfElements();
  auto sizeQlp = plaintext->GetElement<DCRTPoly>().GetNumOfElements();

  if (sizeQlc < sizeQlp) {
    // Ciphertext remains the same
    // Level reduce the plaintext
    plaintext->GetElement<DCRTPoly>().DropLastElements(sizeQlp - sizeQlc);
  } else if (sizeQlc > sizeQlp) {
    // Plaintext remains same
    // Level reduce the ciphertext
    auto algo = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm();
    ciphertext = algo->LevelReduceInternal(ciphertext, nullptr, sizeQlc - sizeQlp);
  } // else do nothing

}

template <>
void LPAlgorithmSHEBGVrns<Poly>::EvalAddInPlace(
    Ciphertext<Poly>& ciphertext1,
    ConstCiphertext<Poly> ciphertext2) const {
  NOPOLY
}

template <>
void LPAlgorithmSHEBGVrns<NativePoly>::EvalAddInPlace(
    Ciphertext<NativePoly>& ciphertext1,
    ConstCiphertext<NativePoly> ciphertext2) const {
  NONATIVEPOLY
}

template <>
void LPAlgorithmSHEBGVrns<DCRTPoly>::EvalAddInPlace(
    Ciphertext<DCRTPoly>& ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {

  auto ciphertext2_clone = ciphertext2->Clone();
  AdjustLevelsEq(ciphertext1, ciphertext2_clone);
  EvalAddCoreInPlace(ciphertext1, ciphertext2_clone);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalAddMutable(
    Ciphertext<DCRTPoly> &ciphertext1,
    Ciphertext<DCRTPoly> &ciphertext2) const {
  AdjustLevelsEq(ciphertext1, ciphertext2);
  return EvalAddCore(ciphertext1, ciphertext2);
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalAdd(
    ConstCiphertext<Poly> ciphertext, ConstPlaintext plaintext) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalAdd(
    ConstCiphertext<NativePoly> ciphertext, ConstPlaintext plaintext) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalAdd(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  auto inPair = AdjustLevels(ciphertext, plaintext);
  return EvalAddCore(*(inPair.first), inPair.second);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalAddMutable(
    Ciphertext<DCRTPoly> &ciphertext, Plaintext plaintext) const {
  AdjustLevelsEq(ciphertext, plaintext);
  return EvalAddCore(ciphertext, plaintext->GetElement<DCRTPoly>());
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalSub(
    ConstCiphertext<Poly> ciphertext1,
    ConstCiphertext<Poly> ciphertext2) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalSub(
    ConstCiphertext<NativePoly> ciphertext1,
    ConstCiphertext<NativePoly> ciphertext2) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalSub(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  auto ct = AdjustLevels(ciphertext1, ciphertext2);
  return EvalSubCore(*ct[0], *ct[1]);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalSubMutable(
    Ciphertext<DCRTPoly> &ciphertext1,
    Ciphertext<DCRTPoly> &ciphertext2) const {
  AdjustLevelsEq(ciphertext1, ciphertext2);
  return EvalSubCore(ciphertext1, ciphertext2);
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalSub(
    ConstCiphertext<Poly> ciphertext, ConstPlaintext plaintext) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalSub(
    ConstCiphertext<NativePoly> ciphertext, ConstPlaintext plaintext) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalSub(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  auto inPair = AdjustLevels(ciphertext, plaintext);
  return EvalSubCore(*(inPair.first), inPair.second);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalSubMutable(
    Ciphertext<DCRTPoly> &ciphertext, Plaintext plaintext) const {
  AdjustLevelsEq(ciphertext, plaintext);
  return EvalAddCore(ciphertext, plaintext->GetElement<DCRTPoly>());
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalMult(
    ConstCiphertext<Poly> ciphertext1,
    ConstCiphertext<Poly> ciphertext2) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalMult(
    ConstCiphertext<NativePoly> ciphertext1,
    ConstCiphertext<NativePoly> ciphertext2) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT ||
      ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
    PALISADE_THROW(not_available_error,
                   "EvalMult cannot multiply in COEFFICIENT domain.");
  }
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext1->GetCryptoParameters());
  if (cryptoParams->GetModSwitchMethod() == MANUAL) {
    auto ct = AdjustLevels(ciphertext1, ciphertext2);
    return EvalMultCore(*ct[0], *ct[1]);
  } else { // AUTO mode
      auto algo = ciphertext1->GetCryptoContext()->GetEncryptionAlgorithm();
      auto ct1 = ciphertext1->Clone();
      auto ct2 = ciphertext2->Clone();
      if (ciphertext1->GetDepth() > 1) { // do automated modulus switching
        algo->ModReduceInternalInPlace(ct1);
      }
      if (ciphertext2->GetDepth() > 1) { // do automated modulus switching
        algo->ModReduceInternalInPlace(ct2);
      }
      AdjustLevelsEq(ct1, ct2);
      return EvalMultCore(ct1, ct2);
  }
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalMultMutable(
    Ciphertext<DCRTPoly> &ciphertext1,
    Ciphertext<DCRTPoly> &ciphertext2) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext1->GetCryptoParameters());
  if (cryptoParams->GetModSwitchMethod() == MANUAL) {
    AdjustLevelsEq(ciphertext1, ciphertext2);
    return EvalMultCore(ciphertext1, ciphertext2);
  } else { // AUTO mode
      auto algo = ciphertext1->GetCryptoContext()->GetEncryptionAlgorithm();
      if (ciphertext1->GetDepth() > 1) { // do automated modulus switching
        algo->ModReduceInternalInPlace(ciphertext1);
      }
      if (ciphertext2->GetDepth() > 1) { // do automated modulus switching
        algo->ModReduceInternalInPlace(ciphertext2);
      }
      AdjustLevelsEq(ciphertext1, ciphertext2);
      return EvalMultCore(ciphertext1, ciphertext2);
  }
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalMult(
    ConstCiphertext<Poly> ciphertext, ConstPlaintext plaintext) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalMult(
    ConstCiphertext<NativePoly> ciphertext, ConstPlaintext plaintext) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  if (ciphertext->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
    PALISADE_THROW(not_available_error,
                   "EvalMult cannot multiply in COEFFICIENT domain.");
  }
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());
  if (cryptoParams->GetModSwitchMethod() == MANUAL) {
    auto inPair = AdjustLevels(ciphertext, plaintext);
    return EvalMultCore(*(inPair.first), inPair.second);
  } else { // AUTO mode
    auto algo = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm();
    auto ct = ciphertext->Clone();
    if (ciphertext->GetDepth() > 1) { // do automated modulus switching
      algo->ModReduceInternalInPlace(ct);
    }
    auto inPair = AdjustLevels(ct, plaintext);
    return EvalMultCore(*(inPair.first), inPair.second);
  }
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalMultMutable(
    Ciphertext<DCRTPoly> &ciphertext, Plaintext plaintext) const {
  if (ciphertext->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
    PALISADE_THROW(not_available_error,
                   "EvalMult cannot multiply in COEFFICIENT domain.");
  }
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());
  if (cryptoParams->GetModSwitchMethod() == MANUAL) {
    AdjustLevelsEq(ciphertext, plaintext);
    return EvalMultCore(ciphertext, plaintext->GetElement<DCRTPoly>());
  } else { // AUTO mode
    auto algo = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm();
    if (ciphertext->GetDepth() > 1) { // do automated modulus switching
      algo->ModReduceInternalInPlace(ciphertext);
    }
    AdjustLevelsEq(ciphertext, plaintext);
    return EvalMultCore(ciphertext, plaintext->GetElement<DCRTPoly>());
  }
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalMultAndRelinearize(
    ConstCiphertext<Poly> ciphertext1, ConstCiphertext<Poly> ciphertext2,
    const vector<LPEvalKey<Poly>> &ek) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalMultAndRelinearize(
    ConstCiphertext<NativePoly> ciphertext1,
    ConstCiphertext<NativePoly> ciphertext2,
    const vector<LPEvalKey<NativePoly>> &ek) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalMultAndRelinearize(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2,
    const vector<LPEvalKey<DCRTPoly>> &ek) const {
  Ciphertext<DCRTPoly> ciphertext = this->EvalMult(ciphertext1, ciphertext2);

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ek[0]->GetCryptoParameters());

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
  result->SetDepth(ciphertext->GetDepth());

  std::vector<DCRTPoly> cv = ciphertext->GetElements();

  DCRTPoly ct0(cv[0]), ct1(cv[1]);

  // Perform a keyswitching operation to result of the multiplication. It does
  // it until it reaches to 2 elements.
  // TODO: Maybe we can change the number of keyswitching and terminate early.
  // For instance; perform keyswitching until 4 elements left.
  usint depth = ciphertext->GetElements().size() - 2;

  DCRTPoly zero = ciphertext->GetElements()[0].CloneParametersOnly();
  zero.SetValuesToZero();

  for (size_t j = 0, index = (depth - 1); j < depth; j++, --index) {

    LPEvalKeyRelin<DCRTPoly> evalKey =
        std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

    // Create a ciphertext with 3 components (0, 0, c[index+2])
    // so KeySwitch returns only the switched parts of c[index+2]
    vector<DCRTPoly> tmp = {zero, zero, cv[index + 2]};
    Ciphertext<DCRTPoly> cTmp = ciphertext->CloneEmpty();
    cTmp->SetElements(std::move(tmp));
    cTmp->SetDepth(ciphertext->GetDepth());
    cTmp->SetLevel(ciphertext->GetLevel());

    KeySwitchInPlace(evalKey, cTmp);

    ct0 += cTmp->GetElements()[0];
    ct1 += cTmp->GetElements()[1];
  }

  result->SetElements({std::move(ct0), std::move(ct1)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::Relinearize(
    ConstCiphertext<Poly> ciphertext, const vector<LPEvalKey<Poly>> &ek) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::Relinearize(
    ConstCiphertext<NativePoly> ciphertext,
    const vector<LPEvalKey<NativePoly>> &ek) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::Relinearize(
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
	std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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
    usint depth = ciphertext->GetElements().size() - 2;

    DCRTPoly zero = ciphertext->GetElements()[0].CloneParametersOnly();
    zero.SetValuesToZero();

    for (size_t j = 0, index = (depth - 1); j < depth; j++, --index) {

      LPEvalKeyRelin<DCRTPoly> evalKey =
	  std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

      // Create a ciphertext with 3 components (0, 0, c[index+2])
      // so KeySwitch returns only the switched parts of c[index+2]
      vector<DCRTPoly> tmp = {zero, zero, cv[index + 2]};
      Ciphertext<DCRTPoly> cTmp = ciphertext->CloneEmpty();
      cTmp->SetElements(std::move(tmp));
      cTmp->SetDepth(ciphertext->GetDepth());
      cTmp->SetLevel(ciphertext->GetLevel());

      KeySwitchInPlace(evalKey, cTmp);

      ct0 += cTmp->GetElements()[0];
      ct1 += cTmp->GetElements()[1];
    }

    result->SetElements({std::move(ct0), std::move(ct1)});
    result->SetLevel(ciphertext->GetLevel());

    return result;

  }
}

template <>
void LPAlgorithmSHEBGVrns<DCRTPoly>::RelinearizeInPlace(
    Ciphertext<DCRTPoly> &ciphertext,
    const vector<LPEvalKey<DCRTPoly>> &ek) const {

  if (ciphertext->GetElements().size() == 3) {

      LPEvalKeyRelin<DCRTPoly> evalKey =
          std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[0]);

      KeySwitchInPlace(evalKey, ciphertext);

  } else {

    const auto cryptoParams =
	std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
	    ek[0]->GetCryptoParameters());

    const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

    DCRTPoly ct0(cv[0]);
    DCRTPoly ct1(cv[1]);

    // Perform a keyswitching operation to result of the multiplication. It does
    // it until it reaches to 2 elements.
    // TODO: Maybe we can change the number of keyswitching and terminate early.
    // For instance; perform keyswitching until 4 elements left.
    usint depth = ciphertext->GetElements().size() - 2;

    DCRTPoly zero = ciphertext->GetElements()[0].CloneParametersOnly();
    zero.SetValuesToZero();

    for (size_t j = 0, index = (depth - 1); j < depth; j++, --index) {

      LPEvalKeyRelin<DCRTPoly> evalKey =
	  std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

      // Create a ciphertext with 3 components (0, 0, c[index+2])
      // so KeySwitch returns only the switched parts of c[index+2]
      vector<DCRTPoly> tmp = {zero, zero, cv[index + 2]};
      Ciphertext<DCRTPoly> cTmp = ciphertext->CloneEmpty();
      cTmp->SetElements(std::move(tmp));
      cTmp->SetDepth(ciphertext->GetDepth());
      cTmp->SetLevel(ciphertext->GetLevel());

      KeySwitchInPlace(evalKey, cTmp);

      ct0 += cTmp->GetElements()[0];
      ct1 += cTmp->GetElements()[1];
    }

    ciphertext->SetElements({std::move(ct0), std::move(ct1)});

  }
}

template <>
shared_ptr<vector<Poly>>
LPAlgorithmSHEBGVrns<Poly>::EvalFastRotationPrecomputeBV(
    ConstCiphertext<Poly> ciphertext) const {
  NOPOLY
}

template <>
shared_ptr<vector<NativePoly>>
LPAlgorithmSHEBGVrns<NativePoly>::EvalFastRotationPrecomputeBV(
    ConstCiphertext<NativePoly> ciphertext) const {
  NONATIVEPOLY
}

template <>
shared_ptr<vector<DCRTPoly>>
LPAlgorithmSHEBGVrns<DCRTPoly>::EvalFastRotationPrecomputeBV(
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());
  uint32_t relinWindow = cryptoParams->GetRelinWindow();

  const vector<DCRTPoly> &cv = ciphertext->GetElements();
  auto digitDecomp =
      std::make_shared<vector<DCRTPoly>>(cv[1].CRTDecompose(relinWindow));

  return digitDecomp;
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalFastRotationBV(
    ConstCiphertext<Poly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<Poly>> digits, LPEvalKey<DCRTPoly> evalKey) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalFastRotationBV(
    ConstCiphertext<NativePoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<NativePoly>> digits,
    LPEvalKey<DCRTPoly> evalKey) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalFastRotationBV(
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

  // Find the automorphism index that corresponds to rotation index index.
  usint autoIndex = FindAutomorphismIndex2nComplex(index, m);

  // Get the parts of the automorphism key
  std::vector<DCRTPoly> bv(evalKey->GetBVector());
  std::vector<DCRTPoly> av(evalKey->GetAVector());

  // Drop the unnecessary moduli to get better performance.
  auto sizeQ = bv[0].GetParams()->GetParams().size();
  auto sizeQl = cv[0].GetParams()->GetParams().size();
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
  for (size_t i = 0; i < digitsCopy.size(); i++) {
    digitsCopy[i] = digitsCopy[i].AutomorphismTransform(autoIndex);
  }
  DCRTPoly p0Prime(cv[0].AutomorphismTransform(autoIndex));
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
  result->SetElements({p0Prime + p0DoublePrime, std::move(p1DoublePrime)});
  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <>
shared_ptr<vector<Poly>>
LPAlgorithmSHEBGVrns<Poly>::EvalFastRotationPrecomputeGHS(
    ConstCiphertext<Poly> ciphertext) const {
  NOPOLY
}

template <>
shared_ptr<vector<NativePoly>>
LPAlgorithmSHEBGVrns<NativePoly>::EvalFastRotationPrecomputeGHS(
    ConstCiphertext<NativePoly> ciphertext) const {
  NONATIVEPOLY
}

template <>
shared_ptr<vector<DCRTPoly>>
LPAlgorithmSHEBGVrns<DCRTPoly>::EvalFastRotationPrecomputeGHS(
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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

  auto resultPtr = std::make_shared<vector<DCRTPoly>>(result);

  return resultPtr;
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalFastRotationGHS(
    ConstCiphertext<Poly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<Poly>> expandedCiphertext,
    LPEvalKey<DCRTPoly> evalKey) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalFastRotationGHS(
    ConstCiphertext<NativePoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<NativePoly>> expandedCiphertext,
    LPEvalKey<DCRTPoly> evalKey) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalFastRotationGHS(
    ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<DCRTPoly>> expandedCiphertext,
    LPEvalKey<DCRTPoly> evalKey) const {
  // Find the automorphism index that corresponds to rotation index index.
  usint autoIndex = FindAutomorphismIndex2nComplex(index, m);

  // Apply the automorphism to the first component of the ciphertext.
  DCRTPoly psiC0(ciphertext->GetElements()[0].AutomorphismTransform(autoIndex));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          evalKey->GetCryptoParameters());

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  std::vector<DCRTPoly> bv = evalKey->GetBVector();
  std::vector<DCRTPoly> av = evalKey->GetAVector();

  // Applying the automorphism to the expanded ciphertext.
  DCRTPoly expandedC((*expandedCiphertext)[0].AutomorphismTransform(autoIndex));
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

  //cTilda0.SetFormat(Format::COEFFICIENT);
  //cTilda1.SetFormat(Format::COEFFICIENT);

  // Get the plaintext modulus
  const NativeInteger t(cryptoParams->GetPlaintextModulus());

  DCRTPoly ct0 = cTilda0.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

  DCRTPoly ct1 = cTilda1.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

  //ct0.SetFormat(Format::EVALUATION);
  //ct1.SetFormat(Format::EVALUATION);

  ct0 += psiC0;

  result->SetElements({std::move(ct0), std::move(ct1)});
  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <>
shared_ptr<vector<Poly>>
LPAlgorithmSHEBGVrns<Poly>::EvalFastRotationPrecomputeHybrid(
    ConstCiphertext<Poly> ciphertext) const {
  NOPOLY
}

template <>
shared_ptr<vector<NativePoly>>
LPAlgorithmSHEBGVrns<NativePoly>::EvalFastRotationPrecomputeHybrid(
    ConstCiphertext<NativePoly> ciphertext) const {
  NONATIVEPOLY
}

template <>
shared_ptr<vector<DCRTPoly>>
LPAlgorithmSHEBGVrns<DCRTPoly>::EvalFastRotationPrecomputeHybrid(
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalFastRotationHybrid(
    ConstCiphertext<Poly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<Poly>> expandedCiphertext,
    LPEvalKey<DCRTPoly> evalKey) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalFastRotationHybrid(
    ConstCiphertext<NativePoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<NativePoly>> expandedCiphertext,
    LPEvalKey<DCRTPoly> evalKey) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalFastRotationHybrid(
    ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<DCRTPoly>> expandedCiphertext,
    LPEvalKey<DCRTPoly> evalKey) const {
  // Find the automorphism index that corresponds to rotation index index.
  usint autoIndex = FindAutomorphismIndex2nComplex(index, m);

  // Apply the automorphism to the first component of the ciphertext.
  DCRTPoly psiC0(ciphertext->GetElements()[0].AutomorphismTransform(autoIndex));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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
    DCRTPoly cj((*expandedCiphertext)[j].AutomorphismTransform(autoIndex));
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

  //cTilda0.SetFormat(Format::COEFFICIENT);
  //cTilda1.SetFormat(Format::COEFFICIENT);

  // Get the plaintext modulus
  const NativeInteger t(cryptoParams->GetPlaintextModulus());

  DCRTPoly ct0 = cTilda0.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

  DCRTPoly ct1 = cTilda1.ApproxModDown(
      paramsQl, paramsP, cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

  //ct0.SetFormat(Format::EVALUATION);
  //ct1.SetFormat(Format::EVALUATION);

  ct0 += psiC0;

  result->SetElements({std::move(ct0), std::move(ct1)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <>
shared_ptr<vector<Poly>> LPAlgorithmSHEBGVrns<Poly>::EvalFastRotationPrecompute(
    ConstCiphertext<Poly> ciphertext) const {
  NOPOLY
}

template <>
shared_ptr<vector<NativePoly>>
LPAlgorithmSHEBGVrns<NativePoly>::EvalFastRotationPrecompute(
    ConstCiphertext<NativePoly> ciphertext) const {
  NONATIVEPOLY
}

template <>
shared_ptr<vector<DCRTPoly>>
LPAlgorithmSHEBGVrns<DCRTPoly>::EvalFastRotationPrecompute(
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    return EvalFastRotationPrecomputeBV(ciphertext);
  } else if (cryptoParams->GetKeySwitchTechnique() == GHS) {
    return EvalFastRotationPrecomputeGHS(ciphertext);
  } else {  // Hybrid key switching
    return EvalFastRotationPrecomputeHybrid(ciphertext);
  }
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBGVrns<Poly>::EvalFastRotation(
    ConstCiphertext<Poly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<Poly>> precomp) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBGVrns<NativePoly>::EvalFastRotation(
    ConstCiphertext<NativePoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<NativePoly>> precomp) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalFastRotation(
    ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<DCRTPoly>> precomp) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertext->GetCryptoParameters());

  // Return unchanged if no rotation is required
  if (index == 0) {
    CiphertextImpl<DCRTPoly> res(*(ciphertext.get()));
    return std::make_shared<CiphertextImpl<DCRTPoly>>(res);
  }

  // Find the automorphism index that corresponds to rotation index index.
  usint autoIndex = FindAutomorphismIndex2nComplex(index, m);

  // Retrieve the automorphism key that corresponds to the auto index.
  auto autok = ciphertext->GetCryptoContext()
                   ->GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag())
                   .find(autoIndex)
                   ->second;

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    return EvalFastRotationBV(ciphertext, index, m, precomp, autok);
  } else if (cryptoParams->GetKeySwitchTechnique() == GHS) {
    return EvalFastRotationGHS(ciphertext, index, m, precomp, autok);
  } else {  // Hybrid key switching
    return EvalFastRotationHybrid(ciphertext, index, m, precomp, autok);
  }
}

template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmBGVrns<Poly>::ComposedEvalMult(
    ConstCiphertext<Poly> ciphertext1, ConstCiphertext<Poly> ciphertext2,
    const LPEvalKey<Poly> quadKeySwitchHint) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly>
LPLeveledSHEAlgorithmBGVrns<NativePoly>::ComposedEvalMult(
    ConstCiphertext<NativePoly> ciphertext1,
    ConstCiphertext<NativePoly> ciphertext2,
    const LPEvalKey<NativePoly> quadKeySwitchHint) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmBGVrns<DCRTPoly>::ComposedEvalMult(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2,
    const LPEvalKey<DCRTPoly> quadKeySwitchHint) const {
  auto algo = ciphertext1->GetCryptoContext()->GetEncryptionAlgorithm();

  Ciphertext<DCRTPoly> ciphertext = algo->EvalMult(ciphertext1, ciphertext2);

  algo->KeySwitchInPlace(quadKeySwitchHint, ciphertext);

  return algo->ModReduce(ciphertext);
}

template <>
LPEvalKey<Poly> LPAlgorithmPREBGVrns<Poly>::ReKeyGenBV(
    const LPPublicKey<Poly> newPk, const LPPrivateKey<Poly> oldSk) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmPREBGVrns<NativePoly>::ReKeyGenBV(
    const LPPublicKey<NativePoly> newPk,
    const LPPrivateKey<NativePoly> oldSk) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPREBGVrns<DCRTPoly>::ReKeyGenBV(
    const LPPublicKey<DCRTPoly> newPk,
    const LPPrivateKey<DCRTPoly> oldSk) const {
  // Get crypto context of new public key.
  auto cc = newPk->GetCryptoContext();

  // Create an evaluation key that will contain all the re-encryption key
  // elements.
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          newPk->GetCryptoParameters());
  const shared_ptr<DCRTPoly::Params> elementParams =
      cryptoParams->GetElementParams();

  const DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DCRTPoly::DugType dug;
  DCRTPoly::TugType tug;

  const DCRTPoly &sOld = oldSk->GetPrivateElement();

  const DCRTPoly &pNew0 = newPk->GetPublicElements().at(0);
  const DCRTPoly &pNew1 = newPk->GetPublicElements().at(1);

  std::vector<DCRTPoly> bv;
  std::vector<DCRTPoly> av;

  uint32_t relinWindow = cryptoParams->GetRelinWindow();

  // Get the plaintext modulus
  const auto t = cryptoParams->GetPlaintextModulus();

  for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
    if (relinWindow > 0) {
      vector<DCRTPoly::PolyType> sOldDecomposed =
          sOld.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (size_t k = 0; k < sOldDecomposed.size(); k++) {
        // Creates an element with all zeroes
        DCRTPoly filtered(elementParams, EVALUATION, true);

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

        c0 = pNew0 * u + t * e0 + filtered;
        c1 = pNew1 * u + t * e1;

        DCRTPoly a(dug, elementParams, Format::EVALUATION);
        av.push_back(std::move(c1));

        DCRTPoly e(dgg, elementParams, Format::EVALUATION);
        bv.push_back(std::move(c0));
      }
    } else {
      // Creates an element with all zeroes
      DCRTPoly filtered(elementParams, EVALUATION, true);

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

      c0 = pNew0 * u + t * e0 + filtered;
      c1 = pNew1 * u + t * e1;

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
LPEvalKey<Poly> LPAlgorithmPREBGVrns<Poly>::ReKeyGenGHS(
    const LPPublicKey<Poly> newPk, const LPPrivateKey<Poly> oldSk) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmPREBGVrns<NativePoly>::ReKeyGenGHS(
    const LPPublicKey<NativePoly> newPk,
    const LPPrivateKey<NativePoly> oldSk) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPREBGVrns<DCRTPoly>::ReKeyGenGHS(
    const LPPublicKey<DCRTPoly> newPk,
    const LPPrivateKey<DCRTPoly> oldSk) const {
  auto cc = newPk->GetCryptoContext();
  LPEvalKeyRelin<DCRTPoly> ek(
      std::make_shared<LPEvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          newPk->GetCryptoParameters());

  const shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
  const shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
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

  // Get the plaintext modulus
  const auto t = cryptoParams->GetPlaintextModulus();

  for (usint i = 0; i < sizeQ; i++) {
    auto vi = v.GetElementAtIndex(i);
    auto e0i = e0.GetElementAtIndex(i);
    auto e1i = e1.GetElementAtIndex(i);
    auto pNew0i = pNew0.GetElementAtIndex(i);
    auto pNew1i = pNew1.GetElementAtIndex(i);
    auto sOldi = sOld.GetElementAtIndex(i);
    b.SetElementAtIndex(i, vi * pNew0i + PModq[i] * sOldi + t * e0i);
    a.SetElementAtIndex(i, vi * pNew1i + t * e1i);
  }

  for (usint i = sizeQ; i < sizeQP; i++) {
    auto vi = v.GetElementAtIndex(i);
    auto e0i = e0.GetElementAtIndex(i);
    auto e1i = e1.GetElementAtIndex(i);
    auto pNew0i = pNew0.GetElementAtIndex(i);
    auto pNew1i = pNew1.GetElementAtIndex(i);
    b.SetElementAtIndex(i, vi * pNew0i + t * e0i);
    a.SetElementAtIndex(i, vi * pNew1i + t * e1i);
  }

  vector<DCRTPoly> av = {a};
  vector<DCRTPoly> bv = {b};

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <>
LPEvalKey<Poly> LPAlgorithmPREBGVrns<Poly>::ReKeyGen(
    const LPPublicKey<Poly> newPk, const LPPrivateKey<Poly> oldSk) const {
  NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmPREBGVrns<NativePoly>::ReKeyGen(
    const LPPublicKey<NativePoly> newPk,
    const LPPrivateKey<NativePoly> oldSk) const {
  NONATIVEPOLY
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmPREBGVrns<DCRTPoly>::ReKeyGen(
    const LPPublicKey<DCRTPoly> newPk,
    const LPPrivateKey<DCRTPoly> oldSk) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          newPk->GetCryptoParameters());

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    return ReKeyGenBV(newPk, oldSk);
  } else if (cryptoParams->GetKeySwitchTechnique() == GHS) {
    std::string errMsg =
        "ReKeyGen - Proxy re-encryption not supported when using GHS key "
        "switching.";
    PALISADE_THROW(not_available_error, errMsg);
    // return ReKeyGenGHS(newPK, origPrivateKey);
  } else {  // Hybrid
    std::string errMsg =
        "ReKeyGen - Proxy re-encryption not supported when using HYBRID key "
        "switching.";
    PALISADE_THROW(not_available_error, errMsg);
  }
}

template <>
Ciphertext<Poly> LPAlgorithmPREBGVrns<Poly>::ReEncrypt(
    const LPEvalKey<Poly> ek, ConstCiphertext<Poly> ciphertext,
    const LPPublicKey<Poly> publicKey) const {
  NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmPREBGVrns<NativePoly>::ReEncrypt(
    const LPEvalKey<NativePoly> ek, ConstCiphertext<NativePoly> ciphertext,
    const LPPublicKey<NativePoly> publicKey) const {
  NONATIVEPOLY
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmPREBGVrns<DCRTPoly>::ReEncrypt(
    const LPEvalKey<DCRTPoly> ek, ConstCiphertext<DCRTPoly> ciphertext,
    const LPPublicKey<DCRTPoly> publicKey) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
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
    const auto t = cryptoParams->GetPlaintextModulus();

    if (cryptoParams->GetMode() == RLWE)
      u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
    else
      u = DCRTPoly(tug, elementParams, Format::EVALUATION);

    DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
    DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

    DCRTPoly c0 = b * u + t * e0;
    DCRTPoly c1 = a * u + t * e1;

    zeroCiphertext->SetElements({std::move(c0), std::move(c1)});

    // Add the encryption of zero for re-randomization purposes
    auto c = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->EvalAdd(
        ciphertext, zeroCiphertext);

    ciphertext->GetCryptoContext()->KeySwitchInPlace(ek, c);
    return c;
  }
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmMultipartyBGVrns<DCRTPoly>::MultipartyDecryptLead(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          privateKey->GetCryptoParameters());
  const auto t = cryptoParams->GetPlaintextModulus();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  const DCRTPoly &s = privateKey->GetPrivateElement();

  DggType dgg(MP_SD);
  DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);

  DCRTPoly b = cv[0] + s * cv[1] + t * e;

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
  result->SetElements({std::move(b)});

  return result;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmMultipartyBGVrns<DCRTPoly>::MultipartyDecryptMain(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          privateKey->GetCryptoParameters());
  const auto t = cryptoParams->GetPlaintextModulus();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  const DCRTPoly &s = privateKey->GetPrivateElement();

  DggType dgg(MP_SD);
  DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);

  DCRTPoly b = s * cv[1] + t * e;

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
  result->SetElements({std::move(b)});

  return result;
}

template <>
DecryptResult LPAlgorithmMultipartyBGVrns<Poly>::MultipartyDecryptFusion(
    const vector<Ciphertext<Poly>> &ciphertextVec, Poly *plaintext) const {
  const shared_ptr<LPCryptoParameters<Poly>> cryptoParams =
      ciphertextVec[0]->GetCryptoParameters();
  const auto t = cryptoParams->GetPlaintextModulus();

  const std::vector<Poly> &cv0 = ciphertextVec[0]->GetElements();
  Poly b = cv0[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<Poly> &cvi = ciphertextVec[i]->GetElements();
    b += cvi[0];
  }

  b.SwitchFormat();

  *plaintext = b.CRTInterpolate().Mod(t);

  return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmMultipartyBGVrns<NativePoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<NativePoly>> &ciphertextVec,
    Poly *plaintext) const {
  std::string errMsg =
      "BGVrns: Decryption to Poly from NativePoly is not supported as it may "
      "lead to incorrect results.";
  PALISADE_THROW(not_available_error, errMsg);
}

template <>
DecryptResult LPAlgorithmMultipartyBGVrns<DCRTPoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<DCRTPoly>> &ciphertextVec, Poly *plaintext) const {
  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      ciphertextVec[0]->GetCryptoParameters();
  const auto t = cryptoParams->GetPlaintextModulus();

  const std::vector<DCRTPoly> &cv0 = ciphertextVec[0]->GetElements();
  DCRTPoly b = cv0[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<DCRTPoly> &cvi = ciphertextVec[i]->GetElements();
    b += cvi[0];
  }

  b.SwitchFormat();

  *plaintext = b.CRTInterpolate().Mod(t);

  return DecryptResult(plaintext->GetLength());
}

template <>
DecryptResult LPAlgorithmMultipartyBGVrns<DCRTPoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<DCRTPoly>> &ciphertextVec,
    NativePoly *plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          ciphertextVec[0]->GetCryptoParameters());

  const auto t = cryptoParams->GetPlaintextModulus();

  const std::vector<DCRTPoly> &cv0 = ciphertextVec[0]->GetElements();
  DCRTPoly b = cv0[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<DCRTPoly> &cvi = ciphertextVec[i]->GetElements();
    b += cvi[0];
  }

  b.SwitchFormat();
  size_t sizeQl = b.GetNumOfElements();
  // drops extra towers
  for (usint l = sizeQl - 1; l > 0; --l) {
    const vector<NativeInteger> &tModqPrecon = cryptoParams->GettModqPrecon();
    const NativeInteger &negtInvModq = cryptoParams->GetNegtInvModq(l);
    const NativeInteger &negtInvModqPrecon =
        cryptoParams->GetNegtInvModqPrecon(l);
    const vector<NativeInteger> &qlInvModq = cryptoParams->GetqlInvModq(l);
    const vector<NativeInteger> &qlInvModqPrecon =
        cryptoParams->GetqlInvModqPrecon(l);
    b.ModReduce(t, tModqPrecon, negtInvModq, negtInvModqPrecon, qlInvModq,
                qlInvModqPrecon);
  }

  *plaintext = b.GetElementAtIndex(0).Mod(t);

  return DecryptResult(plaintext->GetLength());
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmMultipartyBGVrns<DCRTPoly>::MultiKeySwitchGen(
    const LPPrivateKey<DCRTPoly> originalPrivateKey,
    const LPPrivateKey<DCRTPoly> newPrivateKey,
    const LPEvalKey<DCRTPoly> ek) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          newPrivateKey->GetCryptoParameters());

  LPAlgorithmSHEBGVrns<DCRTPoly> algoSHE;

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    return algoSHE.KeySwitchBVGen(originalPrivateKey, newPrivateKey, ek);
  } else if (cryptoParams->GetKeySwitchTechnique() == GHS) {
    return algoSHE.KeySwitchGHSGen(originalPrivateKey, newPrivateKey, ek);
  } else {  // Hybrid
    return algoSHE.KeySwitchHybridGen(originalPrivateKey, newPrivateKey, ek);
  }
}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmMultipartyBGVrns<DCRTPoly>::MultiMultEvalKey(
    LPEvalKey<DCRTPoly> evalKey, LPPrivateKey<DCRTPoly> sk) const {
  const shared_ptr<LPCryptoParametersBGVrns<DCRTPoly>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          evalKey->GetCryptoParameters());

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          evalKey->GetCryptoContext()->GetCryptoParameters());
  const typename DCRTPoly::DggType &dgg =
      cryptoParams->GetDiscreteGaussianGenerator();
  const shared_ptr<typename DCRTPoly::Params> elementParams =
      cryptoParams->GetElementParams();

  const auto &p = cryptoParams->GetPlaintextModulus();

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

      a.push_back(a0[i] * s + p * f1);
      b.push_back(b0[i] * s + p * f2);
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

      a.push_back(a0[i] * sExt + p * f1);
      b.push_back(b0[i] * sExt + p * f2);
    }
  }

  evalKeyResult->SetAVector(std::move(a));

  evalKeyResult->SetBVector(std::move(b));

  return evalKeyResult;
}

template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmBGVrns<Poly>::LevelReduceInternal(
    ConstCiphertext<Poly> ciphertext, const LPEvalKey<Poly> linearKeySwitchHint,
    size_t levels) const {
  std::string errMsg =
      "LPLeveledSHEAlgorithmBGVrns<Poly>::LevelReduceInternal is only "
      "supported for DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
Ciphertext<NativePoly>
LPLeveledSHEAlgorithmBGVrns<NativePoly>::LevelReduceInternal(
    ConstCiphertext<NativePoly> ciphertext,
    const LPEvalKey<NativePoly> linearKeySwitchHint, size_t levels) const {
  std::string errMsg =
      "LPLeveledSHEAlgorithmBGVrns<NativePoly>::LevelReduceInternal is only "
      "supported for DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmBGVrns<DCRTPoly>::LevelReduceInternal(
    ConstCiphertext<DCRTPoly> ciphertext,
    const LPEvalKey<DCRTPoly> linearKeySwitchHint, size_t levels) const {
  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel() + levels);

  vector<DCRTPoly> copy(ciphertext->GetElements());

  for (size_t i = 0; i < copy.size(); i++) copy[i].DropLastElements(levels);

  result->SetElements(std::move(copy));

  return result;
}

template <>
Ciphertext<Poly> LPLeveledSHEAlgorithmBGVrns<Poly>::LevelReduce(
    ConstCiphertext<Poly> ciphertext, const LPEvalKey<Poly> linearKeySwitchHint,
    size_t levels) const {
  std::string errMsg =
      "LPLeveledSHEAlgorithmBGVrns<Poly>::LevelReduce is only supported for "
      "DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
Ciphertext<NativePoly> LPLeveledSHEAlgorithmBGVrns<NativePoly>::LevelReduce(
    ConstCiphertext<NativePoly> ciphertext,
    const LPEvalKey<NativePoly> linearKeySwitchHint, size_t levels) const {
  std::string errMsg =
      "LPLeveledSHEAlgorithmBGVrns<NativePoly>::LevelReduce is only supported "
      "for DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
Ciphertext<DCRTPoly> LPLeveledSHEAlgorithmBGVrns<DCRTPoly>::LevelReduce(
    ConstCiphertext<DCRTPoly> ciphertext,
    const LPEvalKey<DCRTPoly> linearKeySwitchHint, size_t levels) const {
  return LevelReduceInternal(ciphertext, linearKeySwitchHint, levels);
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBGVrns<DCRTPoly>::EvalMultMany(
    const vector<Ciphertext<DCRTPoly>> &ciphertextList,
    const vector<LPEvalKey<DCRTPoly>> &evalKeys) const {
  auto algo = ciphertextList[0]->GetCryptoContext()->GetEncryptionAlgorithm();

  size_t cSize = ciphertextList.size();

  // If Size is not a power of two then we have to consider an extra level.
  if (cSize & (cSize - 1)) cSize <<= 1;

  size_t step = 1;

  vector<Ciphertext<DCRTPoly>> result(ciphertextList);

  while (cSize > 1) {
    for (usint i = 0; i < ciphertextList.size(); i += 2 * step) {
      if (i + step < ciphertextList.size())
        result[i] =
            algo->ComposedEvalMult(result[i], result[i + step], evalKeys[0]);
      else
        result[i] = algo->LevelReduceInternal(result[i],nullptr,1);
    }
    step <<= 1;
    cSize >>= 1;
  }

  return result[0];
}

template class LPPublicKeyEncryptionSchemeBGVrns<Poly>;
template class LPCryptoParametersBGVrns<Poly>;
template class LPAlgorithmBGVrns<Poly>;
template class LPAlgorithmPREBGVrns<Poly>;
template class LPAlgorithmSHEBGVrns<Poly>;
template class LPAlgorithmMultipartyBGVrns<Poly>;
template class LPAlgorithmParamsGenBGVrns<Poly>;

template class LPPublicKeyEncryptionSchemeBGVrns<NativePoly>;
template class LPCryptoParametersBGVrns<NativePoly>;
template class LPAlgorithmBGVrns<NativePoly>;
template class LPAlgorithmPREBGVrns<NativePoly>;
template class LPAlgorithmSHEBGVrns<NativePoly>;
template class LPAlgorithmMultipartyBGVrns<NativePoly>;
template class LPAlgorithmParamsGenBGVrns<NativePoly>;

template class LPPublicKeyEncryptionSchemeBGVrns<DCRTPoly>;
template class LPCryptoParametersBGVrns<DCRTPoly>;
template class LPAlgorithmBGVrns<DCRTPoly>;
template class LPAlgorithmPREBGVrns<DCRTPoly>;
template class LPAlgorithmSHEBGVrns<DCRTPoly>;
template class LPAlgorithmMultipartyBGVrns<DCRTPoly>;
template class LPAlgorithmParamsGenBGVrns<DCRTPoly>;

}  // namespace lbcrypto
