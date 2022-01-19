// @file pke-rns.cpp - CKKS scheme implementation.
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
 - Andrey Kim, Antonis Papadimitriou, and Yuriy Polyakov. Approximate
homomorphic encryption with reduced approximation error. Cryptology ePrint
Archive, Report 2020/1118, 2020. https://eprint.iacr.org/2020/
1118.
 */

#define PROFILE

#include "math/dftransform.h"
#include "cryptocontext.h"
#include "schemerns/rns-cryptoparameters.h"
#include "globals.h"

namespace lbcrypto {

void CryptoParametersRNS::PrecomputeCRTTables(KeySwitchTechnique ksTech,
                                              RescalingTechnique rsTech,
                                              EncryptionTechnique encTech,
                                              MultiplicationTechnique multTech,
                                              uint32_t numPartQ,
                                              uint32_t auxBits,
                                              uint32_t extraBits) {
  if (!SERIALIZE_PRECOMPUTE)
     return;

  // Set the key switching technique.
  m_ksTechnique = ksTech;
  // Set the rescaling technique.
  m_rsTechnique = rsTech;
  // Set the key encryption technique.
  m_encTechnique = encTech;
  // Set the multiplication technique.
  m_multTechnique = multTech;
  // Set number of digits in HYBRID
  m_numPartQ = numPartQ;
  // Set auxiliary primes bit size in HYBRID
  m_auxBits = auxBits;
  // Set number of extraBits for lower error
  m_extraBits = extraBits;

  size_t sizeQ = GetElementParams()->GetParams().size();
  size_t n = GetElementParams()->GetRingDimension();

  // Construct moduliQ and rootsQ from crypto parameters
  vector<NativeInteger> moduliQ(sizeQ);
  vector<NativeInteger> rootsQ(sizeQ);
  for (size_t i = 0; i < sizeQ; i++) {
    moduliQ[i] = GetElementParams()->GetParams()[i]->GetModulus();
    rootsQ[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
  }

  // Pre-compute CRT::FFT values for Q
  DiscreteFourierTransform::Initialize(n * 2, n / 2);
  ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsQ, 2 * n,
                                                          moduliQ);
  if (m_ksTechnique == HYBRID) {
    // Compute ceil(sizeQ/m_numPartQ), the # of towers per digit
    uint32_t a = ceil(static_cast<double>(sizeQ) / numPartQ);
    if ((int32_t)(sizeQ - a * (numPartQ - 1)) <= 0) {
      auto str =
          "CryptoParametersRNS::PrecomputeCRTTables - HYBRID key "
          "switching parameters: Can't appropriately distribute " +
          std::to_string(sizeQ) + " towers into " + std::to_string(numPartQ) +
          " digits. Please select different number of digits.";
      PALISADE_THROW(config_error, str);
    }

    m_numPerPartQ = a;

    // Compute the composite digits PartQ = Q_j
    vector<BigInteger> moduliPartQ;
    moduliPartQ.resize(m_numPartQ);
    for (usint j = 0; j < m_numPartQ; j++) {
      moduliPartQ[j] = BigInteger(1);
      for (usint i = a * j; i < (j + 1) * a; i++) {
        if (i < moduliQ.size()) moduliPartQ[j] *= moduliQ[i];
      }
    }

    // Compute PartQHat_i = Q/Q_j
    vector<BigInteger> PartQHat;
    PartQHat.resize(m_numPartQ);
    for (size_t i = 0; i < m_numPartQ; i++) {
      PartQHat[i] = BigInteger(1);
      for (size_t j = 0; j < m_numPartQ; j++) {
        if (j != i) PartQHat[i] *= moduliPartQ[j];
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
        m_PartQHatModq[j][i] = PartQHat[j].Mod(moduliQ[i]).ConvertToInt();
        if (i >= j * a && i <= ((j + 1) * a - 1)) {
          m_PartQHatInvModq[j][i] =
              PartQHat[j].ModInverse(moduliQ[i]).ConvertToInt();
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

    uint32_t sizeP;
    // Find number and size of individual special primes.
    uint32_t maxBits = moduliPartQ[0].GetLengthForBase(2);
    for (usint j = 1; j < m_numPartQ; j++) {
      uint32_t bits = moduliPartQ[j].GetLengthForBase(2);
      if (bits > maxBits) maxBits = bits;
    }
    // Select number of primes in auxiliary CRT basis
    sizeP = ceil(static_cast<double>(maxBits) / auxBits);
    uint64_t primeStep = FindAuxPrimeStep();

    // Choose special primes in auxiliary basis and compute their roots
    // moduliP holds special primes p1, p2, ..., pk
    // m_modulusP holds the product of special primes P = p1*p2*...pk
    vector<NativeInteger> moduliP(sizeP);
    vector<NativeInteger> rootsP(sizeP);
    // firstP contains a prime whose size is PModSize.
    NativeInteger firstP = FirstPrime<NativeInteger>(auxBits, primeStep);
    NativeInteger pPrev = firstP;
    BigInteger modulusP(1);
    for (usint i = 0; i < sizeP; i++) {
      // The following loop makes sure that moduli in
      // P and Q are different
      bool foundInQ = false;
      do {
        moduliP[i] = PreviousPrime<NativeInteger>(pPrev, primeStep);
        foundInQ = false;
        for (usint j = 0; j < sizeQ; j++)
          if (moduliP[i] == moduliQ[j]) foundInQ = true;
        pPrev = moduliP[i];
      } while (foundInQ);
      rootsP[i] = RootOfUnity<NativeInteger>(2 * n, moduliP[i]);
      modulusP *= moduliP[i];
      pPrev = moduliP[i];
    }

    // Store the created moduli and roots in m_paramsP
    m_paramsP =
        std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliP, rootsP);

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
    ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsP, 2 * n,
                                                           moduliP);

    // Pre-compute values [P]_{q_i}
    m_PModq.resize(sizeQ);
    for (usint i = 0; i < sizeQ; i++) {
      m_PModq[i] = modulusP.Mod(moduliQ[i]).ConvertToInt();
    }

    // Pre-compute values [P^{-1}]_{q_i}
    m_PInvModq.resize(sizeQ);
    m_PInvModqPrecon.resize(sizeQ);
    for (size_t i = 0; i < sizeQ; i++) {
      BigInteger PInvModqi = modulusP.ModInverse(moduliQ[i]);
      m_PInvModq[i] = PInvModqi.ConvertToInt();
      m_PInvModqPrecon[i] = m_PInvModq[i].PrepModMulConst(moduliQ[i]);
    }

    // Pre-compute values [P/p_j]_{q_i}
    // Pre-compute values [(P/p_j)^{-1}]_{p_j}
    m_PHatInvModp.resize(sizeP);
    m_PHatInvModpPrecon.resize(sizeP);
    m_PHatModq.resize(sizeP);
    for (size_t j = 0; j < sizeP; j++) {
      BigInteger PHatj = modulusP / BigInteger(moduliP[j]);
      BigInteger PHatInvModpj = PHatj.ModInverse(moduliP[j]);
      m_PHatInvModp[j] = PHatInvModpj.ConvertToInt();
      m_PHatInvModpPrecon[j] = m_PHatInvModp[j].PrepModMulConst(moduliP[j]);
      m_PHatModq[j].resize(sizeQ);
      for (size_t i = 0; i < sizeQ; i++) {
        BigInteger PHatModqji = PHatj.Mod(moduliQ[i]);
        m_PHatModq[j][i] = PHatModqji.ConvertToInt();
      }
    }

    BigInteger modulusQ = GetElementParams()->GetModulus();
    // Pre-compute values [Q/q_i]_{p_j}
    // Pre-compute values [(Q/q_i)^{-1}]_{q_i}
    m_QlHatInvModq.resize(sizeQ);
    m_QlHatInvModqPrecon.resize(sizeQ);
    // l will run from 0 to size-2, but modulusQ values
    // run from Q^(l-1) to Q^(0)
    for (size_t l = 0; l < sizeQ; l++) {
      if (l > 0) modulusQ = modulusQ / BigInteger(moduliQ[sizeQ - l]);

      m_QlHatInvModq[sizeQ - l - 1].resize(sizeQ - l);
      m_QlHatInvModqPrecon[sizeQ - l - 1].resize(sizeQ - l);
      for (size_t i = 0; i < sizeQ - l; i++) {
        BigInteger QHati = modulusQ / BigInteger(moduliQ[i]);
        BigInteger QHatInvModqi = QHati.ModInverse(moduliQ[i]);
        m_QlHatInvModq[sizeQ - l - 1][i] = QHatInvModqi.ConvertToInt();
        m_QlHatInvModqPrecon[sizeQ - l - 1][i] =
            m_QlHatInvModq[sizeQ - l - 1][i].PrepModMulConst(moduliQ[i]);
      }
    }

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
            moduli[k] =
                GetParamsPartQ(currDigit)->GetParams()[k % alpha]->GetModulus();
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
    m_PartQlHatInvModq.resize(m_numPartQ);
    m_PartQlHatInvModqPrecon.resize(m_numPartQ);
    for (uint32_t k = 0; k < m_numPartQ; k++) {
      auto params = m_paramsPartQ[k]->GetParams();
      uint32_t sizePartQk = params.size();
      m_PartQlHatInvModq[k].resize(sizePartQk);
      m_PartQlHatInvModqPrecon[k].resize(sizePartQk);
      auto modulusPartQ = m_paramsPartQ[k]->GetModulus();
      for (size_t l = 0; l < sizePartQk; l++) {
        if (l > 0)
          modulusPartQ =
              modulusPartQ / BigInteger(params[sizePartQk - l]->GetModulus());

        m_PartQlHatInvModq[k][sizePartQk - l - 1].resize(sizePartQk - l);
        m_PartQlHatInvModqPrecon[k][sizePartQk - l - 1].resize(sizePartQk -
                                                                 l);
        for (size_t i = 0; i < sizePartQk - l; i++) {
          BigInteger QHat = modulusPartQ / BigInteger(params[i]->GetModulus());
          BigInteger QHatInvModqi = QHat.ModInverse(params[i]->GetModulus());
          m_PartQlHatInvModq[k][sizePartQk - l - 1][i] =
              QHatInvModqi.ConvertToInt();
          m_PartQlHatInvModqPrecon[k][sizePartQk - l - 1][i] =
              m_PartQlHatInvModq[k][sizePartQk - l - 1][i].PrepModMulConst(
                  params[i]->GetModulus());
        }
      }
    }

    // Pre-compute QHat mod complementary partition qi's
    m_PartQlHatModp.resize(sizeQ);
    for (uint32_t l = 0; l < sizeQ; l++) {
      uint32_t alpha = ceil(static_cast<double>(sizeQ) / m_numPartQ);
      uint32_t beta = ceil(static_cast<double>(l + 1) / alpha);
      m_PartQlHatModp[l].resize(beta);
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

        m_PartQlHatModp[l][k].resize(digitSize);
        for (uint32_t i = 0; i < digitSize; i++) {
          BigInteger partQHat =
              partQ / BigInteger(paramsPartQ[i]->GetModulus());
          auto complBasis = GetParamsComplPartQ(l, k);
          m_PartQlHatModp[l][k][i].resize(complBasis->GetParams().size());
          for (size_t j = 0; j < complBasis->GetParams().size(); j++) {
            BigInteger QHatModpj =
                partQHat.Mod(complBasis->GetParams()[j]->GetModulus());
            m_PartQlHatModp[l][k][i][j] = QHatModpj.ConvertToInt();
          }
        }
      }
    }
  }
}

uint64_t CryptoParametersRNS::FindAuxPrimeStep() const {
  return GetElementParams()->GetRingDimension();
}

}

