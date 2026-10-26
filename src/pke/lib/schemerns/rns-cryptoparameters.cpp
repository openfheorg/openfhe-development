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

#define PROFILE

#include "schemerns/rns-cryptoparameters.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

#include "math/dftransform.h"

namespace lbcrypto {
namespace {
// global used to validate the estimated sizeP value
uint32_t sizeP_estimate_global{};
}  // namespace

void CryptoParametersRNS::PrecomputeCRTTables(KeySwitchTechnique ksTech, ScalingTechnique scalTech,
                                              EncryptionTechnique encTech, MultiplicationTechnique multTech,
                                              uint32_t numPartQ, uint32_t auxBits, uint32_t extraBits) {
    // Set the key switching technique.
    m_ksTechnique = ksTech;
    // Set the scaling technique.
    m_scalTechnique = scalTech;
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
    std::vector<NativeInteger> moduliQ(sizeQ);
    std::vector<NativeInteger> rootsQ(sizeQ);
    for (size_t i = 0; i < sizeQ; i++) {
        moduliQ[i] = GetElementParams()->GetParams()[i]->GetModulus();
        rootsQ[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
    }

    // Pre-compute CRT::FFT values for Q
    DiscreteFourierTransform::Initialize(n * 2, n / 2);
    ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsQ, 2 * n, moduliQ);
    if (m_ksTechnique == HYBRID) {
        // numPartQ can not be zero as there is a division by numPartQ
        if (numPartQ == 0)
            OPENFHE_THROW("numPartQ is zero");

        // Compute ceil(sizeQ/numPartQ), the # of towers per digit
        uint32_t a = static_cast<uint32_t>(std::ceil(static_cast<double>(sizeQ) / numPartQ));
        if (sizeQ <= (a * (numPartQ - 1))) {
            auto str = "HYBRID key switching parameters: Can't appropriately distribute " + std::to_string(sizeQ) +
                       " towers into " + std::to_string(numPartQ) +
                       " digits. Please select different number of digits.";
            OPENFHE_THROW(str);
        }

        m_numPerPartQ = a;

        // Compute the composite digits PartQ = Q_j
        std::vector<BigInteger> moduliPartQ(m_numPartQ, 1);
        for (uint32_t j = 0; j < m_numPartQ; j++) {
            for (uint32_t i = a * j; i < (j + 1) * a; i++) {
                if (i < moduliQ.size())
                    moduliPartQ[j] *= moduliQ[i];
            }
        }

        // Compute PartQHat_i = Q/Q_j
        std::vector<BigInteger> PartQHat(m_numPartQ, 1);
        for (size_t i = 0; i < m_numPartQ; i++) {
            for (size_t j = 0; j < m_numPartQ; j++) {
                if (j != i)
                    PartQHat[i] *= moduliPartQ[j];
            }
        }

        // Compute partitions of Q into numPartQ digits
        m_paramsPartQ.resize(m_numPartQ);
        for (uint32_t j = 0; j < m_numPartQ; j++) {
            auto startTower = j * a;
            auto endTower = ((j + 1) * a - 1 < sizeQ) ? (j + 1) * a - 1 : sizeQ - 1;
            std::vector<std::shared_ptr<ILNativeParams>> params =
                    GetElementParams()->GetParamPartition(startTower, endTower);
            std::vector<NativeInteger> moduli(params.size());
            std::vector<NativeInteger> roots(params.size());
            for (uint32_t i = 0; i < params.size(); i++) {
                moduli[i] = params[i]->GetModulus();
                roots[i] = params[i]->GetRootOfUnity();
            }
            m_paramsPartQ[j] =
                    std::make_shared<ILDCRTParams<BigInteger>>(params[0]->GetCyclotomicOrder(), moduli, roots);
        }

        // Find number and size of individual special primes.
        uint32_t maxBits = moduliPartQ[0].GetLengthForBase(2);
        for (uint32_t j = 1; j < m_numPartQ; j++) {
            uint32_t bits = moduliPartQ[j].GetLengthForBase(2);
            if (bits > maxBits)
                maxBits = bits;
        }
        // Select number of primes in auxiliary CRT basis
        uint32_t sizeP = static_cast<uint32_t>(std::ceil(static_cast<double>(maxBits) / auxBits));

        // We want to make sure that P exceeds the maximum digit in Q by a safe margin.
        // The safe margin is chosen to make hybrid key switching error closer to the modulus switching error.
        // The margin of 4 bits accounts for dnum * 3.19 for typical values of dnum. See the noise expression
        // in Section B.2.3 of https://eprint.iacr.org/2021/204 for more details.
        // Composite scaling uses a base margin of 6 bits, and the fast basis extension overflow grows
        // linearly with the number of limbs per digit, adding ceil(log2(compositeDegree)) bits.
        uint32_t margin = (scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) ?
                                  6 + GetMSB64(m_compositeDegree - 1) :
                                  4;
        if (static_cast<uint64_t>(sizeP) * auxBits - maxBits < margin)
            ++sizeP;
        // validate the estimated sizeP value
        if (sizeP_estimate_global > 0) {
            if (sizeP > sizeP_estimate_global) {
                auto str = "EstimateLogP() failure: expected sizeP [" + std::to_string(sizeP_estimate_global) +
                           "], but got sizeP [" + std::to_string(sizeP) + "]";
                OPENFHE_THROW(str);
            }
            // reset sizeP_estimate_global before the next use
            sizeP_estimate_global = 0;
        }

        uint64_t primeStep = FindAuxPrimeStep();
        // the special primes are 1 modulo primeStep, so only about 2^auxBits/primeStep candidates exist
        auto auxPrimesMessage = [&](uint32_t found) {
            return "HYBRID key switching needs " + std::to_string(sizeP) + " auxiliary primes of " +
                   std::to_string(auxBits) + " bits congruent to 1 modulo " + std::to_string(primeStep) +
                   " (a multiple of the ring dimension, and of the odd part of the plaintext modulus for BGV), but only " +
                   std::to_string(found) +
                   " exist; increase KS_AUX_MOD_SIZE, or decrease the ring dimension or the plaintext modulus.";
        };
        if (GetMSB64(primeStep) >= auxBits)
            OPENFHE_THROW(auxPrimesMessage(0));

        // Choose special primes in auxiliary basis and compute their roots
        // moduliP holds special primes p1, p2, ..., pk
        // m_modulusP holds the product of special primes P = p1*p2*...pk
        std::vector<NativeInteger> moduliP(sizeP);
        std::vector<NativeInteger> rootsP(sizeP);
        // firstP contains a prime whose size is PModSize.
        NativeInteger firstP = FirstPrime<NativeInteger>(auxBits, primeStep);
        NativeInteger pPrev = firstP;
        BigInteger modulusP(1);
        for (uint32_t i = 0; i < sizeP; i++) {
            // The following loop makes sure that moduli in
            // P and Q are different
            bool foundInQ = false;
            do {
                try {
                    moduliP[i] = PreviousPrime<NativeInteger>(pPrev, primeStep);
                } catch (const OpenFHEException&) {
                    OPENFHE_THROW(auxPrimesMessage(i));
                }
                foundInQ = false;
                for (uint32_t j = 0; j < sizeQ; j++)
                    if (moduliP[i] == moduliQ[j])
                        foundInQ = true;
                pPrev = moduliP[i];
            } while (foundInQ);
            rootsP[i] = RootOfUnity<NativeInteger>(2 * n, moduliP[i]);
            modulusP *= moduliP[i];
            pPrev = moduliP[i];
        }

        // Store the created moduli and roots in m_paramsP
        m_paramsP = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliP, rootsP);

        // Create the moduli and roots for the extended CRT basis QP
        std::vector<NativeInteger> moduliQP(sizeQ + sizeP);
        std::vector<NativeInteger> rootsQP(sizeQ + sizeP);
        for (size_t i = 0; i < sizeQ; i++) {
            moduliQP[i] = moduliQ[i];
            rootsQP[i] = rootsQ[i];
        }
        for (size_t i = 0; i < sizeP; i++) {
            moduliQP[sizeQ + i] = moduliP[i];
            rootsQP[sizeQ + i] = rootsP[i];
        }

        m_paramsQP = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQP, rootsQP);

        // Precompute params for first 1..sizeQ towers of Q for KeySwitchDown (avoids per-call allocation).
        m_paramsQlHybrid.resize(sizeQ);
        std::vector<NativeInteger> moduliQl, rootsQl;
        moduliQl.reserve(sizeQ);
        rootsQl.reserve(sizeQ);
        for (size_t i = 0; i < sizeQ; ++i) {
            moduliQl.push_back(moduliQ[i]);
            rootsQl.push_back(rootsQ[i]);
            m_paramsQlHybrid[i] = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQl, rootsQl);
        }

        // Pre-compute CRT::FFT values for P
        ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsP, 2 * n, moduliP);

        // Pre-compute values [P]_{q_i}
        m_PModq.resize(sizeQ);
        for (uint32_t i = 0; i < sizeQ; i++) {
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
            if (l > 0)
                modulusQ = modulusQ / BigInteger(moduliQ[sizeQ - l]);

            m_QlHatInvModq[sizeQ - l - 1].resize(sizeQ - l);
            m_QlHatInvModqPrecon[sizeQ - l - 1].resize(sizeQ - l);
            for (size_t i = 0; i < sizeQ - l; i++) {
                BigInteger QHati = modulusQ / BigInteger(moduliQ[i]);
                BigInteger QHatInvModqi = QHati.ModInverse(moduliQ[i]);
                m_QlHatInvModq[sizeQ - l - 1][i] = QHatInvModqi.ConvertToInt();
                m_QlHatInvModqPrecon[sizeQ - l - 1][i] = m_QlHatInvModq[sizeQ - l - 1][i].PrepModMulConst(moduliQ[i]);
            }
        }

        // Pre-compute compementary partitions for ModUp
        uint32_t alpha = static_cast<uint32_t>(std::ceil(static_cast<double>(sizeQ) / m_numPartQ));
        m_paramsComplPartQ.resize(sizeQ);
        m_modComplPartqBarrettMu.resize(sizeQ);
        for (int32_t l = sizeQ - 1; l >= 0; l--) {
            uint32_t beta = static_cast<uint32_t>(std::ceil(static_cast<double>(l + 1) / alpha));
            m_paramsComplPartQ[l].resize(beta);
            m_modComplPartqBarrettMu[l].resize(beta);
            for (uint32_t j = 0; j < beta; j++) {
                const std::shared_ptr<ILDCRTParams<BigInteger>> digitPartition = GetParamsPartQ(j);
                auto cyclOrder = digitPartition->GetCyclotomicOrder();

                uint32_t sizePartQj = digitPartition->GetParams().size();
                if (j == beta - 1)
                    sizePartQj = (l + 1) - j * alpha;
                uint32_t sizeComplPartQj = (l + 1) - sizePartQj + sizeP;

                std::vector<NativeInteger> moduli(sizeComplPartQj);
                std::vector<NativeInteger> roots(sizeComplPartQj);

                for (uint32_t k = 0; k < sizeComplPartQj; k++) {
                    if (k < (l + 1) - sizePartQj) {
                        uint32_t currDigit = k / alpha;
                        if (currDigit >= j)
                            currDigit++;
                        moduli[k] = GetParamsPartQ(currDigit)->GetParams()[k % alpha]->GetModulus();
                        roots[k] = GetParamsPartQ(currDigit)->GetParams()[k % alpha]->GetRootOfUnity();
                    } else {
                        moduli[k] = moduliP[k - ((l + 1) - sizePartQj)];
                        roots[k] = rootsP[k - ((l + 1) - sizePartQj)];
                    }
                }
                m_paramsComplPartQ[l][j] = std::make_shared<ParmType>(cyclOrder, moduli, roots);

                const auto BarrettBase128Bit(BigInteger(1).LShiftEq(128));
                m_modComplPartqBarrettMu[l][j].resize(moduli.size());
                for (uint32_t i = 0; i < moduli.size(); i++) {
                    m_modComplPartqBarrettMu[l][j][i] =
                            (BarrettBase128Bit / BigInteger(moduli[i])).ConvertToInt<DoubleNativeInt>();
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
                    modulusPartQ = modulusPartQ / BigInteger(params[sizePartQk - l]->GetModulus());

                m_PartQlHatInvModq[k][sizePartQk - l - 1].resize(sizePartQk - l);
                m_PartQlHatInvModqPrecon[k][sizePartQk - l - 1].resize(sizePartQk - l);
                for (size_t i = 0; i < sizePartQk - l; i++) {
                    BigInteger QHat = modulusPartQ / BigInteger(params[i]->GetModulus());
                    BigInteger QHatInvModqi = QHat.ModInverse(params[i]->GetModulus());
                    m_PartQlHatInvModq[k][sizePartQk - l - 1][i] = QHatInvModqi.ConvertToInt();
                    m_PartQlHatInvModqPrecon[k][sizePartQk - l - 1][i] =
                            m_PartQlHatInvModq[k][sizePartQk - l - 1][i].PrepModMulConst(params[i]->GetModulus());
                }
            }
        }

        // Pre-compute QHat mod complementary partition qi's
        m_PartQlHatModp.resize(sizeQ);
        for (uint32_t l = 0; l < sizeQ; l++) {
            uint32_t alpha = static_cast<uint32_t>(std::ceil(static_cast<double>(sizeQ) / m_numPartQ));
            uint32_t beta = static_cast<uint32_t>(std::ceil(static_cast<double>(l + 1) / alpha));
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
                    BigInteger partQHat = partQ / BigInteger(paramsPartQ[i]->GetModulus());
                    auto complBasis = GetParamsComplPartQ(l, k);
                    m_PartQlHatModp[l][k][i].resize(complBasis->GetParams().size());
                    for (size_t j = 0; j < complBasis->GetParams().size(); j++) {
                        BigInteger QHatModpj = partQHat.Mod(complBasis->GetParams()[j]->GetModulus());
                        m_PartQlHatModp[l][k][i][j] = QHatModpj.ConvertToInt();
                    }
                }
            }
        }

        PrecomputeDoubleDecompTables(moduliQ, moduliP, rootsP, pPrev, primeStep, moduliPartQ);
    } else if (m_ddDigitSize > 0) {
        OPENFHE_THROW("The double decomposition of key switching requires the HYBRID key switching technique.");
    }
    /////////////////////////////////////
    // BFVrns and BGVrns : Multiparty Decryption : ExpandCRTBasis
    /////////////////////////////////////
    if (GetMultipartyMode() == NOISE_FLOODING_MULTIPARTY) {
        // Pre-compute values [*(Q/q_i/q_0)^{-1}]_{q_i}
        BigInteger modulusQ = BigInteger(GetElementParams()->GetModulus()) / BigInteger(moduliQ[0]);
        m_multipartyQHatInvModq.resize(sizeQ - 1);
        m_multipartyQHatInvModqPrecon.resize(sizeQ - 1);
        m_multipartyQHatModq0.resize(sizeQ - 1);
        // l will run from 0 to size-2, but modulusQ values
        // run from Q^(l-1) to Q^(0)
        for (size_t l = 0, m = sizeQ - l - 2; l < sizeQ - 1; ++l, --m) {
            if (l > 0)
                modulusQ = modulusQ / BigInteger(moduliQ[sizeQ - l]);

            m_multipartyQHatInvModq[m].resize(m + 1);
            m_multipartyQHatInvModqPrecon[m].resize(m + 1);
            m_multipartyQHatModq0[m].resize(1);
            m_multipartyQHatModq0[m][0].resize(m + 1);
            for (size_t i = 1; i < m + 2; i++) {
                BigInteger QHati = modulusQ / BigInteger(moduliQ[i]);
                BigInteger QHatInvModqi = QHati.ModInverse(moduliQ[i]);
                m_multipartyQHatInvModq[m][i - 1] = QHatInvModqi.ConvertToInt();
                m_multipartyQHatInvModqPrecon[m][i - 1] = m_multipartyQHatInvModq[m][i - 1].PrepModMulConst(moduliQ[i]);
                m_multipartyQHatModq0[m][0][i - 1] = QHati.Mod(moduliQ[0]);
            }
        }

        modulusQ = BigInteger(GetElementParams()->GetModulus()) / BigInteger(moduliQ[0]);
        m_multipartyAlphaQModq0.resize(sizeQ - 1);
        for (uint32_t l = sizeQ - 1; l > 0; l--) {
            if (l < sizeQ - 1)
                modulusQ = modulusQ / BigInteger(moduliQ[l + 1]);
            m_multipartyAlphaQModq0[l - 1].resize(l + 1);
            NativeInteger QlModq0 = modulusQ.Mod(moduliQ[0]).ConvertToInt();
            for (uint32_t j = 0; j < l + 1; ++j) {
                m_multipartyAlphaQModq0[l - 1][j] = {QlModq0.ModMul(NativeInteger(j), moduliQ[0])};
            }
        }

        const auto BarrettBase128Bit(BigInteger(1).LShiftEq(128));
        m_multipartyModq0BarrettMu.resize(1);
        m_multipartyModq0BarrettMu[0] = (BarrettBase128Bit / BigInteger(moduliQ[0])).ConvertToInt<DoubleNativeInt>();

        // Stores \frac{1/q_i}
        m_multipartyQInv.resize(sizeQ - 1);
        for (size_t i = 1; i < sizeQ; i++) {
            m_multipartyQInv[i - 1] = 1. / static_cast<double>(moduliQ[i].ConvertToInt());
        }
    }
}

// Tables of the double decomposition of HYBRID key switching (Kim, Lee, Seo, Song, "Accelerating HE operations
// from key decomposition technique", CRYPTO 2023). The key digits over QP = q_0 ... q_{L-1} p_0 ... p_{k-1} are
// decomposed into m_ddNumDigits digits of m_ddDigitSize consecutive limbs; the small centered residues of the key
// (|v| <= D_j / 2 for the key digit D_j) and the ciphertext digits (in [0, r Q_j) for a digit Q_j of r limbs, as
// produced by the fast basis extension of a digit) are multiplied over the small basis B', whose size exceeds the
// largest possible inner product (d N r Q_j D_j, plus 2 margin bits for the rounding of the exact basis switch),
// and the result is switched back exactly to the limbs of QP.
void CryptoParametersRNS::PrecomputeDoubleDecompTables(const std::vector<NativeInteger>& moduliQ,
                                                       const std::vector<NativeInteger>& moduliP,
                                                       const std::vector<NativeInteger>& rootsP,
                                                       NativeInteger lastAuxPrime, uint64_t primeStep,
                                                       const std::vector<BigInteger>& moduliPartQ) {
    m_ddNumDigits = 0;
    m_paramsDD = nullptr;
    m_paramsDDDigit.clear();
    m_modDDBarrettMu.clear();
    m_PartQlHatModDD.clear();
    m_ddDigitHatInvModq.clear();
    m_ddDigitHatInvModqPrecon.clear();
    m_ddDigitHatModDD.clear();
    m_ddAlphaDigitModDD.clear();
    m_ddDigitInv.clear();
    m_ddHatInvModDD.clear();
    m_ddHatInvModDDPrecon.clear();
    m_ddInv.clear();
    m_ddHatModQP.clear();
    m_ddAlphaModQP.clear();
    m_modQPBarrettMu.clear();
    if (m_ddDigitSize == 0)
        return;

    const uint32_t sizeQ = moduliQ.size();
    const uint32_t sizeP = moduliP.size();
    const uint32_t sizeQP = sizeQ + sizeP;
    const uint32_t n = GetElementParams()->GetRingDimension();
    const uint32_t cyclOrder = GetElementParams()->GetCyclotomicOrder();
    const auto& paramsQP = m_paramsQP->GetParams();

    if (m_ddDigitSize > sizeQP)
        m_ddDigitSize = sizeQP;
    m_ddNumDigits = (sizeQP + m_ddDigitSize - 1) / m_ddDigitSize;

    // the key digits D_j (consecutive limbs of QP)
    std::vector<BigInteger> keyDigits(m_ddNumDigits, BigInteger(1));
    m_paramsDDDigit.resize(m_ddNumDigits);
    BigInteger maxKeyDigit(1);
    for (uint32_t j = 0; j < m_ddNumDigits; ++j) {
        const uint32_t start = j * m_ddDigitSize;
        const uint32_t end = std::min(start + m_ddDigitSize, sizeQP);
        std::vector<NativeInteger> moduli, roots;
        for (uint32_t m = start; m < end; ++m) {
            moduli.push_back(paramsQP[m]->GetModulus());
            roots.push_back(paramsQP[m]->GetRootOfUnity());
            keyDigits[j] *= BigInteger(moduli.back());
        }
        m_paramsDDDigit[j] = std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduli, roots);
        if (keyDigits[j] > maxKeyDigit)
            maxKeyDigit = keyDigits[j];
    }

    // the bound on the inner products: d * N * r * max Q_j * max D_j, with 2 margin bits
    BigInteger maxCtDigit(1);
    for (const auto& q : moduliPartQ)
        if (q > maxCtDigit)
            maxCtDigit = q;
    const uint32_t boundBits = GetMSB64(m_numPartQ) + GetMSB64(n) + GetMSB64(m_numPerPartQ) + maxCtDigit.GetMSB() +
                               maxKeyDigit.GetMSB() + 2;

    // the primes of B': continue the descending search of the auxiliary primes, so that they differ from the
    // moduli of Q and P
    std::vector<NativeInteger> moduliDD, rootsDD;
    BigInteger modulusDD(1);
    NativeInteger pPrev = lastAuxPrime;
    while (modulusDD.GetMSB() <= boundBits) {
        bool foundInQ = false;
        do {
            try {
                pPrev = PreviousPrime<NativeInteger>(pPrev, primeStep);
            } catch (const OpenFHEException&) {
                OPENFHE_THROW("The double decomposition of key switching needs " + std::to_string(moduliDD.size() + 1) +
                              " or more primes of " + std::to_string(m_auxBits) + " bits congruent to 1 modulo " +
                              std::to_string(primeStep) +
                              ", but not enough exist; increase KS_AUX_MOD_SIZE or decrease the ring dimension.");
            }
            foundInQ = (std::find(moduliQ.begin(), moduliQ.end(), pPrev) != moduliQ.end());
        } while (foundInQ);
        moduliDD.push_back(pPrev);
        rootsDD.push_back(RootOfUnity<NativeInteger>(2 * n, pPrev));
        modulusDD *= BigInteger(pPrev);
    }
    const uint32_t sizeDD = moduliDD.size();
    m_paramsDD = std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliDD, rootsDD);
    ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsDD, 2 * n, moduliDD);

    const auto BarrettBase128Bit(BigInteger(1).LShiftEq(128));
    m_modDDBarrettMu.resize(sizeDD);
    for (uint32_t k = 0; k < sizeDD; ++k)
        m_modDDBarrettMu[k] = (BarrettBase128Bit / BigInteger(moduliDD[k])).ConvertToInt<DoubleNativeInt>();

    // ciphertext digit -> B' (fast basis extension): [(Q^(l)_part / q_i)]_{p'_k}
    m_PartQlHatModDD.resize(sizeQ);
    for (uint32_t l = 0; l < sizeQ; ++l) {
        const uint32_t beta = static_cast<uint32_t>(std::ceil(static_cast<double>(l + 1) / m_numPerPartQ));
        m_PartQlHatModDD[l].resize(beta);
        for (uint32_t part = 0; part < beta; ++part) {
            const auto& paramsPartQ = GetParamsPartQ(part)->GetParams();
            BigInteger partQ = GetParamsPartQ(part)->GetModulus();
            uint32_t digitSize = paramsPartQ.size();
            if (part == beta - 1) {
                digitSize = l + 1 - part * m_numPerPartQ;
                for (uint32_t idx = digitSize; idx < paramsPartQ.size(); ++idx)
                    partQ = partQ / BigInteger(paramsPartQ[idx]->GetModulus());
            }
            m_PartQlHatModDD[l][part].assign(digitSize, std::vector<NativeInteger>(sizeDD));
            for (uint32_t i = 0; i < digitSize; ++i) {
                const BigInteger partQHat = partQ / BigInteger(paramsPartQ[i]->GetModulus());
                for (uint32_t k = 0; k < sizeDD; ++k)
                    m_PartQlHatModDD[l][part][i][k] = partQHat.Mod(moduliDD[k]).ConvertToInt();
            }
        }
    }

    // key digit -> B' (exact basis switch, DCRTPoly::SwitchCRTBasis layout)
    m_ddDigitHatInvModq.resize(m_ddNumDigits);
    m_ddDigitHatInvModqPrecon.resize(m_ddNumDigits);
    m_ddDigitHatModDD.resize(m_ddNumDigits);
    m_ddAlphaDigitModDD.resize(m_ddNumDigits);
    m_ddDigitInv.resize(m_ddNumDigits);
    for (uint32_t j = 0; j < m_ddNumDigits; ++j) {
        const auto& digitParams = m_paramsDDDigit[j]->GetParams();
        const uint32_t sizeDigit = digitParams.size();
        m_ddDigitHatInvModq[j].resize(sizeDigit);
        m_ddDigitHatInvModqPrecon[j].resize(sizeDigit);
        m_ddDigitInv[j].resize(sizeDigit);
        m_ddDigitHatModDD[j].assign(sizeDD, std::vector<NativeInteger>(sizeDigit));
        for (uint32_t i = 0; i < sizeDigit; ++i) {
            const NativeInteger qi = digitParams[i]->GetModulus();
            const BigInteger hat = keyDigits[j] / BigInteger(qi);
            m_ddDigitHatInvModq[j][i] = hat.ModInverse(BigInteger(qi)).ConvertToInt();
            m_ddDigitHatInvModqPrecon[j][i] = m_ddDigitHatInvModq[j][i].PrepModMulConst(qi);
            m_ddDigitInv[j][i] = 1.0 / qi.ConvertToDouble();
            for (uint32_t k = 0; k < sizeDD; ++k)
                m_ddDigitHatModDD[j][k][i] = hat.Mod(moduliDD[k]).ConvertToInt();
        }
        m_ddAlphaDigitModDD[j].assign(sizeDigit + 1, std::vector<NativeInteger>(sizeDD));
        for (uint32_t k = 0; k < sizeDD; ++k) {
            const NativeInteger digitModp = keyDigits[j].Mod(moduliDD[k]).ConvertToInt();
            m_ddAlphaDigitModDD[j][0][k] = 0;
            for (uint32_t a = 1; a <= sizeDigit; ++a)
                m_ddAlphaDigitModDD[j][a][k] = m_ddAlphaDigitModDD[j][a - 1][k].ModAddFast(digitModp, moduliDD[k]);
        }
    }

    // B' -> QP (exact basis switch of the centered inner products)
    m_ddHatInvModDD.resize(sizeDD);
    m_ddHatInvModDDPrecon.resize(sizeDD);
    m_ddInv.resize(sizeDD);
    std::vector<BigInteger> ddHat(sizeDD);
    for (uint32_t k = 0; k < sizeDD; ++k) {
        ddHat[k] = modulusDD / BigInteger(moduliDD[k]);
        m_ddHatInvModDD[k] = ddHat[k].ModInverse(BigInteger(moduliDD[k])).ConvertToInt();
        m_ddHatInvModDDPrecon[k] = m_ddHatInvModDD[k].PrepModMulConst(moduliDD[k]);
        m_ddInv[k] = 1.0 / moduliDD[k].ConvertToDouble();
    }
    m_ddHatModQP.assign(sizeQP, std::vector<NativeInteger>(sizeDD));
    m_ddAlphaModQP.assign(sizeQP, std::vector<NativeInteger>(sizeDD + 1));
    m_modQPBarrettMu.resize(sizeQP);
    for (uint32_t m = 0; m < sizeQP; ++m) {
        const NativeInteger qm = paramsQP[m]->GetModulus();
        for (uint32_t k = 0; k < sizeDD; ++k)
            m_ddHatModQP[m][k] = ddHat[k].Mod(qm).ConvertToInt();
        const NativeInteger ddModq = modulusDD.Mod(qm).ConvertToInt();
        m_ddAlphaModQP[m][0] = 0;
        for (uint32_t a = 1; a <= sizeDD; ++a)
            m_ddAlphaModQP[m][a] = m_ddAlphaModQP[m][a - 1].ModAddFast(ddModq, qm);
        m_modQPBarrettMu[m] = (BarrettBase128Bit / BigInteger(qm)).ConvertToInt<DoubleNativeInt>();
    }
}

uint64_t CryptoParametersRNS::FindAuxPrimeStep() const {
    return GetElementParams()->GetRingDimension();
}

std::pair<double, uint32_t> CryptoParametersRNS::EstimateLogP(uint32_t numPartQ, double firstModulusSize,
                                                              double dcrtBits, double extraModulusSize,
                                                              uint32_t numPrimes, uint32_t auxBits,
                                                              ScalingTechnique scalTech, bool addOne,
                                                              bool isNoiseFloodingMultiparty,
                                                              uint32_t compositeDegree) {
    // numPartQ can not be zero as there is a division by numPartQ
    if (numPartQ == 0)
        OPENFHE_THROW("numPartQ is zero");

    size_t sizeQ = numPrimes;
    if (extraModulusSize > 0)
        sizeQ++;

    // handles a BFV-specific situation where the number of digits might be initially higher than number of RNS limbs in Q
    if (numPartQ > sizeQ)
        numPartQ = sizeQ;

    // Compute ceil(sizeQ/numPartQ), the # of towers per digit
    size_t numPerPartQ = static_cast<size_t>(std::ceil(static_cast<double>(sizeQ) / numPartQ));
    if (sizeQ <= (numPerPartQ * (numPartQ - 1))) {
        auto str = "HYBRID key switching parameters: Can't appropriately distribute " + std::to_string(sizeQ) +
                   " towers into " + std::to_string(numPartQ) + " digits. Please select different number of digits.";
        OPENFHE_THROW(str);
    }

    // create a vector with the same value of bit sizes
    std::vector<double> qi(sizeQ, dcrtBits);
    qi[0] = firstModulusSize;
    if (extraModulusSize > 0)
        qi[sizeQ - 1] = extraModulusSize;
    if (isNoiseFloodingMultiparty) {
        for (size_t i = 1; i < (NoiseFlooding::NUM_MODULI_MULTIPARTY + 1); ++i) {
            qi[i] = NoiseFlooding::MULTIPARTY_MOD_SIZE;
        }
    }

    // Compute partitions of Q into numPartQ digits
    uint32_t maxBits = 0;
    for (size_t j = 0; j < numPartQ; ++j) {
        size_t startTower = j * numPerPartQ;
        size_t endTower = ((j + 1) * numPerPartQ - 1 < sizeQ) ? (j + 1) * numPerPartQ - 1 : sizeQ - 1;

        // sum qi elements qi[startTower] + ... + qi[endTower] inclusive. the end element should be qi.begin()+(endTower+1)
        uint32_t bits =
                static_cast<uint32_t>(std::accumulate(qi.begin() + startTower, qi.begin() + (endTower + 1), 0.0));
        if (bits > maxBits)
            maxBits = bits;
    }

    // we add an extra bit to account for the special moduli selection logic in BGV and CKKS
    // ignore the case when there is only one max size modulus
    if (addOne && (maxBits != auxBits))
        maxBits++;

    // Select number of primes in auxiliary CRT basis
    uint32_t sizeP = static_cast<uint32_t>(std::ceil(static_cast<double>(maxBits) / auxBits));

    // We want to make sure that P exceeds the maximum digit in Q by a safe margin.
    // The safe margin is chosen to make hybrid key switching error closer to the modulus switching error.
    // The margin of 4 bits accounts for dnum * 3.19 for typical values of dnum. See the noise expression
    // in Section B.2.3 of https://eprint.iacr.org/2021/204 for more details.
    // Composite scaling uses a base margin of 6 bits, and the fast basis extension overflow grows
    // linearly with the number of limbs per digit, adding ceil(log2(compositeDegree)) bits.
    uint32_t margin = (scalTech == COMPOSITESCALINGAUTO || scalTech == COMPOSITESCALINGMANUAL) ?
                              6 + GetMSB64(compositeDegree - 1) :
                              4;
    if (static_cast<uint64_t>(sizeP) * auxBits - maxBits < margin)
        ++sizeP;

    sizeP_estimate_global = sizeP;

    return std::make_pair(sizeP * auxBits, sizeP);
}

}  // namespace lbcrypto
