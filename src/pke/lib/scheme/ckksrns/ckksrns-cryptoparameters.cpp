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

#include "math/dftransform.h"

#include "scheme/ckksrns/ckksrns-cryptoparameters.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

namespace lbcrypto {

// Precomputation of CRT tables encryption, decryption, and  homomorphic multiplication
void CryptoParametersCKKSRNS::PrecomputeCRTTables(KeySwitchTechnique ksTech, ScalingTechnique scalTech,
                                                  EncryptionTechnique encTech, MultiplicationTechnique multTech,
                                                  uint32_t numPartQ, uint32_t auxBits, uint32_t extraBits) {
    CryptoParametersRNS::PrecomputeCRTTables(ksTech, scalTech, encTech, multTech, numPartQ, auxBits, extraBits);

    size_t sizeQ             = GetElementParams()->GetParams().size();
    uint32_t compositeDegree = m_compositeDegree;

    std::vector<NativeInteger> moduliQ(sizeQ);
    std::vector<NativeInteger> rootsQ(sizeQ);

    for (size_t i = 0; i < sizeQ; i++) {
        moduliQ[i] = GetElementParams()->GetParams()[i]->GetModulus();
        rootsQ[i]  = GetElementParams()->GetParams()[i]->GetRootOfUnity();
    }

    // Pre-compute values for rescaling
    m_qlInvModq.resize(sizeQ - 1);
    m_qlInvModqPrecon.resize(sizeQ - 1);
    for (size_t k = 0; k < sizeQ - 1; k++) {
        size_t l = sizeQ - (k + 1);
        m_qlInvModq[k].resize(l);
        m_qlInvModqPrecon[k].resize(l);
        for (uint32_t i = 0; i < l; i++) {
            m_qlInvModq[k][i]       = moduliQ[l].ModInverse(moduliQ[i]);
            m_qlInvModqPrecon[k][i] = m_qlInvModq[k][i].PrepModMulConst(moduliQ[i]);
        }
    }

    // Pre-compute scaling factors for each level (used in FLEXIBLE* scaling techniques)
    if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT ||
        m_scalTechnique == COMPOSITESCALINGAUTO || m_scalTechnique == COMPOSITESCALINGMANUAL) {
        m_scalingFactorsReal.resize(sizeQ);

        if ((sizeQ == 1) && (extraBits == 0) && (m_scalTechnique != COMPOSITESCALINGAUTO) &&
            (m_scalTechnique != COMPOSITESCALINGMANUAL)) {
            // mult depth = 0 and FLEXIBLEAUTO
            // when multiplicative depth = 0, we use the scaling mod size instead of modulus size
            // Plaintext modulus is used in EncodingParamsImpl to store the exponent p of the scaling factor
            m_scalingFactorsReal[0] = std::pow(2, GetPlaintextModulus());
        }
        else if ((sizeQ == 2) && (extraBits > 0) && (m_scalTechnique != COMPOSITESCALINGAUTO) &&
                 (m_scalTechnique != COMPOSITESCALINGMANUAL)) {
            // mult depth = 0 and FLEXIBLEAUTOEXT
            // when multiplicative depth = 0, we use the scaling mod size instead of modulus size
            // Plaintext modulus is used in EncodingParamsImpl to store the exponent p of the scaling factor
            m_scalingFactorsReal[0] = moduliQ[sizeQ - 1].ConvertToDouble();
            m_scalingFactorsReal[1] = std::pow(2, GetPlaintextModulus());
        }
        else {
            m_scalingFactorsReal[0] = moduliQ[sizeQ - 1].ConvertToDouble();
            if (m_scalTechnique == COMPOSITESCALINGAUTO || m_scalTechnique == COMPOSITESCALINGMANUAL) {
                for (uint32_t j = 1; j < compositeDegree; j++) {
                    m_scalingFactorsReal[0] *= moduliQ[sizeQ - j - 1].ConvertToDouble();
                }
            }
            else if (extraBits > 0)
                m_scalingFactorsReal[1] = moduliQ[sizeQ - 2].ConvertToDouble();

            const double lastPresetFactor = (extraBits == 0) ? m_scalingFactorsReal[0] : m_scalingFactorsReal[1];
            // number of levels with pre-calculated factors
            const size_t numPresetFactors = (extraBits == 0 || (m_scalTechnique == COMPOSITESCALINGAUTO ||
                                                                m_scalTechnique == COMPOSITESCALINGMANUAL)) ?
                                                1 :
                                                2;

            for (size_t k = numPresetFactors; k < sizeQ; k++) {
                if (m_scalTechnique == COMPOSITESCALINGAUTO || m_scalTechnique == COMPOSITESCALINGMANUAL) {
                    if (k % compositeDegree == 0) {
                        double prevSF           = m_scalingFactorsReal[k - compositeDegree];
                        m_scalingFactorsReal[k] = prevSF * prevSF;
                        for (uint32_t j = 0; j < compositeDegree; j++) {
                            m_scalingFactorsReal[k] /= moduliQ[sizeQ - k + j].ConvertToDouble();
                        }
                    }
                    else {
                        m_scalingFactorsReal[k] = 1;
                    }
                }
                else {
                    double prevSF           = m_scalingFactorsReal[k - 1];
                    m_scalingFactorsReal[k] = prevSF * prevSF / moduliQ[sizeQ - k].ConvertToDouble();

                    if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT) {
                        double ratio = m_scalingFactorsReal[k] / lastPresetFactor;
                        if (ratio <= 0.5 || ratio >= 2.0) {
                            OPENFHE_THROW("FLEXIBLEAUTO scaling failed at level " + std::to_string(k) +
                                          " with scaling factor ratio " + std::to_string(ratio) +
                                          ". Use FIXEDMANUAL or FIXEDAUTO instead.");
                        }
                    }
                }
            }
        }

        m_scalingFactorsRealBig.resize(sizeQ - 1);

        if (m_scalingFactorsRealBig.size() > 0) {
            if (extraBits == 0) {
                m_scalingFactorsRealBig[0] = m_scalingFactorsReal[0] * m_scalingFactorsReal[0];
            }
            else {
                m_scalingFactorsRealBig[0] = m_scalingFactorsReal[0] * m_scalingFactorsReal[1];
            }
            for (uint32_t k = 1; k < sizeQ - 1; k++) {
                m_scalingFactorsRealBig[k] = m_scalingFactorsReal[k] * m_scalingFactorsReal[k];
            }
        }

        // Moduli as real
        m_dmoduliQ.resize(sizeQ);
        for (uint32_t i = 0; i < sizeQ; ++i) {
            m_dmoduliQ[i] = moduliQ[i].ConvertToDouble();
        }
    }
    else {
        const auto p = GetPlaintextModulus();
        m_approxSF   = std::pow(2, p);
    }
    if (m_ksTechnique == HYBRID) {
        const auto BarrettBase128Bit(BigInteger(1).LShiftEq(128));
        m_modqBarrettMu.resize(sizeQ);
        for (uint32_t i = 0; i < sizeQ; i++) {
            m_modqBarrettMu[i] = (BarrettBase128Bit / BigInteger(moduliQ[i])).ConvertToInt<DoubleNativeInt>();
        }
    }

    /////////////////////////////////////
    // Composite scaling : bootstrapping modulus raise (ExtendCiphertext)
    // Tables for the exact CRT basis extension (DCRTPoly::ExpandCRTBasis) from the small
    // bottom basis Ql = {q_0, ..., q_{d-1}}, d = compositeDegree (the towers remaining in
    // the depleted ciphertext), to the full basis Q. ComplQl = {q_d, ..., q_{L-1}} is the
    // complement of Ql in Q. Precomputing these here keeps ExtendCiphertext in full RNS
    // (no multiprecision arithmetic at runtime).
    /////////////////////////////////////
    if (compositeDegree > 1 && sizeQ > compositeDegree) {
        uint32_t sizeQl      = compositeDegree;
        uint32_t sizeComplQl = sizeQ - sizeQl;

        std::vector<NativeInteger> moduliComplQl(moduliQ.begin() + sizeQl, moduliQ.end());
        std::vector<NativeInteger> rootsComplQl(rootsQ.begin() + sizeQl, rootsQ.end());
        m_paramsModRaiseComplQl = std::make_shared<ILDCRTParams<BigInteger>>(GetElementParams()->GetCyclotomicOrder(),
                                                                             moduliComplQl, rootsComplQl);

        BigInteger modulusQl(1);
        for (uint32_t i = 0; i < sizeQl; ++i)
            modulusQl *= BigInteger(moduliQ[i]);

        // Ql/q_i, shared by the QlHatInvModq and QlHatModComplq tables below
        std::vector<BigInteger> QlHat(sizeQl);
        for (uint32_t i = 0; i < sizeQl; ++i)
            QlHat[i] = modulusQl / BigInteger(moduliQ[i]);

        // [(Ql/q_i)^{-1}]_{q_i}
        m_modRaiseQlHatInvModq.resize(sizeQl);
        m_modRaiseQlHatInvModqPrecon.resize(sizeQl);
        for (uint32_t i = 0; i < sizeQl; ++i) {
            m_modRaiseQlHatInvModq[i]       = QlHat[i].ModInverse(BigInteger(moduliQ[i])).ConvertToInt();
            m_modRaiseQlHatInvModqPrecon[i] = m_modRaiseQlHatInvModq[i].PrepModMulConst(moduliQ[i]);
        }

        // [Ql/q_i]_{q_j} and the overflow correction [a*Ql]_{q_j}, 0 <= a <= sizeQl, q_j in ComplQl;
        // the alpha table is a running sum whose a = 0 row keeps the zero value assign() gives it
        m_modRaiseQlHatModComplq.assign(sizeComplQl, std::vector<NativeInteger>(sizeQl));
        m_modRaiseAlphaQlModComplq.assign(sizeQl + 1, std::vector<NativeInteger>(sizeComplQl));
        for (uint32_t j = 0; j < sizeComplQl; ++j) {
            BigInteger qj(moduliComplQl[j]);
            for (uint32_t i = 0; i < sizeQl; ++i)
                m_modRaiseQlHatModComplq[j][i] = QlHat[i].Mod(qj).ConvertToInt();
            NativeInteger QlModqj = modulusQl.Mod(qj).ConvertToInt();
            for (uint32_t a = 1; a <= sizeQl; ++a)
                m_modRaiseAlphaQlModComplq[a][j] =
                    m_modRaiseAlphaQlModComplq[a - 1][j].ModAddFast(QlModqj, moduliComplQl[j]);
        }

        if (m_modqBarrettMu.size() == sizeQ) {
            // reuse the Barrett constants computed for HYBRID above
            m_modRaiseModComplqBarrettMu.assign(m_modqBarrettMu.begin() + sizeQl, m_modqBarrettMu.end());
        }
        else {
            m_modRaiseModComplqBarrettMu.resize(sizeComplQl);
            const auto BarrettBase128Bit(BigInteger(1).LShiftEq(128));
            for (uint32_t j = 0; j < sizeComplQl; ++j)
                m_modRaiseModComplqBarrettMu[j] =
                    (BarrettBase128Bit / BigInteger(moduliComplQl[j])).ConvertToInt<DoubleNativeInt>();
        }

        // 1./q_i for q_i in Ql (used for the fractional part of the overflow correction)
        m_modRaiseqInv.resize(sizeQl);
        for (uint32_t i = 0; i < sizeQl; ++i)
            m_modRaiseqInv[i] = 1.0 / moduliQ[i].ConvertToDouble();
    }

    /////////////////////////////////////
    // Sparse secret encapsulation (SPARSE_ENCAPSULATED): auxiliary basis and tables for the
    // key switching to/from the sparse secret at the bootstrapping modulus raise
    // (FHECKKSRNS::KeySwitchGenSparse / KeySwitchSparse). The switching key is generated
    // over Ql*P', where Ql = {q_0, ..., q_{d-1}} (d = compositeDegree) is the basis of the
    // bottom level and P' = p'_0*...*p'_{k-1} is an auxiliary modulus exceeding the bottom
    // modulus by ~6 bits, so that the key switching noise floor(Ql*e/P') is comparable to the
    // modulus switching noise (see https://github.com/openfheorg/openfhe-development/issues/1041):
    // - for a bottom modulus of at most 60 bits, P' has ~66 bits: two primes of
    //   MAX_MODULUS_SIZE/2 + 3 = 33 bits (the standard 64-bit build), or, for composite scaling
    //   with a register word size of at most 33 bits, three primes of ~22 bits;
    // - for a larger bottom modulus (composite scaling only; at most 121 bits), P' has ~127 bits,
    //   split into primes that fit the register word size.
    // The primes of the composite scaling cases are searched upwards from the target size, so
    // that enough primes congruent to 1 modulo 2N exist for ring dimensions up to 2^17 (the
    // resulting P' is then slightly larger than the target, which only reduces the noise).
    // The tables below support the exact (HPS-style) CRT basis switches (DCRTPoly::SwitchCRTBasis)
    // used to extend the ciphertext/keys from Ql to P' and to scale the key-switched ciphertext
    // back down from Ql*P' to Ql; the exact method is used so that no alpha*P' overflow term is
    // dropped during the basis switches.
    /////////////////////////////////////
    if (GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
        const uint32_t sizeQl = compositeDegree;
        if (sizeQ < sizeQl)
            OPENFHE_THROW("The modulus chain is shorter than the composite degree.");

        BigInteger modulusQl(1);
        for (uint32_t i = 0; i < sizeQl; ++i)
            modulusQl *= BigInteger(moduliQ[i]);
        const uint32_t bitsQl = modulusQl.GetMSB();
        if (bitsQl > 121)
            OPENFHE_THROW(
                "SPARSE_ENCAPSULATED supports a bottom (first) modulus of at most 121 bits; the current one has " +
                std::to_string(bitsQl) + " bits.");

        // total size of the auxiliary modulus P' and the number/size of its primes: ~66 bits for bottom moduli
        // of at most 60 bits, and ~127 bits for larger ones (up to 121 bits; the Hamming weight of the sparse
        // secret is doubled as well)
        constexpr uint32_t smallBottomModulusBits = 60;
        const uint32_t auxBitsSparse              = (bitsQl <= smallBottomModulusBits) ? 66 : 127;
        m_sparseKSHammingWeight                   = (bitsQl <= smallBottomModulusBits) ? 32 : 64;
        const bool isComposite                    = (compositeDegree > 1);
        const uint32_t registerBits               = (isComposite) ? GetRegisterWordSize() : MAX_MODULUS_SIZE;
        uint32_t sizePSparse                      = 2;
        uint32_t bitsPSparse                      = (auxBitsSparse + sizePSparse - 1) / sizePSparse;
        // the primes have to fit (strictly) in the register word size and in a native integer
        while (bitsPSparse >= registerBits || bitsPSparse > MAX_MODULUS_SIZE) {
            ++sizePSparse;
            bitsPSparse = (auxBitsSparse + sizePSparse - 1) / sizePSparse;
        }
        // the original configuration (two 33-bit primes searched downwards) is kept for the non-composite case
        const bool searchDown = (!isComposite && sizePSparse == 2);

        uint32_t n         = GetElementParams()->GetRingDimension();
        uint64_t primeStep = FindAuxPrimeStep();

        // the auxiliary primes must differ from all moduli in Q and in the hybrid key
        // switching basis P (a repeated modulus would be registered with a different root
        // of unity in the NTT tables)
        std::vector<NativeInteger> moduliToAvoid = moduliQ;
        if (GetParamsP() != nullptr) {
            for (const auto& p : GetParamsP()->GetParams())
                moduliToAvoid.push_back(p->GetModulus());
        }

        std::vector<NativeInteger> moduliPSparse(sizePSparse);
        std::vector<NativeInteger> rootsPSparse(sizePSparse);
        NativeInteger pCur = FirstPrime<NativeInteger>(bitsPSparse, primeStep);
        if (!searchDown) {
            // FirstPrime returns the smallest prime with bitsPSparse bits; start just below it so the
            // loop below can accept it
            pCur = PreviousPrime<NativeInteger>(pCur, primeStep);
        }
        BigInteger modulusPSparse(1);
        for (uint32_t j = 0; j < sizePSparse; ++j) {
            bool found = false;
            do {
                pCur  = (searchDown) ? PreviousPrime<NativeInteger>(pCur, primeStep) :
                                       NextPrime<NativeInteger>(pCur, primeStep);
                found = (std::find(moduliToAvoid.begin(), moduliToAvoid.end(), pCur) != moduliToAvoid.end());
            } while (found);
            if (isComposite && pCur.GetMSB() > registerBits)
                OPENFHE_THROW(
                    "Could not find enough auxiliary primes for SPARSE_ENCAPSULATED that fit the register word "
                    "size (" +
                    std::to_string(registerBits) + " bits) for this ring dimension.");
            moduliPSparse[j] = pCur;
            rootsPSparse[j]  = RootOfUnity<NativeInteger>(2 * n, moduliPSparse[j]);
            modulusPSparse *= BigInteger(moduliPSparse[j]);
        }

        std::vector<NativeInteger> moduliQlSparse(moduliQ.begin(), moduliQ.begin() + sizeQl);
        std::vector<NativeInteger> rootsQlSparse(rootsQ.begin(), rootsQ.begin() + sizeQl);

        m_sparseKSParamsP = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliPSparse, rootsPSparse);
        m_sparseKSParamsQ = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQlSparse, rootsQlSparse);

        std::vector<NativeInteger> moduliQPSparse(moduliQlSparse);
        std::vector<NativeInteger> rootsQPSparse(rootsQlSparse);
        moduliQPSparse.insert(moduliQPSparse.end(), moduliPSparse.begin(), moduliPSparse.end());
        rootsQPSparse.insert(rootsQPSparse.end(), rootsPSparse.begin(), rootsPSparse.end());
        m_sparseKSParamsQP = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQPSparse, rootsQPSparse);

        // Pre-compute CRT::FFT values for P'
        ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsPSparse, 2 * n, moduliPSparse);

        const auto BarrettBase128Bit(BigInteger(1).LShiftEq(128));

        // ---- tables for the switch from P' to Ql (scaling down after the key switch) ----
        m_sparseKSPModq.resize(sizeQl);
        m_sparseKSPInvModq.resize(sizeQl);
        m_sparseKSPHatModq.assign(sizeQl, std::vector<NativeInteger>(sizePSparse));
        m_sparseKSAlphaPModq.assign(sizePSparse + 1, std::vector<NativeInteger>(sizeQl));
        m_sparseKSModqBarrettMu.resize(sizeQl);
        for (uint32_t i = 0; i < sizeQl; ++i) {
            BigInteger qi(moduliQ[i]);
            m_sparseKSPModq[i]    = modulusPSparse.Mod(qi).ConvertToInt();
            m_sparseKSPInvModq[i] = modulusPSparse.ModInverse(qi).ConvertToInt();
            for (uint32_t j = 0; j < sizePSparse; ++j)
                m_sparseKSPHatModq[i][j] = (modulusPSparse / BigInteger(moduliPSparse[j])).Mod(qi).ConvertToInt();
            // the overflow correction [a*P']_{q_i}, 0 <= a <= k (running sum; the a = 0 row stays zero)
            for (uint32_t a = 1; a <= sizePSparse; ++a)
                m_sparseKSAlphaPModq[a][i] = m_sparseKSAlphaPModq[a - 1][i].ModAddFast(m_sparseKSPModq[i], moduliQ[i]);
            // reuse the Barrett constants computed for HYBRID above when available
            m_sparseKSModqBarrettMu[i] = (m_modqBarrettMu.size() > i) ?
                                             m_modqBarrettMu[i] :
                                             (BarrettBase128Bit / qi).ConvertToInt<DoubleNativeInt>();
        }
        // [(P'/p'_j)^{-1}]_{p'_j} and 1./p'_j
        m_sparseKSPHatInvModp.resize(sizePSparse);
        m_sparseKSPHatInvModpPrecon.resize(sizePSparse);
        m_sparseKSpInv.resize(sizePSparse);
        for (uint32_t j = 0; j < sizePSparse; ++j) {
            BigInteger pj(moduliPSparse[j]);
            BigInteger PHatj               = modulusPSparse / pj;
            m_sparseKSPHatInvModp[j]       = PHatj.ModInverse(pj).ConvertToInt();
            m_sparseKSPHatInvModpPrecon[j] = m_sparseKSPHatInvModp[j].PrepModMulConst(moduliPSparse[j]);
            m_sparseKSpInv[j]              = 1.0 / moduliPSparse[j].ConvertToDouble();
        }

        // ---- tables for the switch from Ql to P' (extending the ciphertext and the keys) ----
        // [(Ql/q_i)^{-1}]_{q_i} and 1/q_i are shared with the composite scaling modulus raise
        // (m_modRaiseQlHatInvModq etc.); only the P'-dependent tables are computed here.
        m_sparseKSQlHatModp.assign(sizePSparse, std::vector<NativeInteger>(sizeQl));
        m_sparseKSAlphaQlModp.assign(sizeQl + 1, std::vector<NativeInteger>(sizePSparse));
        m_sparseKSModpBarrettMu.resize(sizePSparse);
        for (uint32_t j = 0; j < sizePSparse; ++j) {
            BigInteger pj(moduliPSparse[j]);
            for (uint32_t i = 0; i < sizeQl; ++i)
                m_sparseKSQlHatModp[j][i] = (modulusQl / BigInteger(moduliQ[i])).Mod(pj).ConvertToInt();
            NativeInteger QlModpj = modulusQl.Mod(pj).ConvertToInt();
            for (uint32_t a = 1; a <= sizeQl; ++a)
                m_sparseKSAlphaQlModp[a][j] = m_sparseKSAlphaQlModp[a - 1][j].ModAddFast(QlModpj, moduliPSparse[j]);
            m_sparseKSModpBarrettMu[j] = (BarrettBase128Bit / pj).ConvertToInt<DoubleNativeInt>();
        }
    }
}

uint64_t CryptoParametersCKKSRNS::FindAuxPrimeStep() const {
    size_t n = GetElementParams()->GetRingDimension();
    return static_cast<uint64_t>(2 * n);
}

void CryptoParametersCKKSRNS::ConfigureCompositeDegree(uint32_t scalingModSize) {
    // Add logic to determine whether composite scaling is feasible or not
    if (GetScalingTechnique() == COMPOSITESCALINGAUTO) {
        uint32_t registerWordSize = GetRegisterWordSize();
        if (registerWordSize <= 64) {
            if (registerWordSize < scalingModSize) {
                uint32_t compositeDegree =
                    static_cast<uint32_t>(std::ceil(static_cast<float>(scalingModSize) / registerWordSize));
                // Assert minimum allowed moduli size on composite scaling mode
                // @fdiasmor TODO: make it more robust for a range of multiplicative depth
                if (static_cast<float>(scalingModSize) / compositeDegree < 19) {
                    std::string errMsg = "Moduli size (";
                    errMsg += std::to_string(static_cast<float>(scalingModSize) / compositeDegree);
                    errMsg +=
                        ") is too short (< 19) for target multiplicative depth. Consider increasing the scaling factor or the register word size.";
                    OPENFHE_THROW(errMsg);
                }
                m_compositeDegree = compositeDegree;
            }  // else composite degree remains set to 1
        }
        else {
            OPENFHE_THROW("COMPOSITESCALING scaling technique only supports register word size <= 64.");
        }
    }
}

}  // namespace lbcrypto
