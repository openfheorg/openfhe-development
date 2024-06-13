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

#ifndef LBCRYPTO_CRYPTO_RNS_CRYPTOPARAMETERS_H
#define LBCRYPTO_CRYPTO_RNS_CRYPTOPARAMETERS_H

#include "lattice/lat-hal.h"

#include "schemebase/rlwe-cryptoparameters.h"

#include <string>
#include <vector>
#include <memory>
#include <utility>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief main implementation class to capture essential cryptoparameters of
 * any LBC system.
 * As CryptoParametersRNS is not an abstract class and we don't want to
 * instantiate, then we make all its constructors and the destructor protected
 * @tparam Element a ring element.
 */
class CryptoParametersRNS : public CryptoParametersRLWE<DCRTPoly> {
    using ParmType = typename DCRTPoly::Params;

protected:
    CryptoParametersRNS()
        : CryptoParametersRLWE<DCRTPoly>(),
          m_ksTechnique(BV),
          m_scalTechnique(FIXEDMANUAL),
          m_encTechnique(STANDARD),
          m_multTechnique(HPS),
          m_MPIntBootCiphertextCompressionLevel(SLACK) {}

    CryptoParametersRNS(const CryptoParametersRNS& rhs)
        : CryptoParametersRLWE<DCRTPoly>(rhs),
          m_ksTechnique(rhs.m_ksTechnique),
          m_scalTechnique(rhs.m_scalTechnique),
          m_encTechnique(rhs.m_encTechnique),
          m_multTechnique(rhs.m_multTechnique),
          m_MPIntBootCiphertextCompressionLevel(rhs.m_MPIntBootCiphertextCompressionLevel) {}

    /**
   * Constructor that initializes values.  Note that it is possible to set
   * parameters in a way that is overall infeasible for actual use. There are
   * fewer degrees of freedom than parameters provided.  Typically one chooses
   * the basic noise, assurance and security parameters as the typical
   * community-accepted values, then chooses the plaintext modulus and depth
   * as needed.  The element parameters should then be choosen to provide
   * correctness and security.  In some cases we would need to operate over
   * already encrypted/provided ciphertext and the depth needs to be
   * pre-computed for initial settings.
   *
   * @param params element parameters.
   * @param &plaintextModulus plaintext modulus.
   * @param distributionParameter noise distribution parameter.
   * @param assuranceMeasure assurance level.
   * @param securityLevel security level.
   * @param digitSize the size of the relinearization window.
   * @param secretKeyDist sets the secretKeyDist of operation: GAUSSIAN or UNIFORM_TERNARY
   * @param maxRelinSkDeg the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching method
   * @param scalTech scaling method
   * @param mPIntBootCiphertextCompressionLevel compression level
   */
    CryptoParametersRNS(std::shared_ptr<ParmType> params, const PlaintextModulus& plaintextModulus,
                        float distributionParameter, float assuranceMeasure, SecurityLevel securityLevel,
                        usint digitSize, SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2,
                        KeySwitchTechnique ksTech = BV, ScalingTechnique scalTech = FIXEDMANUAL,
                        EncryptionTechnique encTech = STANDARD, MultiplicationTechnique multTech = HPS,
                        MultipartyMode multipartyMode                         = FIXED_NOISE_MULTIPARTY,
                        ExecutionMode executionMode                           = EXEC_EVALUATION,
                        DecryptionNoiseMode decryptionNoiseMode               = FIXED_NOISE_DECRYPT,
                        COMPRESSION_LEVEL mPIntBootCiphertextCompressionLevel = COMPRESSION_LEVEL::SLACK)
        : CryptoParametersRLWE<DCRTPoly>(
              std::move(params), EncodingParams(std::make_shared<EncodingParamsImpl>(plaintextModulus)),
              distributionParameter, assuranceMeasure, securityLevel, digitSize, maxRelinSkDeg, secretKeyDist, INDCPA,
              multipartyMode, executionMode, decryptionNoiseMode) {
        m_ksTechnique                         = ksTech;
        m_scalTechnique                       = scalTech;
        m_encTechnique                        = encTech;
        m_multTechnique                       = multTech;
        m_MPIntBootCiphertextCompressionLevel = mPIntBootCiphertextCompressionLevel;
    }

    CryptoParametersRNS(std::shared_ptr<ParmType> params, EncodingParams encodingParams, float distributionParameter,
                        float assuranceMeasure, SecurityLevel securityLevel, usint digitSize,
                        SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2, KeySwitchTechnique ksTech = BV,
                        ScalingTechnique scalTech = FIXEDMANUAL, EncryptionTechnique encTech = STANDARD,
                        MultiplicationTechnique multTech = HPS, ProxyReEncryptionMode PREMode = INDCPA,
                        MultipartyMode multipartyMode           = FIXED_NOISE_MULTIPARTY,
                        ExecutionMode executionMode             = EXEC_EVALUATION,
                        DecryptionNoiseMode decryptionNoiseMode = FIXED_NOISE_DECRYPT, PlaintextModulus noiseScale = 1,
                        uint32_t statisticalSecurity = 30, uint32_t numAdversarialQueries = 1,
                        uint32_t thresholdNumOfParties                        = 1,
                        COMPRESSION_LEVEL mPIntBootCiphertextCompressionLevel = COMPRESSION_LEVEL::SLACK)
        : CryptoParametersRLWE<DCRTPoly>(std::move(params), std::move(encodingParams), distributionParameter,
                                         assuranceMeasure, securityLevel, digitSize, maxRelinSkDeg, secretKeyDist,
                                         PREMode, multipartyMode, executionMode, decryptionNoiseMode, noiseScale,
                                         statisticalSecurity, numAdversarialQueries, thresholdNumOfParties) {
        m_ksTechnique                         = ksTech;
        m_scalTechnique                       = scalTech;
        m_encTechnique                        = encTech;
        m_multTechnique                       = multTech;
        m_MPIntBootCiphertextCompressionLevel = mPIntBootCiphertextCompressionLevel;
    }

    virtual ~CryptoParametersRNS() {}

public:
    /**
   * Computes all tables needed for decryption, homomorphic multiplication and key switching.
   * Even though this is a pure virtual function and must be overriden in all derived classes,
   * PrecomputeCRTTables() has its own implementation in the source file. It should be called from
   * derived classes' PrecomputeCRTTables() only and must not be called from CryptoParametersRNS::load().
   * @param ksTech the technique to use for key switching (e.g., BV or GHS).
   * @param scalTech the technique to use for scaling (e.g., FLEXIBLEAUTO or FIXEDMANUAL).
   */
    virtual void PrecomputeCRTTables(KeySwitchTechnique ksTech, ScalingTechnique scalTech, EncryptionTechnique encTech,
                                     MultiplicationTechnique multTech, uint32_t numPartQ, uint32_t auxBits,
                                     uint32_t extraBits) = 0;

    virtual uint64_t FindAuxPrimeStep() const;

    /*
   * Estimates the extra modulus bitsize needed for hybrid key swithing (used for finding the minimum secure ring dimension).
   *
   * @param numPartQ number of digits in hybrid key switching
   * @param firstModulusSize bit size of first modulus
   * @param dcrtBits bit size for other moduli
   * @param extraModulusSize bit size for extra modulus in FLEXIBLEAUTOEXT (CKKS and BGV only)
   * @param numPrimes number of moduli witout extraModulus
   * @param auxBits size of auxiliar moduli used for hybrid key switching
   *
   * @return log2 of the modulus and number of RNS limbs.
   */
    static std::pair<double, uint32_t> EstimateLogP(uint32_t numPartQ, double firstModulusSize, double dcrtBits,
                                                    double extraModulusSize, uint32_t numPrimes, uint32_t auxBits);

    /*
   * Estimates the extra modulus bitsize needed for threshold FHE noise flooding (only for BGV and BFV)
   *
   * @return number of extra bits needed for noise flooding
   */
    static constexpr double EstimateMultipartyFloodingLogQ() {
        return static_cast<double>(NoiseFlooding::MULTIPARTY_MOD_SIZE * NoiseFlooding::NUM_MODULI_MULTIPARTY);
    }

    /**
   * == operator to compare to this instance of CryptoParametersBase object.
   *
   * @param &rhs CryptoParameters to check equality against.
   */
    bool operator==(const CryptoParametersBase<DCRTPoly>& rhs) const override {
        const auto* el = dynamic_cast<const CryptoParametersRNS*>(&rhs);

        if (el == nullptr)
            return false;

        return CryptoParametersBase<DCRTPoly>::operator==(rhs) && m_scalTechnique == el->GetScalingTechnique() &&
               m_ksTechnique == el->GetKeySwitchTechnique() && m_multTechnique == el->GetMultiplicationTechnique() &&
               m_encTechnique == el->GetEncryptionTechnique() && m_numPartQ == el->GetNumPartQ() &&
               m_auxBits == el->GetAuxBits() && m_extraBits == el->GetExtraBits() && m_PREMode == el->GetPREMode() &&
               m_multipartyMode == el->GetMultipartyMode() && m_executionMode == el->GetExecutionMode();
    }

    void PrintParameters(std::ostream& os) const override {
        CryptoParametersBase<DCRTPoly>::PrintParameters(os);
    }

    /////////////////////////////////////
    // PrecomputeCRTTables
    /////////////////////////////////////

    /**
   * Method to retrieve the technique to be used for key switching.
   *
   * @return the key switching technique.
   */
    enum KeySwitchTechnique GetKeySwitchTechnique() const {
        return m_ksTechnique;
    }

    /**
   * Method to retrieve the technique to be used for scaling.
   *
   * @return the scaling technique.
   */
    enum ScalingTechnique GetScalingTechnique() const {
        return m_scalTechnique;
    }

    /**
   * Method to retrieve the technique to be used for rescaling.
   *
   * @return the rescaling technique.
   */
    enum EncryptionTechnique GetEncryptionTechnique() const {
        return m_encTechnique;
    }

    /**
   * Method to retrieve the technique to be used for rescaling.
   *
   * @return the rescaling technique.
   */
    enum MultiplicationTechnique GetMultiplicationTechnique() const {
        return m_multTechnique;
    }

    uint32_t GetAuxBits() const {
        return m_auxBits;
    }

    uint32_t GetExtraBits() const {
        return m_extraBits;
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> GetParamsPK() const override {
        if ((m_ksTechnique == HYBRID) && (m_PREMode != NOT_SET))
            return m_paramsQP;
        if ((m_encTechnique == EXTENDED) && (m_paramsQr != nullptr))
            return m_paramsQr;
        return m_params;
    }

    /////////////////////////////////////
    // BGVrns : ModReduce
    /////////////////////////////////////

    /**
   * Method that returns the NTL precomputions for [t]_{q_i}
   *
   * @return the pre-computed values.
   */
    const std::vector<NativeInteger>& GettModqPrecon() const {
        return m_tModqPrecon;
    }

    /**
   * Get the precomputed table of [-t^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
    const NativeInteger& GetNegtInvModq(usint l) const {
        return m_negtInvModq[l];
    }

    /**
   * Method that returns the NTL precomputions for [-t^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
    const NativeInteger& GetNegtInvModqPrecon(usint l) const {
        return m_negtInvModqPrecon[l];
    }

    /////////////////////////////////////
    // CKKSrns : DropLastElementAndScale
    /////////////////////////////////////

    /**
   * Q^(l) = \prod_{j=0}^{l-1}
   * Gets the precomputed table of [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetQlQlInvModqlDivqlModq(size_t i) const {
        return m_QlQlInvModqlDivqlModq[i];
    }

    /**
   * Q^(l) = \prod_{j=0}^{l-1}
   * Gets the NTL precomputions for [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetQlQlInvModqlDivqlModqPrecon(size_t i) const {
        return m_QlQlInvModqlDivqlModqPrecon[i];
    }

    /**
   * Gets the precomputed table of [q_i^{-1}]_{q_j}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetqlInvModq(size_t i) const {
        return m_qlInvModq[i];
    }

    /**
   * Gets the NTL precomputions for [q_i^{-1}]_{q_j}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetqlInvModqPrecon(size_t i) const {
        return m_qlInvModqPrecon[i];
    }

    /////////////////////////////////////
    // KeySwitchHybrid : KeyGen
    /////////////////////////////////////

    /**
   * Gets Q*P CRT basis
   * Q*P = {q_1,...,q_l,p_1,...,p_k}
   * Used in Hybrid key switch generation
   *
   * @return the precomputed CRT params
   */
    const std::shared_ptr<ILDCRTParams<BigInteger>> GetParamsQP() const {
        return m_paramsQP;
    }

    /**
   * Method that returns the number of digits.
   * Used in Hybrid key switch generation
   * @return the number of digits.
   */
    uint32_t GetNumPartQ() const {
        return m_numPartQ;
    }

    /**
   * Gets the precomputed table of [P]_{q_i}
   * Used in Hybrid key switch generation.
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetPModq() const {
        return m_PModq;
    }

    /////////////////////////////////////
    // KeySwitchHybrid : KeySwitch
    /////////////////////////////////////

    /**
   * Gets the Auxiliary CRT basis {P} = {p_1,...,p_k}
   * Used in Hybrid key switching
   *
   * @return the parameters CRT params
   */
    const std::shared_ptr<ILDCRTParams<BigInteger>> GetParamsP() const {
        return m_paramsP;
    }

    /**
   * Method that returns the number of towers within every digit.
   * This is the alpha parameter from the paper (see documentation
   * for KeySwitchHHybrid).
   * Used in Hybrid key switching
   *
   * @return the number of towers per digit.
   */
    uint32_t GetNumPerPartQ() const {
        return m_numPerPartQ;
    }

    /*
   * Method that returns the number of partitions.
   * Used in Hybrid key switching
   *
   * @return the number of partitions.
   */
    uint32_t GetNumberOfQPartitions() const {
        return m_paramsPartQ.size();
    }

    /**
   * Method that returns the element parameters corresponding to
   * partitions {Q_j} of Q.
   * Used in Hybrid key switching
   *
   * @return the pre-computed values.
   */
    const std::shared_ptr<ILDCRTParams<BigInteger>>& GetParamsPartQ(uint32_t part) const {
        return m_paramsPartQ[part];
    }

    /*
   * Method that returns the element parameters corresponding to the
   * complementary basis of a single digit j, i.e., the basis consisting of
   * all other digits plus the special primes. Note that numTowers should be
   * up to l (where l is the number of towers).
   *
   * @param numTowers is the total number of towers there are in the
   * ciphertext.
   * @param digit is the index of the digit we want to get the complementary
   * partition from.
   * @return the partitions.
   */
    const std::shared_ptr<ILDCRTParams<BigInteger>>& GetParamsComplPartQ(uint32_t numTowers, uint32_t digit) const {
        return m_paramsComplPartQ[numTowers][digit];
    }

    /**
   * Method that returns the precomputed values for QHat^-1 mod qj within a
   * partition of towers, used in HYBRID.
   *
   * @return the pre-computed values.
   */
    const std::vector<NativeInteger>& GetPartQlHatInvModq(uint32_t part, uint32_t sublvl) const {
        if (part < m_PartQlHatInvModq.size() && sublvl < m_PartQlHatInvModq[part].size())
            return m_PartQlHatInvModq[part][sublvl];

        OPENFHE_THROW(
            "CryptoParametersCKKS::GetPartitionQHatInvModQTable - "
            "index out of bounds.");
    }

    /**
   * Barrett multiplication precomputations getter.
   *
   * @param index The number of towers in the ciphertext.
   * @return the pre-computed values.
   */
    const std::vector<NativeInteger>& GetPartQlHatInvModqPrecon(uint32_t part, uint32_t sublvl) const {
        if (part < m_PartQlHatInvModqPrecon.size() && sublvl < m_PartQlHatInvModqPrecon[part].size())
            return m_PartQlHatInvModqPrecon[part][sublvl];

        OPENFHE_THROW(
            "CryptoParametersCKKS::"
            "GetPartitionQHatInvModQPreconTable - index "
            "out of bounds.");
    }

    /**
   * Barrett multiplication precomputations getter.
   *
   * @param index The table containing [PartQHat]_{p_j}
   * @return the pre-computed values.
   */
    const std::vector<std::vector<NativeInteger>>& GetPartQlHatModp(uint32_t lvl, uint32_t part) const {
        if (lvl < m_PartQlHatModp.size() && part < m_PartQlHatModp[lvl].size())
            return m_PartQlHatModp[lvl][part];

        OPENFHE_THROW(
            "CryptoParametersCKKS::GetPartitionQHatModPTable - "
            "index out of bounds.");
    }

    /**
   * Barrett multiplication precomputations getter.
   *
   * @param index The number of towers in the ciphertext.
   * @return the pre-computed values.
   */
    const std::vector<DoubleNativeInt>& GetmodComplPartqBarrettMu(uint32_t lvl, uint32_t part) const {
        if (lvl < m_modComplPartqBarrettMu.size() && part < m_modComplPartqBarrettMu[lvl].size())
            return m_modComplPartqBarrettMu[lvl][part];

        OPENFHE_THROW(
            "CryptoParametersCKKS::GetPartitionPrecon - index out "
            "of bounds.");
    }

    /**
   * Gets the precomputed table of [P^{-1}]_{q_i}
   * Used in GHS key switching
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetPInvModq() const {
        return m_PInvModq;
    }

    /**
   * Gets the NTL precomputions for [P^{-1}]_{q_i}
   * Used for speeding up GHS key switching.
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetPInvModqPrecon() const {
        return m_PInvModqPrecon;
    }

    /**
   * Get the precomputed table of [(P/p_j)^{-1}]_{p_j}
   * Used in GHS key switching.
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetPHatInvModp() const {
        return m_PHatInvModp;
    }

    /**
   * Get the NTL precomputions for [(P/p_j)^{-1}]_{p_j}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetPHatInvModpPrecon() const {
        return m_PHatInvModpPrecon;
    }

    /**
   * Gets the precomputed table of [P/p_j]_{q_i}
   * Used in GHS key switching.
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GetPHatModq() const {
        return m_PHatModq;
    }

    /**
   * Gets the Barrett modulo reduction precomputation for q_i
   *
   * @return the precomputed table
   */
    const std::vector<DoubleNativeInt>& GetModqBarrettMu() const {
        return m_modqBarrettMu;
    }

    /**
   * Method that returns the precomputed values for [t^(-1)]_{q_i}
   * Used in ModulusSwitching.
   *
   * @return the pre-computed values.
   */
    const std::vector<NativeInteger>& GettInvModq() const {
        return m_tInvModq;
    }

    /**
   * Method that returns the NTL precomputions for [t^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
    const std::vector<NativeInteger>& GettInvModqPrecon() const {
        return m_tInvModqPrecon;
    }

    /**
   * Method that returns the precomputed values for [t^(-1)]_{p_j}
   * Used in KeySwitching.
   *
   * @return the pre-computed values.
   */
    const std::vector<NativeInteger>& GettInvModp() const {
        return m_tInvModp;
    }

    /**
   * Method that returns the NTL precomputions for [t^{-1}]_{p_j}
   *
   * @return the pre-computed values.
   */
    const std::vector<NativeInteger>& GettInvModpPrecon() const {
        return m_tInvModpPrecon;
    }

    /////////////////////////////////////
    // CKKSrns Scaling Factor
    /////////////////////////////////////

    /**
   * Method to retrieve the scaling factor of level l.
   * For FIXEDMANUAL scaling technique method always returns 2^p, where p corresponds to plaintext modulus
   * @param l For FLEXIBLEAUTO scaling technique the level whose scaling factor we want to learn.
   * Levels start from 0 (no scaling done - all towers) and go up to K-1, where K is the number of towers supported.
   * @return the scaling factor.
   */
    double GetScalingFactorReal(uint32_t l = 0) const {
        if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT) {
            if (l >= m_scalingFactorsReal.size()) {
                // TODO: Return an error here.
                return m_approxSF;
            }

            return m_scalingFactorsReal[l];
        }

        return m_approxSF;
    }

    double GetScalingFactorRealBig(uint32_t l = 0) const {
        if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT) {
            if (l >= m_scalingFactorsRealBig.size()) {
                // TODO: Return an error here.
                return m_approxSF;
            }

            return m_scalingFactorsRealBig[l];
        }

        return m_approxSF;
    }

    /**
   * Method to retrieve the modulus to be dropped of level l.
   * For FIXEDMANUAL rescaling technique method always returns 2^p, where p corresponds to plaintext modulus
   * @param l index of modulus to be dropped for FLEXIBLEAUTO scaling technique
   * @return the precomputed table
   */
    double GetModReduceFactor(uint32_t l = 0) const {
        if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT) {
            return m_dmoduliQ[l];
        }

        return m_approxSF;
    }

    /////////////////////////////////////
    // BFVrns : Encrypt : POverQ
    /////////////////////////////////////

    const NativeInteger GetNegQModt(uint32_t i = 0) const {
        return m_negQModt[i];
    }

    const NativeInteger GetNegQModtPrecon(uint32_t i = 0) const {
        return m_negQModtPrecon[i];
    }

    const NativeInteger GetNegQrModt() const {
        return m_negQrModt;
    }

    const NativeInteger GetNegQrModtPrecon() const {
        return m_negQrModtPrecon;
    }

    /**
   * Method that returns the precomputed values for [t^(-1)]_{a} where a is from {q_i} U r
   * Used in ModulusSwitching.
   *
   * @return the pre-computed values.
   */
    const std::vector<NativeInteger>& GettInvModqr() const {
        return m_tInvModqr;
    }

    /////////////////////////////////////
    // BFVrns : Mult : ExpandCRTBasis
    /////////////////////////////////////

    const std::shared_ptr<ILDCRTParams<BigInteger>> GetParamsQl(usint l = 0) const {
        return m_paramsQl[l];
    }

    const std::vector<double>& GetQlQHatInvModqDivqFrac(usint l) const {
        return m_QlQHatInvModqDivqFrac[l];
    }

    const std::vector<std::vector<NativeInteger>>& GetQlQHatInvModqDivqModq(usint l) const {
        return m_QlQHatInvModqDivqModq[l];
    }

    /**
   * Gets the Auxiliary CRT basis {R} = {r_1,...,r_k}
   * used in homomorphic multiplication
   *
   * @return the precomputed CRT params
   */
    const std::shared_ptr<ILDCRTParams<BigInteger>> GetParamsRl(usint l = 0) const {
        return m_paramsRl[l];
    }

    /**
   * Gets the Auxiliary expanded CRT basis {S} = {Q*R} =
   * {{q_i},{r_k}} used in homomorphic multiplication
   *
   * @return the precomputed CRT params
   */
    const std::shared_ptr<ILDCRTParams<BigInteger>> GetParamsQlRl(usint l = 0) const {
        return m_paramsQlRl[l];
    }

    /**
   * Gets the precomputed table of [(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetQlHatInvModq(usint l = 0) const {
        return m_QlHatInvModq[l];
    }

    /**
   * Gets the NTL precomputations for [(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetQlHatInvModqPrecon(usint l = 0) const {
        return m_QlHatInvModqPrecon[l];
    }

    /**
   * Gets the precomputed table of [Q/q_i]_{r_k}
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GetQlHatModr(usint l = 0) const {
        return m_QlHatModr[l];
    }

    /**
   * Gets the precomputed table of [\alpha*Q]_{r_k}
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GetalphaQlModr(usint l = 0) const {
        return m_alphaQlModr[l];
    }

    const std::vector<NativeInteger>& GetmNegRlQHatInvModq(usint l = 0) const {
        return m_negRlQHatInvModq[l];
    }

    const std::vector<NativeInteger>& GetmNegRlQHatInvModqPrecon(usint l = 0) const {
        return m_negRlQHatInvModqPrecon[l];
    }

    const std::vector<NativeInteger>& GetmNegRlQlHatInvModq(usint l = 0) const {
        return m_negRlQlHatInvModq[l];
    }

    const std::vector<NativeInteger>& GetmNegRlQlHatInvModqPrecon(usint l = 0) const {
        return m_negRlQlHatInvModqPrecon[l];
    }

    const std::vector<std::vector<NativeInteger>>& GetqInvModr() const {
        return m_qInvModr;
    }

    /**
   * Gets the Barrett modulo reduction precomputations for r_k
   *
   * @return the precomputed table
   */
    std::vector<DoubleNativeInt> const& GetModrBarrettMu() const {
        return m_modrBarrettMu;
    }

    /**
   * Gets the precomputed table of 1./q_i
   *
   * @return the precomputed table
   */
    std::vector<double> const& GetqInv() const {
        return m_qInv;
    }

    /////////////////////////////////////
    // BFVrns : Mult : ScaleAndRound
    /////////////////////////////////////

    /**
   * For S = QR
   * Gets the precomputed table of \frac{[t*R*(S/s_m)^{-1}]_{s_m}/s_m}
   *
   * @return the precomputed table
   */
    const std::vector<double>& GettRSHatInvModsDivsFrac() const {
        return m_tRSHatInvModsDivsFrac;
    }

    /**
   * For S = QR
   * Gets the precomputed table of [\floor{t*R*(S/s_m)^{-1}/s_m}]_{r_k}
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GettRSHatInvModsDivsModr() const {
        return m_tRSHatInvModsDivsModr;
    }

    /////////////////////////////////////
    // BFVrns : Mult : SwitchCRTBasis
    /////////////////////////////////////

    /**
   * Gets the precomputed table of [(R/r_k)^{-1}]_{r_k}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetRlHatInvModr(usint l = 0) const {
        return m_RlHatInvModr[l];
    }

    /**
   * Gets the NTL precomputation for [(R/r_k)^{-1}]_{r_k}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetRlHatInvModrPrecon(usint l = 0) const {
        return m_RlHatInvModrPrecon[l];
    }

    /**
   * Gets the precomputed table of [R/r_k]_{q_i}
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GetRlHatModq(usint l = 0) const {
        return m_RlHatModq[l];
    }

    /**
   * Gets the precomputed table of [\alpha*P]_{q_i}
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GetalphaRlModq(usint l = 0) const {
        return m_alphaRlModq[l];
    }

    const std::vector<double>& GettQlSlHatInvModsDivsFrac(usint l) const {
        return m_tQlSlHatInvModsDivsFrac[l];
    }

    const std::vector<std::vector<NativeInteger>>& GettQlSlHatInvModsDivsModq(usint l) const {
        return m_tQlSlHatInvModsDivsModq[l];
    }

    const std::vector<NativeInteger>& GetQlHatModq(usint l) const {
        return m_QlHatModq[l];
    }

    const std::vector<NativeInteger>& GetQlHatModqPrecon(usint l) const {
        return m_QlHatModqPrecon[l];
    }

    /**
   * Gets the precomputed table of 1./p_j
   *
   * @return the precomputed table
   */
    std::vector<double> const& GetrInv() const {
        return m_rInv;
    }

    /////////////////////////////////////
    // BFVrns : Decrypt : ScaleAndRound
    /////////////////////////////////////

    /**
   * Gets the precomputed table of \frac{t*{Q/q_i}^{-1}/q_i}
   *
   * @return the precomputed table
   */
    const std::vector<double>& GettQHatInvModqDivqFrac() const {
        return m_tQHatInvModqDivqFrac;
    }

    /**
   * When log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
   * Gets the precomputed table of \frac{t*{Q/q_i}^{-1}*B/q_i}
   *
   * @return the precomputed table
   */
    const std::vector<double>& GettQHatInvModqBDivqFrac() const {
        return m_tQHatInvModqBDivqFrac;
    }

    /**
   * Gets the precomputed table of [\floor{t*{Q/q_i}^{-1}/q_i}]_t
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GettQHatInvModqDivqModt() const {
        return m_tQHatInvModqDivqModt;
    }

    /**
   * Gets the NTL precomputations for [\floor{t*{Q/q_i}^{-1}/q_i}]_t
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GettQHatInvModqDivqModtPrecon() const {
        return m_tQHatInvModqDivqModtPrecon;
    }

    /**
   * When log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
   * Gets the precomputed table of [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GettQHatInvModqBDivqModt() const {
        return m_tQHatInvModqBDivqModt;
    }

    /**
   * When log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
   * Gets the NTL precomputations for [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GettQHatInvModqBDivqModtPrecon() const {
        return m_tQHatInvModqBDivqModtPrecon;
    }

    const NativeInteger& GetScalingFactorInt(usint l) const {
        if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT) {
            if (l >= m_scalingFactorsInt.size()) {
                // TODO: Return an error here.
                return m_fixedSF;
            }
            return m_scalingFactorsInt[l];
        }
        return m_fixedSF;
    }

    const NativeInteger& GetScalingFactorIntBig(usint l) const {
        if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT) {
            if (l >= m_scalingFactorsIntBig.size()) {
                // TODO: Return an error here.
                return m_fixedSF;
            }
            return m_scalingFactorsIntBig[l];
        }
        return m_fixedSF;
    }

    const NativeInteger& GetModReduceFactorInt(uint32_t l = 0) const {
        if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT) {
            return m_qModt[l];
        }
        return m_fixedSF;
    }

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    /**
   * Gets the precomputed table of 1./p_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetrInvModq() const {
        return m_rInvModq;
    }

    /**
   * Gets the Auxiliary CRT basis {Qr} = {Q U r}
   * used in BFV encryption in mode EXTENDED
   *
   * @return the precomputed CRT params
   */
    const std::shared_ptr<ILDCRTParams<BigInteger>> GetParamsQr() const {
        return m_paramsQr;
    }

    /////////////////////////////////////
    // BFVrnsB
    /////////////////////////////////////

    /**
   * Gets the Auxiliary CRT basis {Bsk} = {B U msk}
   * used in homomorphic multiplication
   *
   * @return the precomputed CRT params
   */
    const std::shared_ptr<ILDCRTParams<BigInteger>> GetParamsQBsk() const {
        return m_paramsQBsk;
    }

    /**
   * Gets the precomputed table of q_i
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetModuliQ() const {
        return m_moduliQ;
    }

    /**
   * Gets the precomputed table of bsk_j
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetModuliBsk() const {
        return m_moduliBsk;
    }

    /**
   * Gets the Barrett modulo reduction precomputation for bsk_j
   *
   * @return the precomputed table
   */
    std::vector<DoubleNativeInt> const& GetModbskBarrettMu() const {
        return m_modbskBarrettMu;
    }

    /**
   * Gets the precomputed table of [mtilde*(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetmtildeQHatInvModq() const {
        return m_mtildeQHatInvModq;
    }

    /**
   * Gets the NTL precomputations for [mtilde*(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetmtildeQHatInvModqPrecon() const {
        return m_mtildeQHatInvModqPrecon;
    }

    /**
   * Gets the precomputed table of [Q/q_i]_{bsk_j}
   *
   * @return the precomputed table
   */
    std::vector<std::vector<NativeInteger>> const& GetQHatModbsk() const {
        return m_QHatModbsk;
    }

    /**
   * Gets the precomputed table of [(q_i)^{-1}]_{bsk_j}
   *
   * @return the precomputed table
   */
    std::vector<std::vector<NativeInteger>> const& GetqInvModbsk() const {
        return m_qInvModbsk;
    }

    /**
   * Gets the precomputed table of [Q/q_i]_{mtilde}
   *
   * @return the precomputed table
   */
    std::vector<uint64_t> const& GetQHatModmtilde() const {
        return m_QHatModmtilde;
    }

    /**
   * Gets the precomputed table of [Q]_{bsk_j}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetQModbsk() const {
        return m_QModbsk;
    }

    /**
   * Gets the NTL precomputations for [Q]_{bsk_j}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetQModbskPrecon() const {
        return m_QModbskPrecon;
    }

    /**
   * Gets the precomputed [-Q^{-1}]_{mtilde}
   *
   * @return the precomputed value
   */
    uint64_t const& GetNegQInvModmtilde() const {
        return m_negQInvModmtilde;
    }

    /**
   * Gets the precomputed table of [mtilde^{-1}]_{bsk_j}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetmtildeInvModbsk() const {
        return m_mtildeInvModbsk;
    }

    /**
   * Gets the NTL precomputations for [mtilde^{-1}]_{bsk_j}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetmtildeInvModbskPrecon() const {
        return m_mtildeInvModbskPrecon;
    }

    /**
   * Gets the precomputed table of [t*(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GettQHatInvModq() const {
        return m_tQHatInvModq;
    }

    /**
   * Gets the NTL precomputations for [t*(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GettQHatInvModqPrecon() const {
        return m_tQHatInvModqPrecon;
    }

    /**
   * Gets the precomputed table of [t*gamma*(Q/q_i)^(-1)]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GettgammaQHatInvModq() const {
        return m_tgammaQHatInvModq;
    }

    /**
   * Gets the NTL precomputations for [t*gamma*(Q/q_i)^(-1)]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GettgammaQHatInvModqPrecon() const {
        return m_tgammaQHatInvModqPrecon;
    }

    /**
   * Gets the precomputed table of [t/Q]_{bsk_j}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GettQInvModbsk() const {
        return m_tQInvModbsk;
    }

    /**
   * Gets the NTL precomputations for [t/Q]_{bsk_j}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GettQInvModbskPrecon() const {
        return m_tQInvModbskPrecon;
    }

    /**
   * Gets the precomputed table of [(B/b_j)^{-1}]_{b_j}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetBHatInvModb() const {
        return m_BHatInvModb;
    }

    /**
   * Gets the NTL precomputations for [(B/b_j)^{-1}]_{b_j}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetBHatInvModbPrecon() const {
        return m_BHatInvModbPrecon;
    }

    /**
   * Gets the precomputed table of [B/b_j]_{msk}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetBHatModmsk() const {
        return m_BHatModmsk;
    }

    /**
   * Gets the precomputed [B^{-1}]_msk
   *
   * @return the precomputed value
   */
    NativeInteger const& GetBInvModmsk() const {
        return m_BInvModmsk;
    }

    /**
   * Gets the NTL precomputions for [B^{-1}]_msk
   *
   * @return the precomputed value
   */
    NativeInteger const& GetBInvModmskPrecon() const {
        return m_BInvModmskPrecon;
    }

    /**
   * Gets the precomputed table of [B/b_j]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<std::vector<NativeInteger>> const& GetBHatModq() const {
        return m_BHatModq;
    }

    /**
   * Gets the precomputed table of [B]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetBModq() const {
        return m_BModq;
    }

    /**
   * Gets the NTL precomputions for [B]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetBModqPrecon() const {
        return m_BModqPrecon;
    }

    /**
   * Gets auxiliary modulus gamma
   *
   * @return gamma
   */
    uint32_t const& Getgamma() const {
        return m_gamma;
    }

    // TODO: use 64 bit words in case NativeInteger uses smaller word size
    /**
   * Gets t*gamma where t - plaintext modulus, gamma - auxiliary modulus
   *
   * @return t*gamma
   */
    NativeInteger const& Gettgamma() const {
        return m_tgamma;
    }

    /**
   * Gets the precomputed table of [-(q_i)^{-1}]_{t*gamma}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetNegInvqModtgamma() const {
        return m_negInvqModtgamma;
    }

    /**
   * Gets the NTL precomputations for [-(q_i)^{-1}]_{t*gamma}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetNegInvqModtgammaPrecon() const {
        return m_negInvqModtgammaPrecon;
    }

    /**
   * Gets the precomputed table of [*(Q/q_i/q_0)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetMultipartyQHatInvModqAtIndex(usint l) const {
        return m_multipartyQHatInvModq[l];
    }

    /**
   * Gets the NTL precomputations for [*(Q/q_i/q_0)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
    std::vector<NativeInteger> const& GetMultipartyQHatInvModqPreconAtIndex(usint l) const {
        return m_multipartyQHatInvModqPrecon[l];
    }

    /**
   * Gets the precomputed table of [Q/q_i/q_0]_{q_0}
   *
   * @return the precomputed table
   */
    std::vector<std::vector<NativeInteger>> const& GetMultipartyQHatModq0AtIndex(usint l) const {
        return m_multipartyQHatModq0[l];
    }

    /**
   * Gets the precomputed table of [\alpha*Q/q_0]_{q_0} for 0 <= alpha <= 1
   *
   * @return the precomputed table
   */
    std::vector<std::vector<NativeInteger>> const& GetMultipartyAlphaQModq0AtIndex(usint l) const {
        return m_multipartyAlphaQModq0[l];
    }

    /**
   * Gets the Barrett modulo reduction precomputation for q_0
   *
   * @return the precomputed table
   */
    std::vector<DoubleNativeInt> const& GetMultipartyModq0BarrettMu() const {
        return m_multipartyModq0BarrettMu;
    }

    /**
   * Gets the precomputed table of \frac{1/q_i}
   *
   * @return the precomputed table
   */
    std::vector<double> const& GetMultipartyQInv() const {
        return m_multipartyQInv;
    }

    /////////////////////////////////////
    // CKKS RNS MultiParty Bootstrapping Parameter
    /////////////////////////////////////
    /**
   * Gets the Multi-Party Interactive Bootstrapping Ciphertext Compression Level
   * @return m_MPIntBootCiphertextCompressionLevel
   */
    COMPRESSION_LEVEL GetMPIntBootCiphertextCompressionLevel() const {
        return m_MPIntBootCiphertextCompressionLevel;
    }

protected:
    /////////////////////////////////////
    // PrecomputeCRTTables
    /////////////////////////////////////

    // Stores the technique to use for key switching
    enum KeySwitchTechnique m_ksTechnique;

    enum ScalingTechnique m_scalTechnique;

    enum EncryptionTechnique m_encTechnique;

    enum MultiplicationTechnique m_multTechnique;

    uint32_t m_auxBits = 0;

    uint32_t m_extraBits = 0;

    /////////////////////////////////////
    // BGVrns ModReduce
    /////////////////////////////////////

    // Stores NTL precomputations for [t]_{q_i}
    std::vector<NativeInteger> m_tModqPrecon;

    // Stores [-t^{-1}]_{q_i}
    std::vector<NativeInteger> m_negtInvModq;

    // Stores NTL precomputations for [-t^{-1}]_{q_i}
    std::vector<NativeInteger> m_negtInvModqPrecon;

    /////////////////////////////////////
    // CKKSrns/BFVrns DropLastElementAndScale
    /////////////////////////////////////

    // Q^(l) = \prod_{j=0}^{l-1}
    // Stores [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
    std::vector<std::vector<NativeInteger>> m_QlQlInvModqlDivqlModq;

    // Q^(l) = \prod_{j=0}^{l-1}
    // Stores NTL precomputations for [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
    std::vector<std::vector<NativeInteger>> m_QlQlInvModqlDivqlModqPrecon;

    // Stores [q_l^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> m_qlInvModq;

    // Stores NTL precomputations for [q_l^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> m_qlInvModqPrecon;

    /////////////////////////////////////
    // KeySwitchHybrid KeyGen
    /////////////////////////////////////

    // Params for Extended CRT basis {QP} = {q_1...q_l,p_1,...,p_k}
    // used in GHS key switching
    std::shared_ptr<ILDCRTParams<BigInteger>> m_paramsQP;

    // Stores the partition size {PartQ} = {Q_1,...,Q_l}
    // where each Q_i is the product of q_j
    uint32_t m_numPartQ = 0;

    // Stores [P]_{q_i}, used in GHS key switching
    std::vector<NativeInteger> m_PModq;

    /////////////////////////////////////
    // KeySwitchHybrid KeySwitch
    /////////////////////////////////////

    // Params for Auxiliary CRT basis {P} = {p_1,...,p_k}
    // used in GHS key switching
    std::shared_ptr<ILDCRTParams<BigInteger>> m_paramsP;

    // Stores the number of towers per Q_i
    uint32_t m_numPerPartQ = 0;

    // Stores the parameters for moduli Q_i
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> m_paramsPartQ;

    // Stores the parameters for complementary {\bar{Q_i},P}
    std::vector<std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>>> m_paramsComplPartQ;

    // Stores [{(Q_k)^(l)/q_i}^{-1}]_{q_i} for HYBRID
    std::vector<std::vector<std::vector<NativeInteger>>> m_PartQlHatInvModq;

    // Stores NTL precomputations for
    // [{(Q_k)^(l)/q_i}^{-1}]_{q_i} for HYBRID
    std::vector<std::vector<std::vector<NativeInteger>>> m_PartQlHatInvModqPrecon;

    // Stores [QHat_i]_{p_j}
    std::vector<std::vector<std::vector<std::vector<NativeInteger>>>> m_PartQlHatModp;

    // Stores the Barrett mu for CompQBar_i
    std::vector<std::vector<std::vector<DoubleNativeInt>>> m_modComplPartqBarrettMu;

    // Stores [P^{-1}]_{q_i}, required for GHS key switching
    std::vector<NativeInteger> m_PInvModq;

    // Stores NTL precomputations for [P^{-1}]_{q_i}
    std::vector<NativeInteger> m_PInvModqPrecon;

    // Stores [(P/p_j)^{-1}]_{p_j}, required for GHS key switching
    std::vector<NativeInteger> m_PHatInvModp;

    // Stores NTL precomputations for [(P/p_j)^{-1}]_{p_j}
    std::vector<NativeInteger> m_PHatInvModpPrecon;

    // Stores [P/p_j]_{q_i}, required for GHS key switching
    std::vector<std::vector<NativeInteger>> m_PHatModq;

    // Stores the BarrettUint128ModUint64 precomputations for q_j
    std::vector<DoubleNativeInt> m_modqBarrettMu;

    // Stores [t^{-1}]_{p_j}
    std::vector<NativeInteger> m_tInvModp;

    // Stores NTL precomputations for [t^{-1}]_{p_j}
    std::vector<NativeInteger> m_tInvModpPrecon;

    /////////////////////////////////////
    // CKKS Scaling Factor
    /////////////////////////////////////

    // A vector holding the doubles that correspond to the exact
    // scaling factor of each level, when FLEXIBLEAUTO is used.
    std::vector<double> m_scalingFactorsReal;

    std::vector<double> m_scalingFactorsRealBig;

    // Stores q_i as doubles
    std::vector<double> m_dmoduliQ;

    // Stores 2^ptm where ptm - plaintext modulus
    double m_approxSF = 0;

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    std::vector<NativeInteger> m_scalingFactorsInt;

    std::vector<NativeInteger> m_scalingFactorsIntBig;

    std::vector<NativeInteger> m_qModt;

    NativeInteger m_fixedSF = NativeInteger(1);

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    std::vector<NativeInteger> m_negQModt;
    std::vector<NativeInteger> m_negQModtPrecon;
    std::vector<NativeInteger> m_tInvModq;
    std::vector<NativeInteger> m_tInvModqPrecon;
    std::vector<NativeInteger> m_tInvModqr;

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    std::shared_ptr<ILDCRTParams<BigInteger>> m_paramsQr;
    NativeInteger m_negQrModt;
    NativeInteger m_negQrModtPrecon;
    std::vector<NativeInteger> m_rInvModq;

    /////////////////////////////////////
    // BFVrns : Decrypt : ScaleAndRound
    /////////////////////////////////////

    // Stores \frac{t*{Q/q_i}^{-1}/q_i}
    std::vector<double> m_tQHatInvModqDivqFrac;

    // when log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
    // Stores \frac{t*{Q/q_i}^{-1}*B/q_i}
    std::vector<double> m_tQHatInvModqBDivqFrac;

    // Stores [\floor{t*{Q/q_i}^{-1}/q_i}]_t
    std::vector<NativeInteger> m_tQHatInvModqDivqModt;

    // Stores NTL precomputations for [\floor{t*{Q/q_i}^{-1}/q_i}]_t
    std::vector<NativeInteger> m_tQHatInvModqDivqModtPrecon;

    // when log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
    // Stores [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
    std::vector<NativeInteger> m_tQHatInvModqBDivqModt;

    // when log2 q_i >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
    // Stores NTL precomputations for [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
    std::vector<NativeInteger> m_tQHatInvModqBDivqModtPrecon;

    /////////////////////////////////////
    // BFVrns : Mult : ExpandCRTBasis
    /////////////////////////////////////

    // Auxiliary CRT basis {Ql} = {q_i}
    // used in homomorphic multiplication
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> m_paramsQl;

    std::vector<std::vector<double>> m_QlQHatInvModqDivqFrac;
    std::vector<std::vector<std::vector<NativeInteger>>> m_QlQHatInvModqDivqModq;

    // Auxiliary CRT basis {Rl} = {r_k}
    // used in homomorphic multiplication
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> m_paramsRl;

    // Auxiliary expanded CRT basis Ql*Rl = {s_m}
    // used in homomorphic multiplication
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> m_paramsQlRl;

    // Stores [(Ql/q_i)^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> m_QlHatInvModq;

    // Stores NTL precomputations for [(Ql/q_i)^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> m_QlHatInvModqPrecon;

    // Stores [Q/q_i]_{r_k}
    std::vector<std::vector<std::vector<NativeInteger>>> m_QlHatModr;

    // Stores [\alpha*Ql]_{r_k} for 0 <= alpha <= sizeQl
    std::vector<std::vector<std::vector<NativeInteger>>> m_alphaQlModr;

    // Barrett modulo reduction precomputation for r_k
    std::vector<DoubleNativeInt> m_modrBarrettMu;

    // Stores \frac{1/q_i}
    std::vector<double> m_qInv;

    /////////////////////////////////////
    // BFVrns : Mult : ScaleAndRound
    /////////////////////////////////////

    // S = QR
    // Stores \frac{[t*R*(S/s_m)^{-1}]_{s_m}/s_m}
    std::vector<double> m_tRSHatInvModsDivsFrac;

    // S = QR
    // Stores [\floor{t*R*(S/s_m)^{-1}/s_m}]_{r_k}
    std::vector<std::vector<NativeInteger>> m_tRSHatInvModsDivsModr;

    /////////////////////////////////////
    // BFVrns : Mult : SwitchCRTBasis
    /////////////////////////////////////

    // Stores [(Rl/r_k)^{-1}]_{r_k}
    std::vector<std::vector<NativeInteger>> m_RlHatInvModr;

    // Stores NTL precomputations for [(Rl/r_k)^{-1}]_{r_k}
    std::vector<std::vector<NativeInteger>> m_RlHatInvModrPrecon;

    // Stores [Rl/r_k]_{q_i}
    std::vector<std::vector<std::vector<NativeInteger>>> m_RlHatModq;

    // Stores [\alpha*Rl]_{q_i} for 0 <= alpha <= sizeR
    std::vector<std::vector<std::vector<NativeInteger>>> m_alphaRlModq;

    // Stores \frac{1/r_k}
    std::vector<double> m_rInv;

    /////////////////////////////////////
    // BFVrns : Mult : FastExpandCRTBasisPloverQ
    /////////////////////////////////////

    std::vector<std::vector<NativeInteger>> m_negRlQHatInvModq;

    std::vector<std::vector<NativeInteger>> m_negRlQHatInvModqPrecon;

    std::vector<std::vector<NativeInteger>> m_negRlQlHatInvModq;

    std::vector<std::vector<NativeInteger>> m_negRlQlHatInvModqPrecon;

    std::vector<std::vector<NativeInteger>> m_qInvModr;

    /////////////////////////////////////
    // BFVrns : Mult : ExpandCRTBasisQlHat
    /////////////////////////////////////

    std::vector<std::vector<NativeInteger>> m_QlHatModq;

    std::vector<std::vector<NativeInteger>> m_QlHatModqPrecon;

    /////////////////////////////////////
    // BFVrns : Mult : ScaleAndRoundP
    /////////////////////////////////////

    std::vector<std::vector<double>> m_tQlSlHatInvModsDivsFrac;

    std::vector<std::vector<std::vector<NativeInteger>>> m_tQlSlHatInvModsDivsModq;

    /////////////////////////////////////
    // BFVrnsB
    /////////////////////////////////////

    // Auxiliary CRT basis {Bsk} = {B U msk} = {{b_j} U msk}
    std::shared_ptr<ILDCRTParams<BigInteger>> m_paramsQBsk;

    // number of moduli in the base {Q}
    uint32_t m_numq = 0;

    // number of moduli in the auxilliary base {B}
    uint32_t m_numb = 0;

    // mtilde = 2^16
    NativeInteger m_mtilde = NativeInteger(BasicInteger(1) << 16);

    // Auxiliary modulus msk
    NativeInteger m_msk;

    // Stores q_i
    std::vector<NativeInteger> m_moduliQ;

    // Stores auxilliary base moduli b_j
    std::vector<NativeInteger> m_moduliB;

    // Stores the roots of unity modulo bsk_j
    std::vector<NativeInteger> m_rootsBsk;

    // Stores moduli {bsk_i} = {{b_j} U msk}
    std::vector<NativeInteger> m_moduliBsk;

    // Barrett modulo reduction precomputation for bsk_j
    std::vector<DoubleNativeInt> m_modbskBarrettMu;

    // Stores [mtilde*(Q/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> m_mtildeQHatInvModq;

    // Stores NTL precomputations for [mtilde*(Q/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> m_mtildeQHatInvModqPrecon;

    // Stores [Q/q_i]_{bsk_j}
    std::vector<std::vector<NativeInteger>> m_QHatModbsk;

    // Stores [(q_i)^{-1}]_{bsk_j}
    std::vector<std::vector<NativeInteger>> m_qInvModbsk;

    // Stores [Q/q_i]_{mtilde}
    std::vector<uint64_t> m_QHatModmtilde;

    // Stores [Q]_{bsk_j}
    std::vector<NativeInteger> m_QModbsk;
    // Stores NTL precomputations for [Q]_{bsk_j}
    std::vector<NativeInteger> m_QModbskPrecon;

    // Stores [-Q^{-1}]_{mtilde}
    uint64_t m_negQInvModmtilde = 0;

    // Stores [mtilde^{-1}]_{bsk_j}
    std::vector<NativeInteger> m_mtildeInvModbsk;
    // Stores NTL precomputations for [mtilde^{-1}]_{bsk_j}
    std::vector<NativeInteger> m_mtildeInvModbskPrecon;

    // Stores [t*(Q/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> m_tQHatInvModq;

    // Stores NTL precomputations for [t*(Q/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> m_tQHatInvModqPrecon;

    // Stores [t*gamma*(Q/q_i)^(-1)]_{q_i}
    std::vector<NativeInteger> m_tgammaQHatInvModq;
    // Stores NTL precomputations for [t*gamma*(Q/q_i)^(-1)]_{q_i}
    std::vector<NativeInteger> m_tgammaQHatInvModqPrecon;

    // Stores [t/Q]_{bsk_j}
    std::vector<NativeInteger> m_tQInvModbsk;
    // Stores NTL precomputations for [t/Q]_{bsk_j}
    std::vector<NativeInteger> m_tQInvModbskPrecon;

    // Stores [(B/b_j)^{-1}]_{b_j}
    std::vector<NativeInteger> m_BHatInvModb;

    // Stores NTL precomputations for [(B/b_j)^{-1}]_{b_j}
    std::vector<NativeInteger> m_BHatInvModbPrecon;

    // stores [B/b_j]_{msk}
    std::vector<NativeInteger> m_BHatModmsk;

    // Stores [B^{-1}]_msk
    NativeInteger m_BInvModmsk;
    // Stores NTL precomputations for [B^{-1}]_msk
    NativeInteger m_BInvModmskPrecon;

    // Stores [B/b_j]_{q_i}
    std::vector<std::vector<NativeInteger>> m_BHatModq;

    // Stores [B]_{q_i}
    std::vector<NativeInteger> m_BModq;
    // Stores NTL precomputations for [B]_{q_i}
    std::vector<NativeInteger> m_BModqPrecon;

    // Stores gamma = 2^26;
    uint32_t m_gamma = 1 << 26;

    // TODO: use 64 bit words in case NativeInteger uses smaller word size
    // Stores t*gamma on a uint64_t word
    NativeInteger m_tgamma;

    // Stores [-(q_i)^{-1}]_{t*gamma}
    std::vector<NativeInteger> m_negInvqModtgamma;
    // Stores NTL precomputations for [-(q_i)^{-1}]_{t*gamma}
    std::vector<NativeInteger> m_negInvqModtgammaPrecon;

    /////////////////////////////////////
    // BFVrns and BGVrns : Multiparty Decryption : ExpandCRTBasis
    /////////////////////////////////////

    // Stores [*(Q/q_i/q_0)^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> m_multipartyQHatInvModq;

    // Stores NTL precomputations for [*(Q/q_i/q_0)^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> m_multipartyQHatInvModqPrecon;

    // Stores [Q/q_i/q_0]_{q_0}
    std::vector<std::vector<std::vector<NativeInteger>>> m_multipartyQHatModq0;

    // Stores [\alpha*Q/q_0]_{q_0} for 0 <= alpha <= 1
    std::vector<std::vector<std::vector<NativeInteger>>> m_multipartyAlphaQModq0;

    // Barrett modulo reduction precomputation for q_0
    std::vector<DoubleNativeInt> m_multipartyModq0BarrettMu;

    // Stores \frac{1/q_i}
    std::vector<double> m_multipartyQInv;

    /////////////////////////////////////
    // CKKS RNS MultiParty Bootstrapping Parameter
    /////////////////////////////////////
    COMPRESSION_LEVEL m_MPIntBootCiphertextCompressionLevel;

public:
    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<CryptoParametersRLWE<DCRTPoly>>(this));
        ar(cereal::make_nvp("ks", m_ksTechnique));
        ar(cereal::make_nvp("rs", m_scalTechnique));
        ar(cereal::make_nvp("encs", m_encTechnique));
        ar(cereal::make_nvp("muls", m_multTechnique));
        ar(cereal::make_nvp("dnum", m_numPartQ));
        ar(cereal::make_nvp("ab", m_auxBits));
        ar(cereal::make_nvp("eb", m_extraBits));
        ar(cereal::make_nvp("ccl", m_MPIntBootCiphertextCompressionLevel));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            std::string errMsg("serialized object version " + std::to_string(version) +
                               " is from a later version of the library");
            OPENFHE_THROW(errMsg);
        }
        ar(cereal::base_class<CryptoParametersRLWE<DCRTPoly>>(this));
        ar(cereal::make_nvp("ks", m_ksTechnique));
        ar(cereal::make_nvp("rs", m_scalTechnique));
        ar(cereal::make_nvp("encs", m_encTechnique));
        ar(cereal::make_nvp("muls", m_multTechnique));
        ar(cereal::make_nvp("dnum", m_numPartQ));
        ar(cereal::make_nvp("ab", m_auxBits));
        ar(cereal::make_nvp("eb", m_extraBits));
        // try-catch is used for backwards compatibility down to 1.0.x
        // m_MPIntBootCiphertextCompressionLevel was added in v1.1.0
        try {
            ar(cereal::make_nvp("ccl", m_MPIntBootCiphertextCompressionLevel));
        }
        catch (cereal::Exception&) {
            m_MPIntBootCiphertextCompressionLevel = COMPRESSION_LEVEL::SLACK;
        }
    }

    std::string SerializedObjectName() const override {
        return "SchemeParametersRNS";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }
};

}  // namespace lbcrypto

#endif
