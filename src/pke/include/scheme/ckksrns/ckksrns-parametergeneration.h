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

#ifndef SRC_PKE_INCLUDE_SCHEME_CKKSRNS_CKKSRNS_PARAMETERGENERATION_H_
#define SRC_PKE_INCLUDE_SCHEME_CKKSRNS_CKKSRNS_PARAMETERGENERATION_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "schemerns/rns-parametergeneration.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Parameter generation for the CKKS scheme in RNS form: generates the modulus chain (one prime per level,
 * or compositeDegree primes per level for the COMPOSITESCALING* techniques), the auxiliary moduli of key
 * switching and the CRT tables, and validates the ring dimension against the security level.
 */
class ParameterGenerationCKKSRNS : public ParameterGenerationRNS {
  protected:
    /**
     * Generates the modulus chain for composite scaling: each level consists of compositeDegree primes of at most
     * registerWordSize bits whose product approximates 2^dcrtBits (the scaling factor), and the first level of
     * primes whose product approximates 2^firstModSize; all primes are distinct and congruent to 1 modulo the
     * cyclotomic order. Requires firstModSize > dcrtBits.
     *
     * @param moduliQ output: the moduli of the chain (size numPrimes)
     * @param rootsQ output: the corresponding roots of unity
     * @param compositeDegree number of primes per level
     * @param numPrimes total number of primes in the chain
     * @param firstModSize size in bits of the modulus of the first level
     * @param dcrtBits size in bits of the scaling factor (the modulus of each further level)
     * @param cyclOrder cyclotomic order
     * @param registerWordSize maximum size in bits of each prime
     */
    void CompositePrimeModuliGen(std::vector<NativeInteger>& moduliQ, std::vector<NativeInteger>& rootsQ,
                                 uint32_t compositeDegree, uint32_t numPrimes, uint32_t firstModSize, uint32_t dcrtBits,
                                 uint32_t cyclOrder, uint32_t registerWordSize) const;

    /**
     * Generates the modulus chain with one prime per level: primes of dcrtBits bits alternating around 2^dcrtBits
     * (or, for FLEXIBLEAUTO and FLEXIBLEAUTOEXT, chosen so that the level-specific scaling factors stay close to
     * 2^dcrtBits), a first prime of firstModSize bits and, for FLEXIBLEAUTOEXT, an extra prime of extraModsize
     * bits at the top of the chain.
     *
     * @param moduliQ output: the moduli of the chain (size numPrimes)
     * @param rootsQ output: the corresponding roots of unity
     * @param scalTech scaling technique
     * @param numPrimes total number of primes in the chain
     * @param firstModSize size in bits of the first modulus
     * @param dcrtBits size in bits of the scaling factor (the modulus of each further level)
     * @param cyclOrder cyclotomic order
     * @param extraModsize size in bits of the extra modulus of FLEXIBLEAUTOEXT
     */
    void SinglePrimeModuliGen(std::vector<NativeInteger>& moduliQ, std::vector<NativeInteger>& rootsQ,
                              ScalingTechnique scalTech, uint32_t numPrimes, uint32_t firstModSize, uint32_t dcrtBits,
                              uint32_t cyclOrder, uint32_t extraModsize) const;

  public:
    virtual ~ParameterGenerationCKKSRNS() = default;

    /**
     * Generates the CKKS parameters: the modulus chain (see SinglePrimeModuliGen and CompositePrimeModuliGen), the
     * auxiliary moduli of HYBRID key switching, the CRT tables (CryptoParametersCKKSRNS::PrecomputeCRTTables) and
     * the ring dimension, which is chosen from the security level when not set and validated otherwise.
     *
     * @param cryptoParams the crypto parameters to complete
     * @param cyclOrder cyclotomic order (twice the ring dimension; 0 = chosen from the security level)
     * @param numPrimes number of levels in the modulus chain (multiplicative depth + 1)
     * @param scalingModSize size in bits of the scaling factor
     * @param firstModSize size in bits of the first modulus
     * @param mulPartQ number of digits (partitions of Q) for HYBRID key switching
     * @param mPIntBootCiphertextCompressionLevel compression level of interactive multiparty bootstrapping
     * @return true on success
     */
    bool ParamsGenCKKSRNSInternal(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, uint32_t cyclOrder,
                                  uint32_t numPrimes, uint32_t scalingModSize, uint32_t firstModSize, uint32_t mulPartQ,
                                  CompressionLevel mPIntBootCiphertextCompressionLevel) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string SerializedObjectName() const {
        return "ParameterGenerationCKKSRNS";
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_CKKSRNS_CKKSRNS_PARAMETERGENERATION_H_
