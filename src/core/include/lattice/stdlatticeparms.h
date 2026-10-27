//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  Header for the standard values for Lattice Parms, as determined by homomorphicencryption.org, by the
  Security Guidelines for Implementing Homomorphic Encryption (IACR Communications in Cryptology 1(4), 2025,
  https://cic.iacr.org/p/1/4/26; also ePrint 2024/463, https://eprint.iacr.org/2024/463), and by the
  Sparse LWE Kit (https://github.com/HomomorphicEncryption/SparseLWEkit)
 */

#ifndef SRC_CORE_INCLUDE_LATTICE_STDLATTICEPARMS_H_
#define SRC_CORE_INCLUDE_LATTICE_STDLATTICEPARMS_H_

//  #include "math/math-hal.h"

#include <cstdint>
#include <iosfwd>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "lattice/constants-lattice.h"
#include "utils/inttypes.h"

namespace lbcrypto {

// This is the representation of the standard lattice parameters defined in the Homomorphic Encryption Standard
// (http://homomorphicencryption.org, HEStd_* security levels), in the Security Guidelines for Implementing
// Homomorphic Encryption (IACR Communications in Cryptology 1(4), 2025, https://cic.iacr.org/p/1/4/26; also ePrint
// 2024/463; HEORG24_* security levels), and in the Sparse LWE Kit
// (https://github.com/HomomorphicEncryption/SparseLWEkit, HE_SPARSE_* security levels).

// Given a distribution type and a security level, you can get the maxQ for a given ring dimension, and you can
// get the ring dimension given a maxQ.

// The lookup tables in StdLatticeParm are indexed by the enumerator values of DistributionType and SecurityLevel,
// so the enumerators must stay consecutive from 0; new enumerators must be appended at the end (the values are
// also stored in serialized cryptocontexts).

/**
 * @brief Secret key distribution used to select a table of security parameters.
 * The enumerators must stay consecutive from 0 because they index the lookup tables in StdLatticeParm.
 */
enum DistributionType {
    HEStd_uniform,  ///< uniform secret (Homomorphic Encryption Standard only)
    HEStd_error,    ///< Gaussian secret with standard deviation 3.19 (error distribution)
    HEStd_ternary,  ///< uniform ternary secret
    HEStd_sparse,   ///< sparse ternary secret of fixed Hamming weight (HE_SPARSE_* security levels only)
};

/**
 * @brief Security level, i.e., the table of security parameters used to select or validate the ring dimension
 * for the ciphertext modulus.
 *
 * HEStd_* levels are the tables of the Homomorphic Encryption Standard v1.1 (2018), extended to ring dimensions 2^16
 * and 2^17 with the values of the Security Guidelines for Implementing Homomorphic Encryption; they are kept for
 * backward compatibility.
 *
 * HEORG24_* levels are Table 5.2 of the Security Guidelines for Implementing Homomorphic Encryption (Bossuat et
 * al., IACR Communications in Cryptology 1(4), 2025, https://cic.iacr.org/p/1/4/26; also ePrint 2024/463),
 * estimated with the Lattice Estimator and the MATZOV cost model for uniform ternary (HEStd_ternary) and Gaussian
 * (HEStd_error) secrets. They provide 128-, 192-, and 256-bit security against both classical and quantum
 * attacks (there are no separate classical and quantum tables). They are recommended over the HEStd_* levels for
 * new applications, as they reflect more recent cryptanalysis (the bounds on the ciphertext modulus are up to a
 * few bits smaller).
 *
 * HE_SPARSE_H192_128 is the 128-bit classical security table for sparse ternary secrets of Hamming weight 192
 * (the Hamming weight of SPARSE_TERNARY and SPARSE_ENCAPSULATED secret keys in OpenFHE) and ring dimensions 2^15,
 * 2^16, and 2^17, intended for CKKS bootstrapping with sparse secrets. The rows are the OpenFHE parameter sets of
 * the Sparse LWE Kit of HomomorphicEncryption.org (https://github.com/HomomorphicEncryption/SparseLWEkit), whose
 * work factors (134.1, 134.0, and 135.7 bits for 2^15, 2^16, and 2^17, respectively) were obtained with the Lattice
 * Estimator using the BDGL16 reduction cost model (best attack: bdd_mitm_hybrid). It uses the HEStd_sparse
 * distribution type and is the recommended security level for sparse secrets.
 *
 * HEStd_NotSet disables the security-based parameter checks. The enumerators must stay consecutive from 0 because
 * they index the lookup tables in StdLatticeParm; new enumerators must be appended at the end because the values
 * are stored in serialized cryptocontexts.
 */
enum SecurityLevel {
    HEStd_128_classic,
    HEStd_192_classic,
    HEStd_256_classic,
    HEStd_128_quantum,
    HEStd_192_quantum,
    HEStd_256_quantum,
    HEStd_NotSet,
    HEORG24_128,         ///< 128-bit classical/quantum security (Security Guidelines 2024, Table 5.2)
    HEORG24_192,         ///< 192-bit classical/quantum security (Security Guidelines 2024, Table 5.2)
    HEORG24_256,         ///< 256-bit classical/quantum security (Security Guidelines 2024, Table 5.2)
    HE_SPARSE_H192_128,  ///< 128-bit classical security for sparse ternary secrets of Hamming weight 192
};

/**
 * @brief Converts the name of a security level (e.g., "HEStd_128_classic") to the enumerator; throws for an
 * unknown name.
 * @param str name of the security level, spelled as the enumerator
 * @return the security level
 */
SecurityLevel convertToSecurityLevel(const std::string& str);
/**
 * @brief Converts an integer to a security level; throws for values that do not correspond to one of the
 * standard levels (HEStd_NotSet is not accepted).
 * @param num integer value of the enumerator
 * @return the security level
 */
SecurityLevel convertToSecurityLevel(uint32_t num);
/**
 * @brief Prints the name of a security level.
 * @param s output stream
 * @param sl security level to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, SecurityLevel sl);

/**
 * @brief One row of the security parameter tables: for a secret key distribution, a ring dimension, and a security
 * level, the largest supported bit size of the ciphertext modulus.
 * The rows are stored in a static table and indexed by (distribution, security level), then by ring dimension
 * (FindMaxQ) or by modulus bit size (FindRingDim).
 */
class StdLatticeParm {
    DistributionType distType;
    uint32_t ringDim;
    SecurityLevel minSecLev;
    uint32_t maxLogQ;

    // The lookup tables are indexed by the enumerator values of DistributionType and SecurityLevel, which must
    // be consecutive numbers starting from 0. The sizes below are derived from the last enumerator of each enum,
    // so they must be updated when an enumerator is appended.
    static constexpr size_t NUM_DIST_TYPES = static_cast<size_t>(HEStd_sparse) + 1;
    static constexpr size_t NUM_SEC_LEVELS = static_cast<size_t>(HE_SPARSE_H192_128) + 1;
    static std::map<uint32_t, StdLatticeParm*> byRing[NUM_DIST_TYPES][NUM_SEC_LEVELS];
    static std::map<uint32_t, StdLatticeParm*> byLogQ[NUM_DIST_TYPES][NUM_SEC_LEVELS];

    static std::vector<StdLatticeParm> StandardLatticeParmSets;
    static bool initialized;

  public:
    /**
     * @brief Constructs one table row.
     * @param distType secret key distribution
     * @param ringDim ring dimension
     * @param minSecLev security level the row is certified for
     * @param maxLogQ largest supported bit size of the ciphertext modulus
     */
    StdLatticeParm(DistributionType distType, uint32_t ringDim, SecurityLevel minSecLev, uint32_t maxLogQ)
        : distType(distType), ringDim(ringDim), minSecLev(minSecLev), maxLogQ(maxLogQ) {}

    /**
     * @brief Builds the lookup maps (by ring dimension and by modulus bit size) from the static table of rows.
     * Called on first use by FindMaxQ and FindRingDim.
     */
    static void initializeLookups() {
        for (size_t i = 0; i < StandardLatticeParmSets.size(); i++) {
            StdLatticeParm& s = StandardLatticeParmSets[i];
            byRing[static_cast<int>(s.distType)][static_cast<int>(s.minSecLev)][s.ringDim] = &s;
            byLogQ[static_cast<int>(s.distType)][static_cast<int>(s.minSecLev)][s.maxLogQ] = &s;
        }
        initialized = true;
    }

    /**
     * @brief Looks up the largest supported ciphertext modulus bit size for a ring dimension.
     * @param distType secret key distribution
     * @param minSecLev required security level
     * @param ringDim ring dimension
     * @return the maximum log2 of the ciphertext modulus, or 0 if the table has no row for this ring dimension
     */
    static uint32_t FindMaxQ(DistributionType distType, SecurityLevel minSecLev, uint32_t ringDim) {
        int distTypeIdx = static_cast<int>(distType);
        int minSecLevIdx = static_cast<int>(minSecLev);
        if (!initialized)
            initializeLookups();
        auto it = byRing[distTypeIdx][minSecLevIdx].find(ringDim);
        if (it == byRing[distTypeIdx][minSecLevIdx].end())
            return 0;
        return it->second->getMaxLogQ();
    }

    /**
     * @brief Finds the smallest tabulated ring dimension whose maximum modulus bit size is at least curLogQ.
     * Throws if there is no table for the combination of distribution and security level (e.g., HEStd_sparse
     * with an HEStd_* or HEORG24_* level, or HE_SPARSE_H192_128 with a non-sparse distribution).
     * @param distType secret key distribution
     * @param minSecLev required security level
     * @param curLogQ log2 of the ciphertext modulus
     * @return the ring dimension (the smallest tabulated ring dimension if curLogQ is below every table row),
     * or twice the largest tabulated ring dimension if curLogQ exceeds every table row
     */
    static uint32_t FindRingDim(DistributionType distType, SecurityLevel minSecLev, uint32_t curLogQ);

    /**
     * @brief Selects the secret key distribution column of the security tables for a secret key distribution and
     * a security level, and checks that the tables have rows for this combination.
     *
     * HE_SPARSE_H192_128 requires a sparse secret of Hamming weight 192 (SPARSE_TERNARY or SPARSE_ENCAPSULATED) and
     * maps to HEStd_sparse. All other security levels map GAUSSIAN to HEStd_error and every other secret key
     * distribution to HEStd_ternary; for sparse secrets, this treats the secret as uniform ternary, which
     * overestimates the security, so HE_SPARSE_H192_128 is recommended for sparse secrets instead.
     * HEStd_NotSet is accepted with any secret key distribution (no tables are used in this case).
     * @param secretKeyDist secret key distribution
     * @param minSecLev required security level
     * @return the distribution type indexing the security tables
     */
    static DistributionType GetDistributionType(SecretKeyDist secretKeyDist, SecurityLevel minSecLev);

    DistributionType getDistType() const {
        return distType;
    }
    uint32_t getRingDim() const {
        return ringDim;
    }
    SecurityLevel getMinSecLev() const {
        return minSecLev;
    }
    uint32_t getMaxLogQ() const {
        return maxLogQ;
    }
};

} /* namespace lbcrypto */

#endif  // SRC_CORE_INCLUDE_LATTICE_STDLATTICEPARMS_H_
