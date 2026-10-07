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
  Header for the standard values for Lattice Parms, as determined by homomorphicencryption.org
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

#include "utils/inttypes.h"

namespace lbcrypto {

// this is the representation of the standard lattice parameters defined in the
// Homomorphic Encryption Standard, as defined by
// http://homomorphicencryption.org

// given a distribution type and a security level, you can get the maxQ for a
// given ring dimension, and you can get the ring dimension given a maxQ

// The code below is very specific to the layout of the DistributionType and
// SecurityLevel enums IF you change them, go look at and change byRing and
// byLogQ

/**
 * @brief Secret key distribution used to select a table of the Homomorphic Encryption Standard.
 * The enumerators must stay consecutive from 0 because they index the lookup tables in StdLatticeParm.
 */
enum DistributionType {
    HEStd_uniform,
    HEStd_error,
    HEStd_ternary,
};

/**
 * @brief Security level of the Homomorphic Encryption Standard (bits of security, classical or quantum attacks).
 * HEStd_NotSet disables the standard-based parameter checks. The enumerators must stay consecutive from 0 because
 * they index the lookup tables in StdLatticeParm.
 */
enum SecurityLevel {
    HEStd_128_classic,
    HEStd_192_classic,
    HEStd_256_classic,
    HEStd_128_quantum,
    HEStd_192_quantum,
    HEStd_256_quantum,
    HEStd_NotSet,
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
 * @brief One row of the Homomorphic Encryption Standard parameter tables: for a secret key distribution,
 * a ring dimension, and a security level, the largest supported bit size of the ciphertext modulus.
 * The rows are stored in a static table and indexed by (distribution, security level), then by ring dimension
 * (FindMaxQ) or by modulus bit size (FindRingDim).
 */
class StdLatticeParm {
    DistributionType distType;
    uint32_t ringDim;
    SecurityLevel minSecLev;
    uint32_t maxLogQ;

    // NOTE!!! the declaration below relies upon there being three possible values
    // for the first index (the distribution type), and six possible values for
    // the second index (the security level)
    // The values in the enums, above, meet this criteria
    // it's also important that the different values are numbered from 0-2
    // again, the enums above do this
    // DO NOT change the values of the enums to be anything other than consecutive
    // numbers starting from 0, or this code will break in strange ways, and you
    // will suffer MAKE SURE that the number of entries in the DistributionType
    // enum is == the first index, and MAKE SURE that the number of entries in the
    // SecurityLevel enum is == the second index
    inline static std::map<uint32_t, StdLatticeParm*> byRing[3][6];
    inline static std::map<uint32_t, StdLatticeParm*> byLogQ[3][6];

    static std::vector<StdLatticeParm> MakeStandardLatticeParmSets();
    inline static std::vector<StdLatticeParm> StandardLatticeParmSets = MakeStandardLatticeParmSets();
    inline static bool initialized = false;

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
     * @param distType secret key distribution
     * @param minSecLev required security level
     * @param curLogQ log2 of the ciphertext modulus
     * @return the ring dimension, or twice the largest tabulated ring dimension if curLogQ exceeds every table row
     */
    static uint32_t FindRingDim(DistributionType distType, SecurityLevel minSecLev, uint32_t curLogQ) {
        if (!initialized)
            initializeLookups();
        uint32_t prev = 0;

        int distTypeIdx = static_cast<int>(distType);
        int minSecLevIdx = static_cast<int>(minSecLev);
        uint32_t n = 0;
        for (std::pair<const unsigned int, StdLatticeParm*>& it : byLogQ[distTypeIdx][minSecLevIdx]) {
            if ((curLogQ <= it.second->getMaxLogQ()) && (curLogQ > prev))
                return it.second->getRingDim();
            prev = it.second->getMaxLogQ();
            n = it.second->getRingDim();
        }
        return 2 * n;
    }

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

// This is a collection of all of the parameter sets. It is initialized after
// StdLatticeParm is complete so the inline static vector can contain its class type.
inline std::vector<StdLatticeParm> StdLatticeParm::MakeStandardLatticeParmSets() {
    return {
            StdLatticeParm(HEStd_uniform, 1024, HEStd_128_classic, 29),
            StdLatticeParm(HEStd_uniform, 1024, HEStd_192_classic, 21),
            StdLatticeParm(HEStd_uniform, 1024, HEStd_256_classic, 16),
            StdLatticeParm(HEStd_uniform, 2048, HEStd_128_classic, 56),
            StdLatticeParm(HEStd_uniform, 2048, HEStd_192_classic, 39),
            StdLatticeParm(HEStd_uniform, 2048, HEStd_256_classic, 31),
            StdLatticeParm(HEStd_uniform, 4096, HEStd_128_classic, 111),
            StdLatticeParm(HEStd_uniform, 4096, HEStd_192_classic, 77),
            StdLatticeParm(HEStd_uniform, 4096, HEStd_256_classic, 60),
            StdLatticeParm(HEStd_uniform, 8192, HEStd_128_classic, 220),
            StdLatticeParm(HEStd_uniform, 8192, HEStd_192_classic, 154),
            StdLatticeParm(HEStd_uniform, 8192, HEStd_256_classic, 120),
            StdLatticeParm(HEStd_uniform, 16384, HEStd_128_classic, 440),
            StdLatticeParm(HEStd_uniform, 16384, HEStd_192_classic, 307),
            StdLatticeParm(HEStd_uniform, 16384, HEStd_256_classic, 239),
            StdLatticeParm(HEStd_uniform, 32768, HEStd_128_classic, 880),
            StdLatticeParm(HEStd_uniform, 32768, HEStd_192_classic, 612),
            StdLatticeParm(HEStd_uniform, 32768, HEStd_256_classic, 478),

            StdLatticeParm(HEStd_error, 1024, HEStd_128_classic, 29),
            StdLatticeParm(HEStd_error, 1024, HEStd_192_classic, 21),
            StdLatticeParm(HEStd_error, 1024, HEStd_256_classic, 16),
            StdLatticeParm(HEStd_error, 2048, HEStd_128_classic, 56),
            StdLatticeParm(HEStd_error, 2048, HEStd_192_classic, 39),
            StdLatticeParm(HEStd_error, 2048, HEStd_256_classic, 31),
            StdLatticeParm(HEStd_error, 4096, HEStd_128_classic, 111),
            StdLatticeParm(HEStd_error, 4096, HEStd_192_classic, 77),
            StdLatticeParm(HEStd_error, 4096, HEStd_256_classic, 60),
            StdLatticeParm(HEStd_error, 8192, HEStd_128_classic, 220),
            StdLatticeParm(HEStd_error, 8192, HEStd_192_classic, 154),
            StdLatticeParm(HEStd_error, 8192, HEStd_256_classic, 120),
            StdLatticeParm(HEStd_error, 16384, HEStd_128_classic, 440),
            StdLatticeParm(HEStd_error, 16384, HEStd_192_classic, 307),
            StdLatticeParm(HEStd_error, 16384, HEStd_256_classic, 239),
            StdLatticeParm(HEStd_error, 32768, HEStd_128_classic, 883),
            StdLatticeParm(HEStd_error, 32768, HEStd_192_classic, 613),
            StdLatticeParm(HEStd_error, 32768, HEStd_256_classic, 478),
            StdLatticeParm(HEStd_error, 65536, HEStd_128_classic, 1749),
            StdLatticeParm(HEStd_error, 65536, HEStd_192_classic, 1201),
            StdLatticeParm(HEStd_error, 65536, HEStd_256_classic, 931),
            StdLatticeParm(HEStd_error, 131072, HEStd_128_classic, 3525),
            StdLatticeParm(HEStd_error, 131072, HEStd_192_classic, 2413),
            StdLatticeParm(HEStd_error, 131072, HEStd_256_classic, 1868),

            StdLatticeParm(HEStd_ternary, 1024, HEStd_128_classic, 27),
            StdLatticeParm(HEStd_ternary, 1024, HEStd_192_classic, 19),
            StdLatticeParm(HEStd_ternary, 1024, HEStd_256_classic, 14),
            StdLatticeParm(HEStd_ternary, 2048, HEStd_128_classic, 54),
            StdLatticeParm(HEStd_ternary, 2048, HEStd_192_classic, 37),
            StdLatticeParm(HEStd_ternary, 2048, HEStd_256_classic, 29),
            StdLatticeParm(HEStd_ternary, 4096, HEStd_128_classic, 109),
            StdLatticeParm(HEStd_ternary, 4096, HEStd_192_classic, 75),
            StdLatticeParm(HEStd_ternary, 4096, HEStd_256_classic, 58),
            StdLatticeParm(HEStd_ternary, 8192, HEStd_128_classic, 218),
            StdLatticeParm(HEStd_ternary, 8192, HEStd_192_classic, 152),
            StdLatticeParm(HEStd_ternary, 8192, HEStd_256_classic, 118),
            StdLatticeParm(HEStd_ternary, 16384, HEStd_128_classic, 438),
            StdLatticeParm(HEStd_ternary, 16384, HEStd_192_classic, 305),
            StdLatticeParm(HEStd_ternary, 16384, HEStd_256_classic, 237),
            StdLatticeParm(HEStd_ternary, 32768, HEStd_128_classic, 881),
            StdLatticeParm(HEStd_ternary, 32768, HEStd_192_classic, 611),
            StdLatticeParm(HEStd_ternary, 32768, HEStd_256_classic, 476),
            StdLatticeParm(HEStd_ternary, 65536, HEStd_128_classic, 1747),
            StdLatticeParm(HEStd_ternary, 65536, HEStd_192_classic, 1199),
            StdLatticeParm(HEStd_ternary, 65536, HEStd_256_classic, 929),
            StdLatticeParm(HEStd_ternary, 131072, HEStd_128_classic, 3523),
            StdLatticeParm(HEStd_ternary, 131072, HEStd_192_classic, 2411),
            StdLatticeParm(HEStd_ternary, 131072, HEStd_256_classic, 1866),

            StdLatticeParm(HEStd_uniform, 1024, HEStd_128_quantum, 27),
            StdLatticeParm(HEStd_uniform, 1024, HEStd_192_quantum, 19),
            StdLatticeParm(HEStd_uniform, 1024, HEStd_256_quantum, 15),
            StdLatticeParm(HEStd_uniform, 2048, HEStd_128_quantum, 53),
            StdLatticeParm(HEStd_uniform, 2048, HEStd_192_quantum, 37),
            StdLatticeParm(HEStd_uniform, 2048, HEStd_256_quantum, 29),
            StdLatticeParm(HEStd_uniform, 4096, HEStd_128_quantum, 103),
            StdLatticeParm(HEStd_uniform, 4096, HEStd_192_quantum, 72),
            StdLatticeParm(HEStd_uniform, 4096, HEStd_256_quantum, 56),
            StdLatticeParm(HEStd_uniform, 8192, HEStd_128_quantum, 206),
            StdLatticeParm(HEStd_uniform, 8192, HEStd_192_quantum, 143),
            StdLatticeParm(HEStd_uniform, 8192, HEStd_256_quantum, 111),
            StdLatticeParm(HEStd_uniform, 16384, HEStd_128_quantum, 413),
            StdLatticeParm(HEStd_uniform, 16384, HEStd_192_quantum, 286),
            StdLatticeParm(HEStd_uniform, 16384, HEStd_256_quantum, 222),
            StdLatticeParm(HEStd_uniform, 32768, HEStd_128_quantum, 829),
            StdLatticeParm(HEStd_uniform, 32768, HEStd_192_quantum, 573),
            StdLatticeParm(HEStd_uniform, 32768, HEStd_256_quantum, 445),

            StdLatticeParm(HEStd_error, 1024, HEStd_128_quantum, 27),
            StdLatticeParm(HEStd_error, 1024, HEStd_192_quantum, 19),
            StdLatticeParm(HEStd_error, 1024, HEStd_256_quantum, 15),
            StdLatticeParm(HEStd_error, 2048, HEStd_128_quantum, 53),
            StdLatticeParm(HEStd_error, 2048, HEStd_192_quantum, 37),
            StdLatticeParm(HEStd_error, 2048, HEStd_256_quantum, 29),
            StdLatticeParm(HEStd_error, 4096, HEStd_128_quantum, 103),
            StdLatticeParm(HEStd_error, 4096, HEStd_192_quantum, 72),
            StdLatticeParm(HEStd_error, 4096, HEStd_256_quantum, 56),
            StdLatticeParm(HEStd_error, 8192, HEStd_128_quantum, 206),
            StdLatticeParm(HEStd_error, 8192, HEStd_192_quantum, 143),
            StdLatticeParm(HEStd_error, 8192, HEStd_256_quantum, 111),
            StdLatticeParm(HEStd_error, 16384, HEStd_128_quantum, 413),
            StdLatticeParm(HEStd_error, 16384, HEStd_192_quantum, 286),
            StdLatticeParm(HEStd_error, 16384, HEStd_256_quantum, 222),
            StdLatticeParm(HEStd_error, 32768, HEStd_128_quantum, 829),
            StdLatticeParm(HEStd_error, 32768, HEStd_192_quantum, 573),
            StdLatticeParm(HEStd_error, 32768, HEStd_256_quantum, 445),
            StdLatticeParm(HEStd_error, 65536, HEStd_128_quantum, 1665),
            StdLatticeParm(HEStd_error, 65536, HEStd_192_quantum, 1147),
            StdLatticeParm(HEStd_error, 65536, HEStd_256_quantum, 890),
            StdLatticeParm(HEStd_error, 131072, HEStd_128_quantum, 3351),
            StdLatticeParm(HEStd_error, 131072, HEStd_192_quantum, 2304),
            StdLatticeParm(HEStd_error, 131072, HEStd_256_quantum, 1786),

            StdLatticeParm(HEStd_ternary, 1024, HEStd_128_quantum, 25),
            StdLatticeParm(HEStd_ternary, 1024, HEStd_192_quantum, 17),
            StdLatticeParm(HEStd_ternary, 1024, HEStd_256_quantum, 13),
            StdLatticeParm(HEStd_ternary, 2048, HEStd_128_quantum, 51),
            StdLatticeParm(HEStd_ternary, 2048, HEStd_192_quantum, 35),
            StdLatticeParm(HEStd_ternary, 2048, HEStd_256_quantum, 27),
            StdLatticeParm(HEStd_ternary, 4096, HEStd_128_quantum, 101),
            StdLatticeParm(HEStd_ternary, 4096, HEStd_192_quantum, 70),
            StdLatticeParm(HEStd_ternary, 4096, HEStd_256_quantum, 54),
            StdLatticeParm(HEStd_ternary, 8192, HEStd_128_quantum, 202),
            StdLatticeParm(HEStd_ternary, 8192, HEStd_192_quantum, 141),
            StdLatticeParm(HEStd_ternary, 8192, HEStd_256_quantum, 109),
            StdLatticeParm(HEStd_ternary, 16384, HEStd_128_quantum, 411),
            StdLatticeParm(HEStd_ternary, 16384, HEStd_192_quantum, 284),
            StdLatticeParm(HEStd_ternary, 16384, HEStd_256_quantum, 220),
            StdLatticeParm(HEStd_ternary, 32768, HEStd_128_quantum, 827),
            StdLatticeParm(HEStd_ternary, 32768, HEStd_192_quantum, 571),
            StdLatticeParm(HEStd_ternary, 32768, HEStd_256_quantum, 443),
            StdLatticeParm(HEStd_ternary, 65536, HEStd_128_quantum, 1663),
            StdLatticeParm(HEStd_ternary, 65536, HEStd_192_quantum, 1145),
            StdLatticeParm(HEStd_ternary, 65536, HEStd_256_quantum, 888),
            StdLatticeParm(HEStd_ternary, 131072, HEStd_128_quantum, 3348),
            StdLatticeParm(HEStd_ternary, 131072, HEStd_192_quantum, 2301),
            StdLatticeParm(HEStd_ternary, 131072, HEStd_256_quantum, 1784),
    };
}

} /* namespace lbcrypto */

#endif  // SRC_CORE_INCLUDE_LATTICE_STDLATTICEPARMS_H_
