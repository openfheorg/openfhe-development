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
  Implementation for the standard values for Lattice Parms; see stdlatticeparms.h for the sources of the tables
 */

#include "lattice/stdlatticeparms.h"

#include <cstdint>
#include <map>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include "utils/exception.h"
#include "utils/inttypes.h"

namespace lbcrypto {

SecurityLevel convertToSecurityLevel(const std::string& str) {
    if (str == "HEStd_128_classic")
        return HEStd_128_classic;
    else if (str == "HEStd_192_classic")
        return HEStd_192_classic;
    else if (str == "HEStd_256_classic")
        return HEStd_256_classic;
    else if (str == "HEStd_128_quantum")
        return HEStd_128_quantum;
    else if (str == "HEStd_192_quantum")
        return HEStd_192_quantum;
    else if (str == "HEStd_256_quantum")
        return HEStd_256_quantum;
    else if (str == "HEStd_NotSet")
        return HEStd_NotSet;
    else if (str == "HEORG24_128")
        return HEORG24_128;
    else if (str == "HEORG24_192")
        return HEORG24_192;
    else if (str == "HEORG24_256")
        return HEORG24_256;
    else if (str == "HE_SPARSE_H192_128")
        return HE_SPARSE_H192_128;

    OPENFHE_THROW(std::string("Unknown SecurityLevel ") + str);
}
SecurityLevel convertToSecurityLevel(uint32_t num) {
    auto secLevel = static_cast<SecurityLevel>(num);
    switch (secLevel) {
        // case HEStd_NotSet:
        case HEStd_128_classic:
        case HEStd_192_classic:
        case HEStd_256_classic:
        case HEStd_128_quantum:
        case HEStd_192_quantum:
        case HEStd_256_quantum:
        case HEORG24_128:
        case HEORG24_192:
        case HEORG24_256:
        case HE_SPARSE_H192_128:
            return secLevel;
        default:
            break;
    }

    OPENFHE_THROW(std::string("Unknown value for SecurityLevel ") + std::to_string(num));
}

std::ostream& operator<<(std::ostream& s, SecurityLevel sl) {
    switch (sl) {
        case HEStd_128_classic:
            s << "HEStd_128_classic";
            break;
        case HEStd_192_classic:
            s << "HEStd_192_classic";
            break;
        case HEStd_256_classic:
            s << "HEStd_256_classic";
            break;
        case HEStd_128_quantum:
            s << "HEStd_128_quantum";
            break;
        case HEStd_192_quantum:
            s << "HEStd_192_quantum";
            break;
        case HEStd_256_quantum:
            s << "HEStd_256_quantum";
            break;
        case HEStd_NotSet:
            s << "HEStd_NotSet";
            break;
        case HEORG24_128:
            s << "HEORG24_128";
            break;
        case HEORG24_192:
            s << "HEORG24_192";
            break;
        case HEORG24_256:
            s << "HEORG24_256";
            break;
        case HE_SPARSE_H192_128:
            s << "HE_SPARSE_H192_128";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::map<StdLatticeParm::TableKey, StdLatticeParm::Table> StdLatticeParm::byRing;
std::map<StdLatticeParm::TableKey, StdLatticeParm::Table> StdLatticeParm::byLogQ;

bool StdLatticeParm::initialized = false;

uint32_t StdLatticeParm::FindRingDim(DistributionType distType, SecurityLevel minSecLev, uint32_t curLogQ) {
    if (!initialized)
        initializeLookups();

    auto found = byLogQ.find({distType, minSecLev});
    if (found == byLogQ.end()) {
        std::ostringstream os;
        os << "No security table for distribution type " << static_cast<int>(distType) << " and security level "
           << minSecLev << " (HE_SPARSE_H192_128 is for sparse secrets only, the other levels for non-sparse ones)";
        OPENFHE_THROW(os.str());
    }

    uint32_t prev = 0;
    uint32_t n = 0;
    for (const auto& it : found->second) {
        if ((curLogQ <= it.second->getMaxLogQ()) && (curLogQ > prev))
            return it.second->getRingDim();
        prev = it.second->getMaxLogQ();
        n = it.second->getRingDim();
    }
    return 2 * n;
}

DistributionType StdLatticeParm::GetDistributionType(SecretKeyDist secretKeyDist, SecurityLevel minSecLev) {
    const bool sparseSecret = (secretKeyDist == SPARSE_TERNARY) || (secretKeyDist == SPARSE_ENCAPSULATED);
    if (minSecLev == HE_SPARSE_H192_128) {
        if (!sparseSecret) {
            OPENFHE_THROW(
                    "HE_SPARSE_H192_128 is defined only for sparse secrets of Hamming weight 192 (SPARSE_TERNARY or "
                    "SPARSE_ENCAPSULATED); use HEORG24_128 for uniform ternary and Gaussian secrets");
        }
        return HEStd_sparse;
    }
    return (secretKeyDist == GAUSSIAN) ? HEStd_error : HEStd_ternary;
}

// this is a collection of all of the parameter sets
// the constructor for each one saves and indexes it so that you can search for
// it with static methods in the StdLatticeParm class
std::vector<StdLatticeParm> StdLatticeParm::StandardLatticeParmSets({
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

        // Table 5.2 of the Security Guidelines for Implementing Homomorphic Encryption (IACR Communications in
        // Cryptology 1(4), 2025, https://cic.iacr.org/p/1/4/26; also ePrint 2024/463): maximal log2(q) for Gaussian
        // error with standard deviation 3.19, estimated with the Lattice Estimator (commit 8f1ff7e) and the
        // RC.MATZOV cost model. The levels apply to both classical and quantum attacks.
        // There are no rows for N = 1024 at the 192- and 256-bit levels.
        StdLatticeParm(HEStd_ternary, 1024, HEORG24_128, 26),
        StdLatticeParm(HEStd_ternary, 2048, HEORG24_128, 53),
        StdLatticeParm(HEStd_ternary, 2048, HEORG24_192, 36),
        StdLatticeParm(HEStd_ternary, 2048, HEORG24_256, 27),
        StdLatticeParm(HEStd_ternary, 4096, HEORG24_128, 106),
        StdLatticeParm(HEStd_ternary, 4096, HEORG24_192, 73),
        StdLatticeParm(HEStd_ternary, 4096, HEORG24_256, 56),
        StdLatticeParm(HEStd_ternary, 8192, HEORG24_128, 214),
        StdLatticeParm(HEStd_ternary, 8192, HEORG24_192, 147),
        StdLatticeParm(HEStd_ternary, 8192, HEORG24_256, 114),
        StdLatticeParm(HEStd_ternary, 16384, HEORG24_128, 430),
        StdLatticeParm(HEStd_ternary, 16384, HEORG24_192, 297),
        StdLatticeParm(HEStd_ternary, 16384, HEORG24_256, 230),
        StdLatticeParm(HEStd_ternary, 32768, HEORG24_128, 868),
        StdLatticeParm(HEStd_ternary, 32768, HEORG24_192, 597),
        StdLatticeParm(HEStd_ternary, 32768, HEORG24_256, 462),
        StdLatticeParm(HEStd_ternary, 65536, HEORG24_128, 1747),
        StdLatticeParm(HEStd_ternary, 65536, HEORG24_192, 1199),
        StdLatticeParm(HEStd_ternary, 65536, HEORG24_256, 929),
        StdLatticeParm(HEStd_ternary, 131072, HEORG24_128, 3523),
        StdLatticeParm(HEStd_ternary, 131072, HEORG24_192, 2411),
        StdLatticeParm(HEStd_ternary, 131072, HEORG24_256, 1866),

        StdLatticeParm(HEStd_error, 1024, HEORG24_128, 28),
        StdLatticeParm(HEStd_error, 2048, HEORG24_128, 55),
        StdLatticeParm(HEStd_error, 2048, HEORG24_192, 38),
        StdLatticeParm(HEStd_error, 2048, HEORG24_256, 30),
        StdLatticeParm(HEStd_error, 4096, HEORG24_128, 108),
        StdLatticeParm(HEStd_error, 4096, HEORG24_192, 75),
        StdLatticeParm(HEStd_error, 4096, HEORG24_256, 58),
        StdLatticeParm(HEStd_error, 8192, HEORG24_128, 216),
        StdLatticeParm(HEStd_error, 8192, HEORG24_192, 149),
        StdLatticeParm(HEStd_error, 8192, HEORG24_256, 116),
        StdLatticeParm(HEStd_error, 16384, HEORG24_128, 432),
        StdLatticeParm(HEStd_error, 16384, HEORG24_192, 299),
        StdLatticeParm(HEStd_error, 16384, HEORG24_256, 232),
        StdLatticeParm(HEStd_error, 32768, HEORG24_128, 870),
        StdLatticeParm(HEStd_error, 32768, HEORG24_192, 599),
        StdLatticeParm(HEStd_error, 32768, HEORG24_256, 464),
        StdLatticeParm(HEStd_error, 65536, HEORG24_128, 1749),
        StdLatticeParm(HEStd_error, 65536, HEORG24_192, 1201),
        StdLatticeParm(HEStd_error, 65536, HEORG24_256, 931),
        StdLatticeParm(HEStd_error, 131072, HEORG24_128, 3525),
        StdLatticeParm(HEStd_error, 131072, HEORG24_192, 2413),
        StdLatticeParm(HEStd_error, 131072, HEORG24_256, 1868),

        // 128-bit classical security for sparse ternary secrets of Hamming weight 192 (the Hamming weight of
        // SPARSE_TERNARY and SPARSE_ENCAPSULATED secret keys) for the ring dimensions used in CKKS bootstrapping.
        // The work factors below were obtained with the Lattice Estimator (https://github.com/malb/lattice-estimator,
        // commit 6019056) for error standard deviation 3.19 using the MATZOV reduction cost model; the best attack
        // for all three sets is bdd_mitm_hybrid:
        //   N = 32768,  log2(q) = 767:  134.1 bits
        //   N = 65536,  log2(q) = 1553: 134.0 bits
        //   N = 131072, log2(q) = 3104: 135.7 bits
        // Ciphertext moduli below 767 bits map to N = 32768.
        StdLatticeParm(HEStd_sparse, 32768, HE_SPARSE_H192_128, 767),
        StdLatticeParm(HEStd_sparse, 65536, HE_SPARSE_H192_128, 1553),
        StdLatticeParm(HEStd_sparse, 131072, HE_SPARSE_H192_128, 3104),
});

} /* namespace lbcrypto */
