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
  Implementation for the standard values for Lattice Parms, as determined by homomorphicencryption.org
 */

#include "lattice/stdlatticeparms.h"

#include "utils/exception.h"
#include "utils/inttypes.h"

#include <ostream>
#include <map>
#include <string>
#include <vector>

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

    std::string errMsg(std::string("Unknown SecurityLevel ") + str);
    OPENFHE_THROW(errMsg);
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
            return secLevel;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for SecurityLevel ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
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
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::map<usint, StdLatticeParm*> StdLatticeParm::byRing[3][6];
std::map<usint, StdLatticeParm*> StdLatticeParm::byLogQ[3][6];

bool StdLatticeParm::initialized = false;

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
});

} /* namespace lbcrypto */
