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

std::map<uint32_t, const StdLatticeParm*> StdLatticeParm::byRing[3][6];
std::map<uint32_t, const StdLatticeParm*> StdLatticeParm::byLogQ[3][6];

bool StdLatticeParm::initialized = false;

} /* namespace lbcrypto */
