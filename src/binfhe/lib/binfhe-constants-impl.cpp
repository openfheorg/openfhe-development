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

#include <ostream>

#include "binfhe-constants.h"

namespace lbcrypto {

std::ostream& operator<<(std::ostream& s, BINFHEPARAMSET f) {
    switch (f) {
        case TOY:
            s << "TOY";
            break;
        case MEDIUM:
            s << "MEDIUM";
            break;
        case STD128_AP:
            s << "STD128_AP";
            break;
        case STD128_APOPT:
            s << "STD128_APOPT";
            break;
        case STD128:
            s << "STD128";
            break;
        case STD128_OPT:
            s << "STD128_OPT";
            break;
        case STD192:
            s << "STD192";
            break;
        case STD192_OPT:
            s << "STD192_OPT";
            break;
        case STD256:
            s << "STD256";
            break;
        case STD256_OPT:
            s << "STD256_OPT";
            break;
        case STD128Q:
            s << "STD128Q";
            break;
        case STD128Q_OPT:
            s << "STD128Q_OPT";
            break;
        case STD192Q:
            s << "STD192Q";
            break;
        case STD192Q_OPT:
            s << "STD192Q_OPT";
            break;
        case STD256Q:
            s << "STD256Q";
            break;
        case STD256Q_OPT:
            s << "STD256Q_OPT";
            break;
        case SIGNED_MOD_TEST:
            s << "SIGNED_MOD_TEST";
            break;
        default:
            s << "UKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINFHEOUTPUT f) {
    switch (f) {
        case FRESH:
            s << "FRESH";
            break;
        case BOOTSTRAPPED:
            s << "BOOTSTRAPPED";
            break;
        default:
            s << "UKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINFHEMETHOD f) {
    switch (f) {
        case AP:
            s << "AP";
            break;
        case GINX:
            s << "GINX";
            break;
        default:
            s << "UKNOWN";
            break;
    }
    return s;
}

};  // namespace lbcrypto
