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
#include <iostream>
#include "binfhe-constants.h"

namespace lbcrypto {

BINFHE_PARAMSET findparamset(std::string s) {
    BINFHE_PARAMSET returnParam;
    std::cout << "s in findparamset: " << s << std::endl;
    if (s == "TOY") {
        returnParam = TOY;
    }
    else if (s == "MEDIUM") {
        returnParam = MEDIUM;
    }
    else if (s == "STD128_AP") {
        returnParam = STD128_AP;
    }
    else if (s == "STD128_APOPT") {
        returnParam = STD128_APOPT;
    }
    else if (s == "STD128") {
        returnParam = STD128;
    }
    else if (s == "STD128_3") {
        returnParam = STD128_3;
    }
    else if (s == "STD128_en") {
        returnParam = STD128_en;
    }
    else if (s == "STD128_en_3_1") {
        returnParam = STD128_en_3_1;
    }
    else if (s == "STD128_en_3_2") {
        returnParam = STD128_en_3_2;
    }
    else if (s == "STD128_AP_3") {
        returnParam = STD128_AP_3;
    }
    else if (s == "STD128Q_3") {
        returnParam = STD128Q_3;
    }
    else if (s == "STD128Q_OPT_3") {
        returnParam = STD128Q_OPT_3;
    }
    else if (s == "STD128Q_OPT_3_nQks1") {
        returnParam = STD128Q_OPT_3_nQks1;
    }
    else if (s == "STD128Q_OPT_3_en") {
        returnParam = STD128Q_OPT_3_en;
    }
    else if (s == "STD192Q_3") {
        returnParam = STD192Q_3;
    }
    else if (s == "STD192Q_OPT_3") {
        returnParam = STD192Q_OPT_3;
    }
    else if (s == "STD192Q_OPT_3_en") {
        returnParam = STD192Q_OPT_3_en;
    }
    else if (s == "STD192Q_OPT_3_en_3") {
        returnParam = STD192Q_OPT_3_en_3;
    }
    else if (s == "STD256Q_3") {
        returnParam = STD256Q_3;
    }
    else if (s == "STD256Q_4") {
        returnParam = STD256Q_4;
    }
    else if (s == "STD256Q_OPT_3") {
        returnParam = STD256Q_OPT_3;
    }
    else if (s == "STD256Q_OPT_3_en_1") {
        returnParam = STD256Q_OPT_3_en_1;
    }
    else if (s == "STD256Q_OPT_3_en_2") {
        returnParam = STD256Q_OPT_3_en_2;
    }
    else if (s == "STD128_OPT") {
        returnParam = STD128_OPT;
    }
    else if (s == "STD192") {
        returnParam = STD192;
    }
    else if (s == "STD192_OPT") {
        returnParam = STD192_OPT;
    }
    else if (s == "STD256") {
        returnParam = STD256;
    }
    else if (s == "STD256_OPT") {
        returnParam = STD256_OPT;
    }
    else if (s == "STD128Q") {
        returnParam = STD128Q;
    }
    else if (s == "STD128Q_OPT") {
        returnParam = STD128Q_OPT;
    }
    else if (s == "STD192Q") {
        returnParam = STD192Q;
    }
    else if (s == "STD192Q_OPT") {
        returnParam = STD192Q_OPT;
    }
    else if (s == "STD256Q") {
        returnParam = STD256Q;
    }
    else if (s == "STD256Q_OPT") {
        returnParam = STD256Q_OPT;
    }
    else if (s == "SIGNED_MOD_TEST") {
        returnParam = SIGNED_MOD_TEST;
    }
    else {
        std::cout << "unknown" << std::endl;  // change to openfhe_throw later
    }
    std::cout << "returnParam in findparamset: " << returnParam << std::endl;
    return returnParam;
}

std::ostream& operator<<(std::ostream& s, BINFHE_PARAMSET f) {
    switch (f) {
        case TOY:
            s << "TOY";
            break;
        case MEDIUM:
            s << "MEDIUM";
            break;
        case STD128_LMKCDEY:
            s << "STD128_LMKCDEY";
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
        case STD128Q_OPT_3:
            s << "STD128Q_OPT_3";
            break;
        case STD128Q_OPT_3_nQks1:
            s << "STD128Q_OPT_3_nQks1";
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
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINFHE_OUTPUT f) {
    switch (f) {
        case FRESH:
            s << "FRESH";
            break;
        case BOOTSTRAPPED:
            s << "BOOTSTRAPPED";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINFHE_METHOD f) {
    switch (f) {
        case AP:
            s << "DM";
            break;
        case GINX:
            s << "CGGI";
            break;
        case LMKCDEY:
            s << "LMKCDEY";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINGATE f) {
    switch (f) {
        case OR:
            s << "OR";
            break;
        case AND:
            s << "AND";
            break;
        case NOR:
            s << "NOR";
            break;
        case NAND:
            s << "NAND";
            break;
        case XOR_FAST:
            s << "XOR_FAST";
            break;
        case XNOR_FAST:
            s << "XNOR_FAST";
            break;
        case XOR:
            s << "XOR";
            break;
        case XNOR:
            s << "XNOR";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

};  // namespace lbcrypto
