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

#include "constants.h"
#include "utils/exception.h"

#include <string>
#include <ostream>

namespace lbcrypto {

std::ostream& operator<<(std::ostream& s, PKESchemeFeature f) {
    switch (f) {
        case PKE:
            s << "PKE";
            break;
        case KEYSWITCH:
            s << "KEYSWITCH";
            break;
        case PRE:
            s << "PRE";
            break;
        case LEVELEDSHE:
            s << "LEVELEDSHE";
            break;
        case ADVANCEDSHE:
            s << "ADVANCEDSHE";
            break;
        case MULTIPARTY:
            s << "MULTIPARTY";
            break;
        case FHE:
            s << "FHE";
            break;
        case SCHEMESWITCH:
            s << "SCHEMESWITCH";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

ScalingTechnique convertToScalingTechnique(const std::string& str) {
    if (str == "FIXEDMANUAL")
        return FIXEDMANUAL;
    else if (str == "FIXEDAUTO")
        return FIXEDAUTO;
    else if (str == "FLEXIBLEAUTO")
        return FLEXIBLEAUTO;
    else if (str == "FLEXIBLEAUTOEXT")
        return FLEXIBLEAUTOEXT;
    else if (str == "NORESCALE")
        return NORESCALE;

    std::string errMsg(std::string("Unknown ScalingTechnique ") + str);
    OPENFHE_THROW(errMsg);
}
ScalingTechnique convertToScalingTechnique(uint32_t num) {
    auto scTech = static_cast<ScalingTechnique>(num);
    switch (scTech) {
        case FIXEDMANUAL:
        case FIXEDAUTO:
        case FLEXIBLEAUTO:
        case FLEXIBLEAUTOEXT:
        case NORESCALE:
            // case INVALID_RS_TECHNIQUE:
            return scTech;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for ScalingTechnique ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
}
std::ostream& operator<<(std::ostream& s, ScalingTechnique t) {
    switch (t) {
        case FIXEDMANUAL:
            s << "FIXEDMANUAL";
            break;
        case FIXEDAUTO:
            s << "FIXEDAUTO";
            break;
        case FLEXIBLEAUTO:
            s << "FLEXIBLEAUTO";
            break;
        case FLEXIBLEAUTOEXT:
            s << "FLEXIBLEAUTOEXT";
            break;
        case NORESCALE:
            s << "NORESCALE";
            break;
        case INVALID_RS_TECHNIQUE:
            s << "INVALID_RS_TECHNIQUE";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

ProxyReEncryptionMode convertToProxyReEncryptionMode(const std::string& str) {
    if (str == "NOT_SET")
        return NOT_SET;
    else if (str == "INDCPA")
        return INDCPA;
    else if (str == "FIXED_NOISE_HRA")
        return FIXED_NOISE_HRA;
    else if (str == "NOISE_FLOODING_HRA")
        return NOISE_FLOODING_HRA;
    else if (str == "DIVIDE_AND_ROUND_HRA")
        return DIVIDE_AND_ROUND_HRA;

    std::string errMsg(std::string("Unknown ProxyReEncryptionMode ") + str);
    OPENFHE_THROW(errMsg);
}
ProxyReEncryptionMode convertToProxyReEncryptionMode(uint32_t num) {
    auto encrMode = static_cast<ProxyReEncryptionMode>(num);
    switch (encrMode) {
        // case NOT_SET:
        case INDCPA:
        case FIXED_NOISE_HRA:
        case NOISE_FLOODING_HRA:
        case DIVIDE_AND_ROUND_HRA:
            return encrMode;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for ProxyReEncryptionMode ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
}
std::ostream& operator<<(std::ostream& s, ProxyReEncryptionMode p) {
    switch (p) {
        case NOT_SET:
            s << "NOT_SET";
            break;
        case INDCPA:
            s << "INDCPA";
            break;
        case FIXED_NOISE_HRA:
            s << "FIXED_NOISE_HRA";
            break;
        case NOISE_FLOODING_HRA:
            s << "NOISE_FLOODING_HRA";
            break;
        case DIVIDE_AND_ROUND_HRA:
            s << "DIVIDE_AND_ROUND_HRA";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

MultipartyMode convertToMultipartyMode(const std::string& str) {
    if (str == "INVALID_MULTIPARTY_MODE")
        return INVALID_MULTIPARTY_MODE;
    else if (str == "FIXED_NOISE_MULTIPARTY")
        return FIXED_NOISE_MULTIPARTY;
    else if (str == "NOISE_FLOODING_MULTIPARTY")
        return NOISE_FLOODING_MULTIPARTY;

    std::string errMsg(std::string("Unknown MultipartyMode ") + str);
    OPENFHE_THROW(errMsg);
}
MultipartyMode convertToMultipartyMode(uint32_t num) {
    auto mptyMode = static_cast<MultipartyMode>(num);
    switch (mptyMode) {
        // case INVALID_MULTIPARTY_MODE:
        case FIXED_NOISE_MULTIPARTY:
        case NOISE_FLOODING_MULTIPARTY:
            return mptyMode;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for MultipartyMode ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
}
std::ostream& operator<<(std::ostream& s, MultipartyMode t) {
    switch (t) {
        case INVALID_MULTIPARTY_MODE:
            s << "INVALID_MULTIPARTY_MODE";
            break;
        case FIXED_NOISE_MULTIPARTY:
            s << "FIXED_NOISE_MULTIPARTY";
            break;
        case NOISE_FLOODING_MULTIPARTY:
            s << "NOISE_FLOODING_MULTIPARTY";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

ExecutionMode convertToExecutionMode(const std::string& str) {
    if (str == "EXEC_EVALUATION")
        return EXEC_EVALUATION;
    else if (str == "EXEC_NOISE_ESTIMATION")
        return EXEC_NOISE_ESTIMATION;

    std::string errMsg(std::string("Unknown ExecutionMode ") + str);
    OPENFHE_THROW(errMsg);
}
ExecutionMode convertToExecutionMode(uint32_t num) {
    auto execMode = static_cast<ExecutionMode>(num);
    switch (execMode) {
        case EXEC_EVALUATION:
        case EXEC_NOISE_ESTIMATION:
            return execMode;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for ExecutionMode ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
}
std::ostream& operator<<(std::ostream& s, ExecutionMode t) {
    switch (t) {
        case EXEC_EVALUATION:
            s << "EXEC_EVALUATION";
            break;
        case EXEC_NOISE_ESTIMATION:
            s << "EXEC_NOISE_ESTIMATION";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

DecryptionNoiseMode convertToDecryptionNoiseMode(const std::string& str) {
    if (str == "FIXED_NOISE_DECRYPT")
        return FIXED_NOISE_DECRYPT;
    else if (str == "NOISE_FLOODING_DECRYPT")
        return NOISE_FLOODING_DECRYPT;

    std::string errMsg(std::string("Unknown DecryptionNoiseMode ") + str);
    OPENFHE_THROW(errMsg);
}
DecryptionNoiseMode convertToDecryptionNoiseMode(uint32_t num) {
    auto noiseMode = static_cast<DecryptionNoiseMode>(num);
    switch (noiseMode) {
        case FIXED_NOISE_DECRYPT:
        case NOISE_FLOODING_DECRYPT:
            return noiseMode;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for DecryptionNoiseMode ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
}
std::ostream& operator<<(std::ostream& s, DecryptionNoiseMode t) {
    switch (t) {
        case FIXED_NOISE_DECRYPT:
            s << "FIXED_NOISE_DECRYPT";
            break;
        case NOISE_FLOODING_DECRYPT:
            s << "NOISE_FLOODING_DECRYPT";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

KeySwitchTechnique convertToKeySwitchTechnique(const std::string& str) {
    if (str == "BV")
        return BV;
    else if (str == "HYBRID")
        return HYBRID;

    std::string errMsg(std::string("Unknown KeySwitchTechnique ") + str);
    OPENFHE_THROW(errMsg);
}
KeySwitchTechnique convertToKeySwitchTechnique(uint32_t num) {
    auto ksTech = static_cast<KeySwitchTechnique>(num);
    switch (ksTech) {
        // case INVALID_KS_TECH:
        case BV:
        case HYBRID:
            return ksTech;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for KeySwitchTechnique ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
}
std::ostream& operator<<(std::ostream& s, KeySwitchTechnique t) {
    switch (t) {
        case BV:
            s << "BV";
            break;
        case HYBRID:
            s << "HYBRID";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

EncryptionTechnique convertToEncryptionTechnique(const std::string& str) {
    if (str == "STANDARD")
        return STANDARD;
    else if (str == "EXTENDED")
        return EXTENDED;

    std::string errMsg(std::string("Unknown EncryptionTechnique ") + str);
    OPENFHE_THROW(errMsg);
}
EncryptionTechnique convertToEncryptionTechnique(uint32_t num) {
    auto encrTech = static_cast<EncryptionTechnique>(num);
    switch (encrTech) {
        case STANDARD:
        case EXTENDED:
            return encrTech;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for EncryptionTechnique ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
}
std::ostream& operator<<(std::ostream& s, EncryptionTechnique t) {
    switch (t) {
        case STANDARD:
            s << "STANDARD";
            break;
        case EXTENDED:
            s << "EXTENDED";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

MultiplicationTechnique convertToMultiplicationTechnique(const std::string& str) {
    if (str == "BEHZ")
        return BEHZ;
    else if (str == "HPS")
        return HPS;
    else if (str == "HPSPOVERQ")
        return HPSPOVERQ;
    else if (str == "HPSPOVERQLEVELED")
        return HPSPOVERQLEVELED;

    std::string errMsg(std::string("Unknown MultiplicationTechnique ") + str);
    OPENFHE_THROW(errMsg);
}
MultiplicationTechnique convertToMultiplicationTechnique(uint32_t num) {
    auto multTech = static_cast<MultiplicationTechnique>(num);
    switch (multTech) {
        case BEHZ:
        case HPS:
        case HPSPOVERQ:
        case HPSPOVERQLEVELED:
            return multTech;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for MultiplicationTechnique ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
}
std::ostream& operator<<(std::ostream& s, MultiplicationTechnique t) {
    switch (t) {
        case BEHZ:
            s << "BEHZ";
            break;
        case HPS:
            s << "HPS";
            break;
        case HPSPOVERQ:
            s << "HPSPOVERQ";
            break;
        case HPSPOVERQLEVELED:
            s << "HPSPOVERQLEVELED";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, PlaintextEncodings p) {
    switch (p) {
        case COEF_PACKED_ENCODING:
            s << "COEF_PACKED_ENCODING";
            break;
        case PACKED_ENCODING:
            s << "PACKED_ENCODING";
            break;
        case STRING_ENCODING:
            s << "STRING_ENCODING";
            break;
        case CKKS_PACKED_ENCODING:
            s << "CKKS_PACKED_ENCODING";
            break;
        case INVALID_ENCODING:
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

COMPRESSION_LEVEL convertToCompressionLevel(const std::string& str) {
    if (str == "COMPACT")
        return COMPACT;
    else if (str == "SLACK")
        return SLACK;

    std::string errMsg(std::string("Unknown COMPRESSION_LEVEL ") + str);
    OPENFHE_THROW(errMsg);
}
COMPRESSION_LEVEL convertToCompressionLevel(uint32_t num) {
    auto compressionLevel = static_cast<COMPRESSION_LEVEL>(num);
    switch (compressionLevel) {
        case COMPACT:
        case SLACK:
            return compressionLevel;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for COMPRESSION_LEVEL ") + std::to_string(num));
    OPENFHE_THROW(errMsg);
}
std::ostream& operator<<(std::ostream& s, COMPRESSION_LEVEL p) {
    switch (p) {
        case COMPACT:
            s << "COMPACT";
            break;
        case SLACK:
            s << "SLACK";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

}  // namespace lbcrypto
