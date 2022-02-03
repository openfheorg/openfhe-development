// @file UnitTestCompareCryptoContext.cpp - Function to compare 2 crypto contexts generated the old and the new ways
// @copyright Copyright (c) 2019, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef _UNIT_TEST_COMPARE_CTXT_H_
#define _UNIT_TEST_COMPARE_CTXT_H_

#include "cryptocontext.h"

inline bool Equal(const lbcrypto::EncodingParamsImpl& a, const lbcrypto::EncodingParamsImpl& b) {
	if (a != b) {
        std::cerr << "EncodingParams are different: " << std::endl;
        std::cerr << "first : " << a << std::endl;
		std::cerr << "second: " << b << std::endl;
		return false;
	}

    return true;
}

template<typename Element>
bool Equal(const lbcrypto::CryptoContextImpl<Element>& a, const lbcrypto::CryptoContextImpl<Element>& b) {
    // Identical if the parameters and the schemes are identical... the exact
    // same object, OR the same type and the same values
    if (a.GetCryptoParameters().get() != b.GetCryptoParameters().get()) {
        if (typeid(*a.GetCryptoParameters().get()) != typeid(*b.GetCryptoParameters().get())) {
            std::cerr << "CryptoParameters types are different" << std::endl;
            return false;
        }

        // compare encoding and element parameters
        if (!Equal(*(a.GetEncodingParams().get()), *(b.GetEncodingParams().get()))) {
            return false;
        }
        if (*(a.GetElementParams().get()) != *(b.GetElementParams().get())) {
            std::cerr << "ElementParams are different" << std::endl;
            return false;
        }
    }

    if (a.GetScheme().get() != b.GetScheme().get()) {
        if (typeid(*a.GetScheme().get()) != typeid(*b.GetScheme().get())) {
            std::cerr << "EncryptionAlgorithm types/schemes are different" << std::endl;
            return false;
        }

        if (*a.GetScheme().get() != *b.GetScheme().get()) {
            std::cerr << "EncryptionAlgorithms are different" << std::endl;
            return false;
        }
    }

    return true;
}
#endif // _UNIT_TEST_COMPARE_CTXT_H_
