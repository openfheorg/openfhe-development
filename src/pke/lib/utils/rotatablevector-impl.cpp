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


#include "utils/rotatablevector.h"
#include "utils/exception.h"
//#include "utils/logger.h"

std::complex<double> RotatableVector::get(int index) {

	if (this->size > 0)
		return vec[ (start + index) % this->size ];
	else {
		std::string errMsg = "RotatableVector::get Cannot get from empty vector.";
		OPENFHE_THROW(lbcrypto::math_error, errMsg);
	}
}

void RotatableVector::set(int index, std::complex<double> val) {

	if (this->size > 0)
		this->vec[ (start + index) % this->size ] = val;
	else {
		std::string errMsg = "RotatableVector::set Cannot set element in empty vector.";
		OPENFHE_THROW(lbcrypto::math_error, errMsg);
	}
}

// Positive offset corresponds to left rotation.
void RotatableVector::rotate(int offset) {

	if (this->size > 0) {
		this->start = (this->start - offset) % this->size;
		if (this->start < 0)
			this->start += this->size;
	} else {
		std::string errMsg = "RotatableVector::rotateRight Cannot rotate empty vector.";
		OPENFHE_THROW(lbcrypto::math_error, errMsg);
	}
}

std::vector<std::complex<double>> RotatableVector::getVector() {

	std::vector<std::complex<double>> newVec(this->size);
	for (int i=0; i<this->size; i++) {
		newVec[i] = this->vec[ (start + i) % this->size ];
	}
	return newVec;
}

