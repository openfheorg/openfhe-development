/***
 * © 2020 Duality Technologies, Inc. All rights reserved.
 * This is a proprietary software product of Duality Technologies, Inc. protected under copyright laws
 * and international copyright treaties, patent law, trade secret law and other intellectual property
 * rights of general applicability.
 * Any use of this software is strictly prohibited absent a written agreement executed by Duality
 * Technologies, Inc., which provides certain limited rights to use this software.
 * You may not copy, distribute, make publicly available, publicly perform, disassemble, de-compile or
 * reverse engineer any part of this software, breach its security, or circumvent, manipulate, impair or
 * disrupt its operation.
 ***/

#include "utils/rotatablevector.h"
#include "utils/exception.h"
#include "utils/logger.h"

std::complex<double> RotatableVector::get(int index) {
    LOG_DEBUG_ALL("Begin");
	if (this->size > 0)
		return vec[ (start + index) % this->size ];
	else {
		std::string errMsg = "RotatableVector::get Cannot get from empty vector.";
		OPENFHE_THROW(lbcrypto::math_error, errMsg);
	}
}

void RotatableVector::set(int index, std::complex<double> val) {
    LOG_DEBUG_ALL("Begin");
	if (this->size > 0)
		this->vec[ (start + index) % this->size ] = val;
	else {
		std::string errMsg = "RotatableVector::set Cannot set element in empty vector.";
		OPENFHE_THROW(lbcrypto::math_error, errMsg);
	}
}

// Positive offset corresponds to left rotation.
void RotatableVector::rotate(int offset) {
    LOG_DEBUG_ALL("Begin");
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
    LOG_DEBUG_ALL("Begin");
	std::vector<std::complex<double>> newVec(this->size);
	for (int i=0; i<this->size; i++) {
		newVec[i] = this->vec[ (start + i) % this->size ];
	}
	return newVec;
}

