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

#include <vector>
#include <complex>

/**
 * RotatableVector is a class that efficiently implements
 * rotation of elements within in vector. Instead of shifting
 * elements by copying their contents (which is O(n) complexity),
 * it shifts the starting index of the vector (which is O(1)).
 */
class RotatableVector {
	int start;
	int size;
	std::vector<std::complex<double>> vec;

public:

	/*
	 * Constructor of an empty vector.
	 */
	RotatableVector() : start(0), size(0) {}

	/**
	 * Constructor for a vector of size "size".
	 *
	 * @param size the size of the vector.
	 */
	RotatableVector(int size0) : start(0), size(size0), vec(std::vector<std::complex<double>>(size)) {}

	/**
	 * Gets the elements in position "index" of the vector.
	 *
	 * @param index The position of the vector we want to get.
	 */
	std::complex<double> get(int index);

	/**
	 * Sets the position "index" of the vector to value "val".
	 *
	 * @param index The position of the vector we want to set.
	 * @param val The value we want to store in the vector.
	 */
	void set(int index, std::complex<double> val);

	/**
	 * Rotates the vector by offset. Positive offsets correspond
	 * to left rotations, whereas negative ones to right.
	 *
	 * @param offset The offset we want to move vector elements by.
	 * 		  Can be positive or negative.
	 */
	void rotate(int offset);

	/**
	 * Returns a regular std::vector containing the elements in
	 * this RotatbleVector.
	 */
	std::vector<std::complex<double>> getVector();

	/**
	 * Returns the length of the RotatableVector.
	 */
	inline int length()
	{
		return size;
	}
};

