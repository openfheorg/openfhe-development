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

