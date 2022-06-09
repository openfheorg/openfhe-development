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
#ifndef LBCRYPTO_DUALITY_UTILS_LINEARTRANSFORM_H
#define LBCRYPTO_DUALITY_UTILS_LINEARTRANSFORM_H

#include <vector>
#include <complex>
#include <iostream>

/*
 * Subroutines used by the linear transformation homomorphic capability
 */

namespace lbcrypto {

/**
 * Extracts shifted diagonal of matrix A.
 *
 * @param &A square linear map.
 * @param index the index by which the diagonal shifted.
 *
 * @return the vector corresponding to the shifted diagonal
 */
std::vector<std::complex<double>> ExtractShiftedDiagonal(
	const std::vector<std::vector<std::complex<double>>> &A,
	int index);

/**
 * Rotates a vector by an index - left rotation
 *
 * @param &a square linear map.
 * @param index rotation index.
 *
 * @return the rotated vector
 */
std::vector<std::complex<double>> Rotate(
	const std::vector<std::complex<double>> &a,
	int32_t index);


/**
 * Clones the current vector up to the size indicated by the "slote" variable
 *
 * @param &a square linear map.
 * @param slots the new size of the vector.
 *
 * @return the vector with cloned values
 */
std::vector<std::complex<double>> Fill(
	const std::vector<std::complex<double>> &a,
	int slots);

/**
 * Computes the coefficients for the FFT encoding for CoeffEncodingCollapse such that every
 * iteration occupies one level.
 *
 * @param pows vector of roots of unity powers.
 * @param rotGroup rotation group indices to appropriately choose the elements of pows to compute iFFT.
 * @param flag_i flag that is 0 when we compute the coefficients for conj(U_0^T) and is 1 for conj(i*U_0^T).
 */
std::vector<std::vector<std::complex<double>>> CoeffEncodingOneLevel(
	const std::vector<std::complex<double>> &pows,
	const std::vector<uint32_t> &rotGroup,
	bool flag_i);

/**
 * Computes the coefficients for the FFT decoding for CoeffDecodingCollapse such that every
 * iteration occupies one level.
 *
 * @param pows vector of roots of unity powers.
 * @param rotGroup rotation group indices to appropriately choose the elements of pows to compute iFFT.
 * @param flag_i flag that is 0 when we compute the coefficients for U_0 and is 1 for i*U_0.
 */
std::vector<std::vector<std::complex<double>>> CoeffDecodingOneLevel(
	const std::vector<std::complex<double>> &pows,
	const std::vector<uint32_t> &rotGroup,
	bool flag_i);


/**
 * Computes the coefficients for the given level budget for the FFT encoding. Needed in
 * EvalLTFFTPrecomputeEncoding.
 *
 * @param pows vector of roots of unity powers.
 * @param rotGroup rotation group indices to appropriately choose the elements of pows to compute iFFT.
 * @param levelBudget the user specified budget for levels.
 * @param flag_i flag that is 0 when we compute the coefficients for conj(U_0^T) and is 1 for conj(i*U_0^T).
 */
std::vector<std::vector<std::vector<std::complex<double>>>> CoeffEncodingCollapse(
	const std::vector<std::complex<double>> &pows,
	const std::vector<uint32_t> &rotGroup,
	uint32_t levelBudget,
	bool flag_i);

/**
 * Computes the coefficients for the given level budget for the FFT decoding. Needed in
 * EvalLTFFTPrecomputeDecoding.
 *
 * @param pows vector of roots of unity powers.
 * @param rotGroup rotation group indices to appropriately choose the elements of pows to compute FFT.
 * @param levelBudget the user specified budget for levels.
 * @param flag_i flag that is 0 when we compute the coefficients for U_0 and is 1 for i*U_0.
 */
std::vector<std::vector<std::vector<std::complex<double>>>> CoeffDecodingCollapse(
	const std::vector<std::complex<double>> &pows,
	const std::vector<uint32_t> &rotGroup,
	uint32_t levelBudget,
	bool flag_i);


/**
 * Ensures that the index for rotation is positive and between 1 and slots.
 *
 * @param index signed rotation amount.
 * @param slots number of slots and size of vector that is rotated.
 */
uint32_t ReduceRotation(int32_t index, uint32_t slots);

/**
 * Computes parameters to ensure the encoding and decoding computations take exactly the
 * specified number of levels. More specifically, it returns a vector than contains
 * layers (the number of layers to collapse in one level), rows (how many such levels),
 * rem (the number of layers remaining to be collapsed in one level)
 *
 * @param logSlots the base 2 logarithm of the number of slots.
 * @param budget the allocated level budget for the computation.
 */
std::vector<uint32_t> SelectLayers(uint32_t logSlots, uint32_t budget = 4);

/**
 * Computes all parameters needed for the homomorphic encoding and decoding in the bootstrapping
 * operation and returns them as a vector. The returned vector's data can be accessed using
 * enum'ed indices from FFT_PARAMS that are defined below.
 *
 * @param slots number of slots.
 * @param levelBudget the allocated level budget for the computation.
 * @param dim1 the value for the inner dimension in the baby-step giant-step strategy
 * @return vector with parameters for the homomorphic encoding and decoding in bootstrapping
 */
std::vector<int32_t> GetCollapsedFFTParams(uint32_t slots, uint32_t levelBudget = 4, uint32_t dim1 = 0);

namespace FFT_PARAMS {
	/**
	 * Enums representing indices for the vector returned by GetCollapsedFFTParams()
	 */
	enum {
		LEVEL_BUDGET,      // the level budget
		LAYERS_COLL,       // the number of layers to collapse in one level
		LAYERS_REM,        // the number of layers remaining to be collapsed in one level to have exactly the number of levels specified in the level budget
		NUM_ROTATIONS,     // the number of rotations in one level
		BABY_STEP,         // the baby step in the baby-step giant-step strategy
		GIANT_STEP,        // the giant step in the baby-step giant-step strategy
		NUM_ROTATIONS_REM, // the number of rotations in the remaining level
		BABY_STEP_REM,     // the baby step in the baby-step giant-step strategy for the remaining level
		GIANT_STEP_REM,    // the giant step in the baby-step giant-step strategy for the remaining level
		TOTAL_ELEMENTS     // total number of elements in the vector
	};
}
}

#endif
