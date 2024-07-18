// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2021, Duality Technologies Inc.
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
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THISvector<
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#define PROFILE

#include <fstream>
#include <iostream>
#include <iterator>
#include <math.h>
#include <inttypes.h>
#include <assert.h>

#include "openfhe.h"

using namespace lbcrypto;

// These pre-computations come from "Secure Outsourced Matrix Computation and Application to
// Neural Networks" (Jiang, Kim, Lauter, Song)
struct MatrixMatrixProductPrecomputations {
    int rowSize;
    std::vector<Plaintext> sigmaPlaintexts;
    std::vector<Plaintext> tauPlaintexts;
    std::vector<std::vector<Plaintext>> phiPlaintexts;
} MatrixMatrixProductPrecomputations;

void getMaxError(std::vector<double> vec1, std::vector<double> vec2);

template <typename Element>
std::vector<std::vector<Element>> getDiagonals(std::vector<std::vector<Element>> matrix);

std::vector<std::vector<double>> generateRandomMatrix(size_t numRows, size_t numCols);

std::vector<double> extractAndLinearizeMatrixBlock(std::vector<std::vector<double>> matrix, size_t numSlots,
                                                   size_t rowSize, size_t offsetRows = 0, size_t offsetCols = 0);

std::vector<std::vector<std::vector<double>>> extractAndLinearizeMatrix(const std::vector<std::vector<double>>& matrix,
                                                                        size_t numSlots, size_t rowSize);

std::vector<std::vector<Ciphertext<DCRTPoly>>> EncryptMatrix(
    const std::vector<std::vector<std::vector<double>>>& matrix, PublicKey<DCRTPoly> publicKey);

std::vector<std::vector<std::vector<double>>> DecryptMatrix(
    const std::vector<std::vector<Ciphertext<DCRTPoly>>>& matrix, PrivateKey<DCRTPoly> privateKey);

void getMaxErrorMatrix(const std::vector<std::vector<std::vector<double>>>& vec1,
                       const std::vector<std::vector<std::vector<double>>>& vec2);

template <typename Element>
std::vector<Element> naiveMatrixVectorMultiply(std::vector<std::vector<Element>> matrix, std::vector<Element> vec);

template <typename Element>
std::vector<Element> naiveMatrixVectorMultiply(std::vector<Element> matrix, int numRows, std::vector<Element> vec);

template <typename Element>
std::vector<std::vector<Element>> naiveMatrixMatrixMultiply(std::vector<std::vector<Element>> matrix1,
                                                            std::vector<std::vector<Element>> matrix2);

template <typename Element>
std::vector<std::vector<Element>> naiveMatrixMatrixMultiply(std::vector<Element> matrix1, std::vector<Element> matrix2,
                                                            size_t numRows1, size_t numCols1, size_t numCols2);

std::vector<std::vector<double>> getSigmaPermutationMatrix(size_t rowSize);

std::vector<std::vector<double>> getTauPermutationMatrix(size_t rowSize);

std::vector<std::vector<double>> getPhiDiagonals(size_t rowSize, size_t numRotations);

struct MatrixMatrixProductPrecomputations getMatrixMatrixProductPrecomputations(CryptoContext<DCRTPoly>& context,
                                                                                int rowSize);

// Square matrix multiplication
template <typename Element>
void MatrixMatrixProductSquareBSGS(CryptoContext<DCRTPoly>& context, Ciphertext<Element>& cMat1,
                                   Ciphertext<Element>& cMat2, uint32_t rowSize, Ciphertext<Element>& cProduct,
                                   struct MatrixMatrixProductPrecomputations precomp);

template <typename Element>
void MatrixMatrixProductSquare(CryptoContext<DCRTPoly>& context, Ciphertext<Element>& cMat1, Ciphertext<Element>& cMat2,
                               uint32_t rowSize, Ciphertext<Element>& cProduct,
                               struct MatrixMatrixProductPrecomputations precomp);

void MatrixMatrixProduct(std::vector<std::vector<Ciphertext<DCRTPoly>>>& matrix1,
                         std::vector<std::vector<Ciphertext<DCRTPoly>>>& matrix2, uint32_t rowSize,
                         std::vector<std::vector<Ciphertext<DCRTPoly>>>& product,
                         struct MatrixMatrixProductPrecomputations precomp);

void printMinAndMax(std::vector<double> arr) {
    double min = -1;
    double max = 1;
    for (size_t i = 0; i < arr.size(); i++) {
        if (min > arr[i])
            min = arr[i];
        if (max < arr[i])
            max = arr[i];
    }
    std::cout << "min: " << min << std::endl;
    std::cout << "max: " << max << std::endl;
}

int RunMatrixBlockExample();
int RunMatrixExample();

int main() {
    RunMatrixBlockExample();
    RunMatrixExample();
}

int RunMatrixBlockExample() {
    std::cout << "----------------------" << std::endl;
    std::cout << "matrix block example started\n";

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    // This is the size of a row in a single matrix ciphertext block. Note that rowSize * rowSize = numSlots.
    size_t rowSize = 32;

    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);

    std::cout << "Scaling mod size: " << parameters.GetScalingModSize() << std::endl;
    std::cout << "First mod size: " << parameters.GetFirstModSize() << std::endl;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetRingDim(1 << 11);
    parameters.SetBatchSize(1 << 10);
    uint32_t depth = 5;
    std::cout << "depth: " << depth << std::endl;
    parameters.SetMultiplicativeDepth(depth);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    int32_t numSlots = cc->GetEncodingParams()->GetBatchSize();
    std::cout << "numSlots = " << numSlots << std::endl;

    std::cout << "Generating Keys" << std::endl;
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    std::set<int32_t> indices;
    for (size_t i = 1; i < rowSize; i++) {
        indices.insert(i);
        indices.insert(-i);
        indices.insert(i * rowSize);
        indices.insert(i - rowSize);
    }
    std::cout << "matrix rotation keys: " << indices.size() << std::endl;

    std::vector<int32_t> indicesList(indices.begin(), indices.end());
    cc->EvalAtIndexKeyGen(keys.secretKey, indicesList);

    std::cout << "Finished generating keys" << std::endl;

    // Perform pre-computations
    struct MatrixMatrixProductPrecomputations precomp = getMatrixMatrixProductPrecomputations(cc, rowSize);

    auto matrix1 = generateRandomMatrix(rowSize, rowSize);
    auto matrix2 = generateRandomMatrix(rowSize, rowSize);

    // matrix block multiplication in the clear
    auto matrixProduct = naiveMatrixMatrixMultiply<double>(matrix1, matrix2);
    auto vecProduct    = extractAndLinearizeMatrixBlock(matrixProduct, numSlots, rowSize);

    auto vec1 = extractAndLinearizeMatrixBlock(matrix1, numSlots, rowSize);

    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(vec1);
    auto ctxt1      = cc->Encrypt(keys.publicKey, ptxt1);

    auto vec2       = extractAndLinearizeMatrixBlock(matrix2, numSlots, rowSize);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(vec2);
    auto ctxt2      = cc->Encrypt(keys.publicKey, ptxt2);

    Ciphertext<DCRTPoly> cResult;

    // encrypted matrix block multiplication
    MatrixMatrixProductSquare<DCRTPoly>(cc, ctxt1, ctxt2, rowSize, cResult, precomp);

    Plaintext result;
    cc->Decrypt(keys.secretKey, cResult, &result);
    std::vector<double> dResult = result->GetRealPackedValue();

    getMaxError(vecProduct, dResult);

    std::cout << "matrix block example terminated gracefully\n";
    return EXIT_SUCCESS;
}

int RunMatrixExample() {
    std::cout << "----------------------" << std::endl;
    std::cout << "matrix example started\n";

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    // This is the size of a row in a single matrix ciphertext block. Note that rowSize * rowSize = numSlots.
    size_t rowSize = 32;

    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);

    std::cout << "Scaling mod size: " << parameters.GetScalingModSize() << std::endl;
    std::cout << "First mod size: " << parameters.GetFirstModSize() << std::endl;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetRingDim(1 << 11);
    parameters.SetBatchSize(1 << 10);
    uint32_t depth = 5;
    std::cout << "depth: " << depth << std::endl;
    parameters.SetMultiplicativeDepth(depth);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    int32_t numSlots = cc->GetEncodingParams()->GetBatchSize();
    std::cout << "numSlots = " << numSlots << std::endl;

    std::cout << "Generating Keys" << std::endl;
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    std::set<int32_t> indices;
    for (size_t i = 1; i < rowSize; i++) {
        indices.insert(i);
        indices.insert(-i);
        indices.insert(i * rowSize);
        indices.insert(i - rowSize);
    }
    std::cout << "matrix rotation keys: " << indices.size() << std::endl;

    std::vector<int32_t> indicesList(indices.begin(), indices.end());
    cc->EvalAtIndexKeyGen(keys.secretKey, indicesList);

    std::cout << "Finished generating keys" << std::endl;

    // Perform pre-computations
    struct MatrixMatrixProductPrecomputations precomp = getMatrixMatrixProductPrecomputations(cc, rowSize);

    size_t rows  = rowSize * 2 + 3;
    size_t cols1 = rowSize * 2 + 5;
    size_t cols2 = rowSize * 2 + 5;

    auto matrix1 = generateRandomMatrix(rows, cols1);
    auto matrix2 = generateRandomMatrix(cols1, cols2);

    auto matrixProduct = naiveMatrixMatrixMultiply<double>(matrix1, matrix2);
    auto vecProduct    = extractAndLinearizeMatrix(matrixProduct, numSlots, rowSize);

    auto mat1 = extractAndLinearizeMatrix(matrix1, numSlots, rowSize);

    auto ctxt1 = EncryptMatrix(mat1, keys.publicKey);

    auto mat2  = extractAndLinearizeMatrix(matrix2, numSlots, rowSize);
    auto ctxt2 = EncryptMatrix(mat2, keys.publicKey);

    std::vector<std::vector<Ciphertext<DCRTPoly>>> cResult;

    MatrixMatrixProduct(ctxt1, ctxt2, rowSize, cResult, precomp);

    auto dResult = DecryptMatrix(cResult, keys.secretKey);

    getMaxErrorMatrix(vecProduct, dResult);

    std::cout << "matrix block example terminated gracefully\n";
    return EXIT_SUCCESS;
}

void getMaxError(std::vector<double> vec1, std::vector<double> vec2) {
    assert(vec1.size() == vec2.size());
    assert(vec1.size() > 0);
    double maxError             = 0;
    double maxRelativeError     = 0;
    double averageError         = 0;
    double averageRelativeError = 0;
    uint32_t count              = 0;
    for (size_t i = 0; i < vec1.size(); i++) {
        double error = abs(vec1[i] - vec2[i]);
        if (maxError < error) {
            maxError = error;
        }
        averageError += error;
        if (vec2[i] != 0) {
            double relativeError = error / abs(vec2[i]);
            if (maxRelativeError < relativeError) {
                maxRelativeError = relativeError;
            }
            averageRelativeError += relativeError;
            count += 1;
        }
    }
    averageError /= vec1.size();
    averageRelativeError /= count;

    std::cout << "Max absolute error: " << maxError << std::endl;
    std::cout << "Max relative error: " << maxRelativeError << std::endl;
    std::cout << "Average absolute error: " << averageError << std::endl;
    std::cout << "Average relative error: " << averageRelativeError << std::endl;
    std::cout << "----------------------" << std::endl;
}

void getMaxErrorMatrix(const std::vector<std::vector<std::vector<double>>>& vec1,
                       const std::vector<std::vector<std::vector<double>>>& vec2) {
    for (size_t i = 0; i < vec1.size(); i++) {
        for (size_t j = 0; j < vec1[0].size(); j++) {
            std::cerr << "Matrix Block [" << i << "][" << j << "]:" << std::endl;
            getMaxError(vec1[i][j], vec2[i][j]);
        }
    }
}

// Helper methods to get permutation matrices for matrix multiplication
template <typename Element>
std::vector<std::vector<Element>> getDiagonals(std::vector<std::vector<Element>> matrix) {
    size_t diagonalLength = matrix.size();
    if (diagonalLength == 0) {
        return std::vector<std::vector<Element>>();
    }
    size_t numDiagonals = matrix[0].size();

    std::vector<std::vector<Element>> diagonals;
    for (size_t j = 0; j < numDiagonals; j++) {
        std::vector<Element> diagonal;
        for (size_t i = 0; i < diagonalLength; i++) {
            diagonal.emplace_back(matrix[i][(i + j) % numDiagonals]);
        }
        diagonals.emplace_back(diagonal);
    }
    return diagonals;
}

template <typename Element>
std::vector<Element> naiveMatrixVectorMultiply(std::vector<std::vector<Element>> matrix, std::vector<Element> vec) {
    std::vector<Element> product;
    for (size_t i = 0; i < matrix.size(); i++) {
        Element dotProd = 0;
        for (size_t j = 0; j < vec.size(); j++) {
            dotProd += matrix[i][j] * vec[j];
        }
        product.emplace_back(dotProd);
    }
    return product;
}

template <typename Element>
std::vector<Element> naiveMatrixVectorMultiply(std::vector<Element> matrix, int numRows, std::vector<Element> vec) {
    std::vector<Element> product;
    for (size_t i = 0; i < (size_t)numRows; i++) {
        Element dotProd = 0;
        for (size_t j = 0; j < vec.size(); j++) {
            dotProd += matrix[i * vec.size() + j] * vec[j];
        }
        product.emplace_back(dotProd);
    }
    return product;
}

template <typename Element>
std::vector<std::vector<Element>> naiveMatrixMatrixMultiply(std::vector<std::vector<Element>> matrix1,
                                                            std::vector<std::vector<Element>> matrix2) {
    std::vector<std::vector<Element>> product;
    for (size_t i = 0; i < matrix1.size(); i++) {
        std::vector<Element> row;
        for (size_t j = 0; j < matrix2[0].size(); j++) {
            Element dotProd = 0;
            for (size_t k = 0; k < matrix2.size(); k++) {
                dotProd += matrix1[i][k] * matrix2[k][j];
            }
            row.emplace_back(dotProd);
        }
        product.emplace_back(row);
    }
    return product;
}

template <typename Element>
std::vector<std::vector<Element>> naiveMatrixMatrixMultiply(std::vector<Element> matrix1, std::vector<Element> matrix2,
                                                            size_t numRows1, size_t numCols1, size_t numCols2) {
    std::vector<std::vector<Element>> product;
    for (size_t i = 0; i < numRows1; i++) {
        std::vector<Element> row;
        for (size_t j = 0; j < numCols2; j++) {
            Element dotProd = 0;
            for (size_t k = 0; k < numCols1; k++) {
                dotProd += matrix1[i * numCols1 + k] * matrix2[k * numCols2 + j];
            }
            row.emplace_back(dotProd);
        }
        product.emplace_back(row);
    }
    return product;
}

std::vector<std::vector<double>> getSigmaPermutationMatrix(size_t rowSize) {
    std::vector<std::vector<double>> sigma(rowSize * rowSize, std::vector<double>(rowSize * rowSize, 0));
    ;
    for (size_t i = 0; i < rowSize; i++) {
        for (size_t j = 0; j < rowSize; j++) {
            size_t rowIndex           = rowSize * i + j;
            size_t colIndex           = rowSize * i + ((i + j) % rowSize);
            sigma[rowIndex][colIndex] = 1;
        }
    }
    return sigma;
}

std::vector<std::vector<double>> getTauPermutationMatrix(size_t rowSize) {
    std::vector<std::vector<double>> tau(rowSize * rowSize, std::vector<double>(rowSize * rowSize, 0));
    ;
    for (size_t i = 0; i < rowSize; i++) {
        for (size_t j = 0; j < rowSize; j++) {
            size_t rowIndex         = rowSize * i + j;
            size_t colIndex         = rowSize * ((i + j) % rowSize) + j;
            tau[rowIndex][colIndex] = 1;
        }
    }
    return tau;
}

std::vector<std::vector<double>> getPhiDiagonals(size_t rowSize, size_t numRotations) {
    std::vector<std::vector<double>> phiDiagonals(2, std::vector<double>(rowSize * rowSize, 0));
    ;
    for (size_t i = 0; i < rowSize * rowSize; i++) {
        if (i % rowSize < rowSize - numRotations) {
            phiDiagonals[0][i] = 1;
        }
    }

    for (size_t i = 0; i < rowSize * rowSize; i++) {
        if (rowSize - numRotations <= i % rowSize && i % rowSize < rowSize) {
            phiDiagonals[1][i] = 1;
        }
    }
    return phiDiagonals;
}

// Square matrix multiplication
// TODO: There seems to be a bug with the Baby-Step Giant-Step version below.
template <typename Element>
void MatrixMatrixProductSquareBSGS(CryptoContext<DCRTPoly>& context, Ciphertext<Element>& cMat1,
                                   Ciphertext<Element>& cMat2, uint32_t rowSize, Ciphertext<Element>& cProduct,
                                   struct MatrixMatrixProductPrecomputations precomp) {
    int sqrtRowSize = (int)ceil(std::sqrt(rowSize));

    std::vector<Ciphertext<Element>> rotations1;
    std::vector<Ciphertext<Element>> rotations2;
    for (int j = 0; j < sqrtRowSize; j++) {
        auto rotatedCt = context->EvalAtIndex(cMat1, j);
        rotations1.emplace_back(rotatedCt);
        rotatedCt = context->EvalAtIndex(cMat2, j * rowSize);
        rotations2.emplace_back(rotatedCt);
    }

    Ciphertext<Element> linearTransform1;
    int count = 0;
    for (int i = -sqrtRowSize; i < sqrtRowSize; i++) {
        int index          = sqrtRowSize * i;
        int rotationAmount = sqrtRowSize * i;
        Ciphertext<Element> sumCt;
        if (index > -(int)rowSize) {
            sumCt = context->EvalMult(cMat1, precomp.sigmaPlaintexts[count]);
        }
        count++;
        for (int j = 1; j < sqrtRowSize; j++) {
            index = sqrtRowSize * i + j;
            if (index <= -(int)rowSize || index >= (int)rowSize)
                continue;
            auto productCt = context->EvalMult(rotations1[j], precomp.sigmaPlaintexts[count]);
            if (!sumCt)
                sumCt = productCt;
            context->EvalAddInPlace(sumCt, productCt);
            count++;
        }
        auto finalRotatedCt = context->EvalAtIndex(sumCt, rotationAmount);
        if (linearTransform1)
            context->EvalAddInPlace(linearTransform1, finalRotatedCt);
        else
            linearTransform1 = finalRotatedCt;
    }

    // Step 1-2
    Ciphertext<Element> linearTransform2;
    count = 0;
    for (int i = 0; i < sqrtRowSize; i++) {
        int rotationAmount = sqrtRowSize * i * rowSize;
        auto sumCt         = context->EvalMult(cMat2, precomp.tauPlaintexts[count]);
        count++;
        for (int j = 1; j < sqrtRowSize; j++) {
            int index = sqrtRowSize * i + j;
            if (index >= (int)rowSize)
                continue;
            auto productCt = context->EvalMult(rotations2[j], precomp.tauPlaintexts[count]);
            context->EvalAddInPlace(sumCt, productCt);
            count++;
        }
        auto finalRotatedCt = context->EvalAtIndex(sumCt, rotationAmount);
        if (linearTransform2)
            context->EvalAddInPlace(linearTransform2, finalRotatedCt);
        else
            linearTransform2 = finalRotatedCt;
    }

    // Steps 2 and 3
    cProduct = context->EvalMult(linearTransform1, linearTransform2);

    for (size_t i = 1; i < rowSize; i++) {
        // Step 2
        auto rotatedCt  = context->EvalAtIndex(linearTransform1, i);
        auto productCt1 = context->EvalMult(rotatedCt, precomp.phiPlaintexts[i][0]);

        rotatedCt               = context->EvalAtIndex(linearTransform1, i - rowSize);
        auto productCt2         = context->EvalMult(rotatedCt, precomp.phiPlaintexts[i][1]);
        auto linearTransformPhi = context->EvalAdd(productCt1, productCt2);

        auto linearTransformPsi = context->EvalAtIndex(linearTransform2, i * rowSize);

        // Step 3
        auto tempProduct = context->EvalMult(linearTransformPhi, linearTransformPsi);
        cProduct         = context->EvalAdd(cProduct, tempProduct);
    }
}

struct MatrixMatrixProductPrecomputations getMatrixMatrixProductPrecomputations(CryptoContext<DCRTPoly>& context,
                                                                                int rowSize) {
    std::vector<std::vector<double>> sigmaDiagonals = getDiagonals(getSigmaPermutationMatrix(rowSize));
    std::vector<std::vector<double>> tauDiagonals   = getDiagonals(getTauPermutationMatrix(rowSize));

    std::vector<Plaintext> sigmaPlaintexts;
    std::vector<Plaintext> tauPlaintexts;
    std::vector<std::vector<Plaintext>> phiPlaintexts;

    for (int i = 0; i < rowSize * rowSize; i++) {
        Plaintext ptxtSigma = context->MakeCKKSPackedPlaintext(sigmaDiagonals[i]);
        sigmaPlaintexts.emplace_back(ptxtSigma);
        Plaintext ptxtTau = context->MakeCKKSPackedPlaintext(tauDiagonals[i]);
        tauPlaintexts.emplace_back(ptxtTau);
    }
    for (int i = 0; i < rowSize; i++) {
        std::vector<std::vector<double>> phi = getPhiDiagonals(rowSize, i);
        Plaintext ptxtPhi1                   = context->MakeCKKSPackedPlaintext(phi[0]);
        Plaintext ptxtPhi2                   = context->MakeCKKSPackedPlaintext(phi[1]);
        std::vector<Plaintext> phiVec        = {ptxtPhi1, ptxtPhi2};
        phiPlaintexts.emplace_back(phiVec);
    }

    struct MatrixMatrixProductPrecomputations precomp;
    precomp.rowSize         = rowSize;
    precomp.sigmaPlaintexts = sigmaPlaintexts;
    precomp.tauPlaintexts   = tauPlaintexts;
    precomp.phiPlaintexts   = phiPlaintexts;

    return precomp;
}

template <typename Element>
void MatrixMatrixProductSquare(CryptoContext<DCRTPoly>& context, Ciphertext<Element>& cMat1, Ciphertext<Element>& cMat2,
                               uint32_t rowSize, Ciphertext<Element>& cProduct,
                               struct MatrixMatrixProductPrecomputations precomp) {
    auto linearTransform1 = context->EvalMult(cMat1, precomp.sigmaPlaintexts[0]);
    for (size_t i = 1; i < rowSize; i++) {
        auto rotatedCt = context->EvalAtIndex(cMat1, i);
        // TODO: Fast rotations
        //auto decompose = context->EvalFastRotationPrecompute(cMat1);
        //usint m = context->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
        //auto rotatedCt = context->EvalFastRotation(cMat1, i, m, decompose);
        auto productCt   = context->EvalMult(rotatedCt, precomp.sigmaPlaintexts[i]);
        linearTransform1 = context->EvalAdd(linearTransform1, productCt);

        rotatedCt = context->EvalAtIndex(cMat1, -i);
        //rotatedCt = context->EvalFastRotation(cMat1, -i, m, decompose);
        productCt        = context->EvalMult(rotatedCt, precomp.sigmaPlaintexts[rowSize * rowSize - i]);
        linearTransform1 = context->EvalAdd(linearTransform1, productCt);
    }

    // Step 1-2
    auto linearTransform2 = context->EvalMult(cMat2, precomp.tauPlaintexts[0]);
    for (size_t i = 1; i < rowSize; i++) {
        auto rotatedCt = context->EvalAtIndex(cMat2, i * rowSize);
        //auto decompose = context->EvalFastRotationPrecompute(cMat2);
        //usint m = context->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
        //auto rotatedCt = context->EvalFastRotation(cMat2, i * rowSize, m, decompose);
        auto productCt   = context->EvalMult(rotatedCt, precomp.tauPlaintexts[i * rowSize]);
        linearTransform2 = context->EvalAdd(linearTransform2, productCt);
    }

    // Steps 2 and 3

    cProduct = context->EvalMult(linearTransform1, linearTransform2);

    for (size_t i = 1; i < rowSize; i++) {
        // Step 2
        auto rotatedCt = context->EvalAtIndex(linearTransform1, i);
        //auto decompose = context->EvalFastRotationPrecompute(linearTransform1);
        //usint m = context->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
        //auto rotatedCt = context->EvalFastRotation(linearTransform1, i, m, decompose);

        auto productCt1 = context->EvalMult(rotatedCt, precomp.phiPlaintexts[i][0]);

        rotatedCt = context->EvalAtIndex(linearTransform1, i - rowSize);
        //rotatedCt = context->EvalFastRotation(linearTransform1, i - rowSize, m, decompose);
        auto productCt2         = context->EvalMult(rotatedCt, precomp.phiPlaintexts[i][1]);
        auto linearTransformPhi = context->EvalAdd(productCt1, productCt2);

        auto linearTransformPsi = context->EvalAtIndex(linearTransform2, i * rowSize);
        //decompose = context->EvalFastRotationPrecompute(linearTransform2);
        //auto linearTransformPsi = context->EvalFastRotation(linearTransform2, i * rowSize, m, decompose);

        // Step 3
        auto tempProduct = context->EvalMult(linearTransformPhi, linearTransformPsi);
        cProduct         = context->EvalAdd(cProduct, tempProduct);
    }
}

// matrix multiplication
void MatrixMatrixProduct(std::vector<std::vector<Ciphertext<DCRTPoly>>>& matrix1,
                         std::vector<std::vector<Ciphertext<DCRTPoly>>>& matrix2, uint32_t rowSize,
                         std::vector<std::vector<Ciphertext<DCRTPoly>>>& product,
                         struct MatrixMatrixProductPrecomputations precomp) {
    auto cc = matrix1[0][0]->GetCryptoContext();
    for (size_t i = 0; i < matrix1.size(); i++) {
        std::vector<Ciphertext<DCRTPoly>> row;
        for (size_t j = 0; j < matrix2[0].size(); j++) {
            Ciphertext<DCRTPoly> dotProd;
            MatrixMatrixProductSquare<DCRTPoly>(cc, matrix1[i][0], matrix2[0][j], rowSize, dotProd, precomp);
            for (size_t k = 1; k < matrix2.size(); k++) {
                Ciphertext<DCRTPoly> dotProdNew;
                MatrixMatrixProductSquare<DCRTPoly>(cc, matrix1[i][k], matrix2[k][j], rowSize, dotProdNew, precomp);
                cc->EvalAddInPlace(dotProd, dotProdNew);
            }
            row.emplace_back(dotProd);
        }
        product.emplace_back(row);
    }
}

std::vector<std::vector<double>> generateRandomMatrix(size_t numRows, size_t numCols) {
    std::vector<std::vector<double>> matrix;

    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);
    for (size_t i = 0; i < numRows; i++) {
        for (size_t k = 0; k < numCols; k++) {
            x.emplace_back(dis(gen));
        }
        matrix.emplace_back(x);
        x.clear();
    }

    return matrix;
}

std::vector<double> extractAndLinearizeMatrixBlock(std::vector<std::vector<double>> matrix, size_t numSlots,
                                                   size_t rowSize, size_t offsetRows, size_t offsetCols) {
    std::vector<double> vec(numSlots, 0.0);
    size_t endRows = (offsetRows + rowSize > matrix.size()) ? matrix.size() : offsetRows + rowSize;
    size_t endCols = (offsetCols + rowSize > matrix[0].size()) ? matrix[0].size() : offsetCols + rowSize;
    for (size_t i = offsetRows; i < endRows; i++) {
        for (size_t j = offsetCols; j < endCols; j++) {
            vec[(i - offsetRows) * rowSize + (j - offsetCols)] = matrix[i][j];
        }
    }
    return vec;
}

std::vector<std::vector<std::vector<double>>> extractAndLinearizeMatrix(const std::vector<std::vector<double>>& matrix,
                                                                        size_t numSlots, size_t rowSize) {
    size_t numBlockRows = std::ceil((double)matrix.size() / rowSize);
    size_t numBlockCols = std::ceil((double)matrix[0].size() / rowSize);
    std::vector<std::vector<std::vector<double>>> mat(numBlockRows);
    for (size_t i = 0; i < numBlockRows; i++) {
        mat[i] = std::vector<std::vector<double>>(numBlockCols);
        for (size_t j = 0; j < numBlockCols; j++) {
            mat[i][j] = extractAndLinearizeMatrixBlock(matrix, numSlots, rowSize, i * rowSize, j * rowSize);
        }
    }
    return mat;
}

std::vector<std::vector<Ciphertext<DCRTPoly>>> EncryptMatrix(
    const std::vector<std::vector<std::vector<double>>>& matrix, PublicKey<DCRTPoly> publicKey) {
    std::vector<std::vector<Ciphertext<DCRTPoly>>> ctMatrix(matrix.size());
    auto cc = publicKey->GetCryptoContext();
    for (size_t i = 0; i < matrix.size(); i++) {
        for (size_t j = 0; j < matrix[0].size(); j++) {
            Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(matrix[i][j]);
            ctMatrix[i].emplace_back(cc->Encrypt(publicKey, ptxt1));
        }
    }
    return ctMatrix;
}

std::vector<std::vector<std::vector<double>>> DecryptMatrix(
    const std::vector<std::vector<Ciphertext<DCRTPoly>>>& matrix, PrivateKey<DCRTPoly> privateKey) {
    std::vector<std::vector<std::vector<double>>> ptMatrix(matrix.size());
    Plaintext result;
    auto cc = privateKey->GetCryptoContext();
    for (size_t i = 0; i < matrix.size(); i++) {
        for (size_t j = 0; j < matrix[0].size(); j++) {
            cc->Decrypt(privateKey, matrix[i][j], &result);
            ptMatrix[i].emplace_back(result->GetRealPackedValue());
        }
    }
    return ptMatrix;
}
