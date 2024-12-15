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

/*
  HPDIC example to encrypt neural network model weights
 */

#include <iostream>
#include <string>
#include "openfhe.h"
#include "cnpy.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    // Sample Program: Step 3: Encryption

    // First plaintext vector is encoded
    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    // Second plaintext vector is encoded
    std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);
    // Third plaintext vector is encoded
    std::vector<int64_t> vectorOfInts3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext3               = cryptoContext->MakePackedPlaintext(vectorOfInts3);

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
    auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);

    // Sample Program: Step 4: Evaluation

    // Homomorphic additions
    auto ciphertextAdd12     = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
    auto ciphertextAddResult = cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);

    // Homomorphic multiplications
    auto ciphertextMul12      = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    auto ciphertextMultResult = cryptoContext->EvalMult(ciphertextMul12, ciphertext3);

    // Homomorphic rotations
    auto ciphertextRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
    auto ciphertextRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
    auto ciphertextRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
    auto ciphertextRot4 = cryptoContext->EvalRotate(ciphertext1, -2);

    // Sample Program: Step 5: Decryption

    // Decrypt the result of additions
    Plaintext plaintextAddResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult, &plaintextAddResult);

    // Decrypt the result of multiplications
    Plaintext plaintextMultResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult, &plaintextMultResult);

    // Decrypt the result of rotations
    Plaintext plaintextRot1;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
    Plaintext plaintextRot2;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
    Plaintext plaintextRot3;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &plaintextRot3);
    Plaintext plaintextRot4;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &plaintextRot4);

    plaintextRot1->SetLength(vectorOfInts1.size());
    plaintextRot2->SetLength(vectorOfInts1.size());
    plaintextRot3->SetLength(vectorOfInts1.size());
    plaintextRot4->SetLength(vectorOfInts1.size());

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
    std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;
    std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
    std::cout << "Left rotation of #1 by 2: " << plaintextRot2 << std::endl;
    std::cout << "Right rotation of #1 by 1: " << plaintextRot3 << std::endl;
    std::cout << "Right rotation of #1 by 2: " << plaintextRot4 << std::endl;

    std::cout << std::endl;
    std::cout << "===== HPDIC ===== " << std::endl;
    std::cout << std::endl;

    /**
     * HPDIC: Load model data in numpy, e.g., ~/PFLlib/results/numpy_MNIST.npy
     */
    // 默认文件路径
    std::string default_path = "/home/cc/PFLlib/results/numpy_MNIST.npy";

    // 提示用户输入文件路径
    std::cout << "Enter the path to the .npy file (Press Enter to use default): ";
    std::string input_path;
    std::getline(std::cin, input_path);

    // 使用用户输入路径或默认路径
    std::string file_path = input_path.empty() ? default_path : input_path;
    std::cout << "Using file path: " << file_path << std::endl;

    float* data;
    size_t sz_array = 0;

    try {
        // 加载 .npy 文件
        cnpy::NpyArray my_npz = cnpy::npy_load(file_path);

        // 获取数据指针并转换为适当的类型（numpy里面是float32）
        data = my_npz.data<float>();

        // 获取数组的形状
        std::vector<size_t> shape = my_npz.shape;

        // 打印数组的维度
        std::cout << "Shape: ";
        for (size_t dim : shape) {
            std::cout << dim << " ";
            sz_array = dim;
        }
        std::cout << std::endl;

        // 打印前 3 个和后 3 个值
        size_t total_elements = 1;
        for (size_t dim : shape) {
            total_elements *= dim;  // 计算总元素数
        }

        std::cout << "First 3 values: ";
        for (size_t i = 0; i < std::min(total_elements, static_cast<size_t>(3)); ++i) {
            std::cout << data[i] << " ";
        }
        std::cout << std::endl;

        std::cout << "Last 3 values: ";
        for (size_t i = total_elements > 3 ? total_elements - 3 : 0; i < total_elements; ++i) {
            std::cout << data[i] << " ";
        }
        std::cout << std::endl;
    }
    catch (const std::exception& e) {
        // 捕获并处理加载文件时的异常
        std::cerr << "Error loading file: " << e.what() << std::endl;
        return 1;
    }

    // TODO
    std::cout << "Encrypting " << sz_array << " floating numbers." << std::endl;
    auto p1_pack = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    auto prod_c1_and_p1_pack = cryptoContext->EvalMult(ciphertext1, p1_pack);
    Plaintext p1_sqr;
    cryptoContext->Decrypt(keyPair.secretKey, prod_c1_and_p1_pack, &p1_sqr);
    std::cout << "#1 * #1" << p1_sqr << std::endl;

    return 0;
}
