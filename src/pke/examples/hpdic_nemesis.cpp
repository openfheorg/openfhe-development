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
#include <chrono>
#include "openfhe.h"
#include "cnpy.h"
#include "math/discretegaussiangenerator.h"  // 确保包含高斯生成器头文件

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    // parameters.SetMultiplicativeDepth(2);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetBatchSize(1);  // 设置 batch size 为 1，关闭批处理

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

    // std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    // std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    // std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // Output results
    // std::cout << "\nResults of homomorphic computations" << std::endl;
    // std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
    // std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;
    // std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
    // std::cout << "Left rotation of #1 by 2: " << plaintextRot2 << std::endl;
    // std::cout << "Right rotation of #1 by 1: " << plaintextRot3 << std::endl;
    // std::cout << "Right rotation of #1 by 2: " << plaintextRot4 << std::endl;

    // std::cout << std::endl;
    // std::cout << "===== HPDIC ===== " << std::endl;
    // std::cout << std::endl;

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

    std::cout << "Encrypting " << sz_array << " floating numbers." << std::endl;

    std::vector<int64_t> hpdic_vec1 = {2};
    Plaintext hpdic_pt1             = cryptoContext->MakePackedPlaintext(hpdic_vec1);
    auto hpdic_ct1                  = cryptoContext->Encrypt(keyPair.publicKey, hpdic_pt1);
    std::cout << "Plaintext hpdic_vec1: " << hpdic_vec1 << std::endl;

    auto start = std::chrono::high_resolution_clock::now();

    // Caching
    auto prod_c1_and_p1 = cryptoContext->EvalMult(hpdic_ct1, hpdic_pt1);

    // TODO BEGIN
    // Step 1: 获取密文的分量
    auto elements = prod_c1_and_p1->GetElements();  // 分量 c0 和 c1

    // Step 2: 确保分量格式一致
    auto& c0 = elements[0];
    auto& c1 = elements[1];
    c0.SetFormat(Format::COEFFICIENT);
    c1.SetFormat(Format::COEFFICIENT);

    const auto cryptoParams = cryptoContext->GetCryptoParameters();
    NativeInteger q         = c0.GetParams()->GetModulus();  // 获取模数 q

    DCRTPoly newC0 = c0;
    DCRTPoly newC1 = c1;

    // Step 3: 添加噪声
    for (size_t i = 0; i < c0.GetNumOfElements(); ++i) {
        const auto& nativePolyC0 = c0.GetElementAtIndex(i);
        const auto& nativePolyC1 = c1.GetElementAtIndex(i);

        NativePoly updatedPolyC0 = nativePolyC0;
        NativePoly updatedPolyC1 = nativePolyC1;

        for (size_t j = 0; j < updatedPolyC0.GetLength(); ++j) {
            // 添加小范围噪声
            auto noise = NativeInteger((rand() % 3) - 1);  // 噪声范围 [-1, 0, +1]

            // 修改 c0 的系数
            updatedPolyC0[j] = (updatedPolyC0[j] + noise) % q;

            // 修改 c1 的系数，确保解密公式平衡
            updatedPolyC1[j] = (updatedPolyC1[j] - noise) % q;  // 校正项
        }

        newC0.SetElementAtIndex(i, updatedPolyC0);
        newC1.SetElementAtIndex(i, updatedPolyC1);
    }

    newC0.SetFormat(Format::EVALUATION);
    newC1.SetFormat(Format::EVALUATION);

    // Step 4: 替换密文分量并更新 prod_c1_and_p1
    elements[0] = newC0;
    elements[1] = newC1;
    prod_c1_and_p1->SetElements(elements);

    std::cout << "Modified c0 and c1 directly on polynomial level while maintaining decryptability." << std::endl;

    //TODO END

    auto end                 = std::chrono::high_resolution_clock::now();
    auto duration            = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Nemesis time taken for multi-cache: " << duration.count() << " microseconds" << std::endl;

    // Step 1: 解密密文
    Plaintext decryptedPt;
    cryptoContext->Decrypt(keyPair.secretKey, prod_c1_and_p1, &decryptedPt);

    // Step 2: 提取第一个 slot 的值
    auto packedValues = decryptedPt->GetPackedValue();  // 获取所有槽位的明文值
    if (!packedValues.empty()) {
        std::cout << "Value of the first slot: " << packedValues[0] << std::endl;
    }
    else {
        std::cout << "Decrypted plaintext is empty!" << std::endl;
    }

    std::vector<int64_t> hpdic_vec2 = {8};
    Plaintext hpdic_pt2             = cryptoContext->MakePackedPlaintext(hpdic_vec2);
    start                           = std::chrono::high_resolution_clock::now();
    auto hpdic_ct2                  = cryptoContext->Encrypt(keyPair.publicKey, hpdic_pt2);
    end                             = std::chrono::high_resolution_clock::now();
    duration                        = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "OpenFHE time taken for homoencrypt: " << duration.count() << " microseconds" << std::endl;

    return 0;
}
