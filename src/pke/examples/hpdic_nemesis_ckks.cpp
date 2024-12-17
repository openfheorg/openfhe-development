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

HPDIC Nemesis MOD

*/

#define PROFILE

#include <chrono>
#include <iostream>
#include "cnpy.h"
#include "openfhe.h"

using namespace lbcrypto;
using namespace std::chrono;  // 引用 std::chrono 命名空间

/**
 * Function: EncryptWithNoise
 * Description: 每次处理 numSlots 数据，将其与 vec_base 进行乘法，并添加随机高斯噪声。
 * Inputs:
 *   - cryptoContext: CKKS 加密上下文
 *   - publicKey: 公钥
 *   - data: 输入数据向量
 *   - vec_base: 预定义的密文，含有 numSlots 个 1
 *   - numSlots: 每次处理的槽位数量
 *   - gaussianStdDev: 高斯噪声标准差
 * Outputs:
 *   - std::vector<Ciphertext<DCRTPoly>>: 生成的密文列表
 */
std::vector<Ciphertext<DCRTPoly>> EncryptWithNoise(CryptoContext<DCRTPoly> cryptoContext,
                                                   const PublicKey<DCRTPoly>& publicKey,
                                                   const std::vector<float>& data,
                                                   const Ciphertext<DCRTPoly>& vec_base, size_t numSlots,
                                                   double gaussianStdDev) {
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;

    // 初始化高斯噪声生成器
    DiscreteGaussianGeneratorImpl<NativeVector> dgg(gaussianStdDev);

    size_t totalDataSize = data.size();
    size_t numBatches    = (totalDataSize + numSlots - 1) / numSlots;  // 计算批次数量

    for (size_t batch = 0; batch < numBatches; ++batch) {
        // 1. 从数据中提取 numSlots 个元素（不足时补 0）
        std::vector<double> batchData(numSlots, 0.0);
        size_t startIdx = batch * numSlots;
        for (size_t i = 0; i < numSlots && (startIdx + i) < totalDataSize; ++i) {
            batchData[i] = data[startIdx + i];
        }

        // 2. 创建明文并加密
        Plaintext ptxt  = cryptoContext->MakeCKKSPackedPlaintext(batchData, 1, 0);
        auto ct_product = cryptoContext->EvalMult(ptxt, vec_base);

        // 3. 提取 c0 和 c1 分量
        auto elements = ct_product->GetElements();
        DCRTPoly c0   = elements[0];
        DCRTPoly c1   = elements[1];

        const auto cryptoParams  = cryptoContext->GetCryptoParameters();
        const auto elementParams = c0.GetParams();
        const auto numTowers     = elementParams->GetParams().size();

        // 4. 构建随机噪声 DCRTPoly
        DCRTPoly randomNoise(elementParams, Format::COEFFICIENT);
        for (size_t i = 0; i < numTowers; ++i) {
            auto ringDim = elementParams->GetParams()[i]->GetRingDimension();
            auto modulus = elementParams->GetParams()[i]->GetModulus();

            NativeVector noiseVector = dgg.GenerateVector(ringDim, modulus);
            NativePoly noisePoly(elementParams->GetParams()[i], Format::COEFFICIENT);
            noisePoly.SetValues(noiseVector, Format::COEFFICIENT);

            randomNoise.SetElementAtIndex(i, noisePoly);
        }
        randomNoise.SetFormat(Format::EVALUATION);

        // 5. 修改密文的 c0 和 c1 分量
        DCRTPoly newC0 = c0 + randomNoise;
        DCRTPoly newC1 = c1 - randomNoise;

        elements[0] = newC0;
        elements[1] = newC1;

        ct_product->SetElements(elements);

        // 6. 保存处理后的密文
        ciphertexts.push_back(ct_product);
    }

    return ciphertexts;
}

/**
 * Function: LoadNumpyFile
 * Description: 加载一个 .npy 文件，并返回数据作为 std::vector<float>。
 * Inputs:
 *   - file_path: std::string - 指定 .npy 文件的路径。
 * Outputs:
 *   - std::vector<float> - 包含文件中所有浮点数数据的向量。
 */
std::vector<float> LoadNumpyFile(const std::string& file_path) {
    std::vector<float> data_vector;

    try {
        // 加载 .npy 文件
        cnpy::NpyArray my_npz = cnpy::npy_load(file_path);

        // 获取数据指针并转换为 float 类型
        float* data = my_npz.data<float>();

        // 获取数组的总元素数
        size_t total_elements = 1;
        for (size_t dim : my_npz.shape) {
            total_elements *= dim;
        }

        // 将数据复制到 std::vector
        data_vector.assign(data, data + total_elements);

        // 打印数组的维度
        std::cout << "Shape: ";
        for (size_t dim : my_npz.shape) {
            std::cout << dim << " ";
        }
        std::cout << std::endl;

        // 打印前 3 个和后 3 个值
        std::cout << "First 3 values: ";
        for (size_t i = 0; i < std::min(total_elements, static_cast<size_t>(3)); ++i) {
            std::cout << data_vector[i] << " ";
        }
        std::cout << std::endl;

        std::cout << "Last 3 values: ";
        for (size_t i = total_elements > 3 ? total_elements - 3 : 0; i < total_elements; ++i) {
            std::cout << data_vector[i] << " ";
        }
        std::cout << std::endl;

        std::cout << "Successfully loaded " << total_elements << " floating-point numbers." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error loading file: " << e.what() << std::endl;
    }

    return data_vector;
}

void SimpleBootstrapExample();

int main(int argc, char* argv[]) {

    CCParams<CryptoContextCKKSRNS> parameters;
    // A. Specify main parameters
    /*  A1) Secret key distribution
    * The secret key distribution for CKKS should either be SPARSE_TERNARY or UNIFORM_TERNARY.
    * The SPARSE_TERNARY distribution was used in the original CKKS paper,
    * but in this example, we use UNIFORM_TERNARY because this is included in the homomorphic
    * encryption standard.
    */
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    /*  A2) Desired security level based on FHE standards.
    * In this example, we use the "NotSet" option, so the example can run more quickly with
    * a smaller ring dimension. Note that this should be used only in
    * non-production environments, or by experts who understand the security
    * implications of their choices. In production-like environments, we recommend using
    * HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
    * or 256-bit security, respectively. If you choose one of these as your security level,
    * you do not need to set the ring dimension.
    */
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

    /*  A3) Scaling parameters.
    * By default, we set the modulus sizes and rescaling technique to the following values
    * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
    * below unless you are an FHE expert.
    */
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    ScalingTechnique rescaleTech = FIXEDAUTO;
    usint dcrtBits               = 78;
    usint firstMod               = 89;
#else
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits               = 59;
    usint firstMod               = 60;
#endif

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    /*  A4) Multiplicative depth.
    * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
    * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
    * needs to consume a few levels to run. We compute the number of bootstrapping levels required
    * using GetBootstrapDepth, and add it to levelsAvailableAfterBootstrap to set our initial multiplicative
    * depth. We recommend using the input parameters below to get started.
    */
    std::vector<uint32_t> levelBudget = {4, 4};

    // Note that the actual number of levels avalailable after bootstrapping before next bootstrapping 
    // will be levelsAvailableAfterBootstrap - 1 because an additional level
    // is used for scaling the ciphertext before next bootstrapping (in 64-bit CKKS bootstrapping)
    uint32_t levelsAvailableAfterBootstrap = 10;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint ringDim = cryptoContext->GetRingDimension();
    // This is the maximum number of slots that can be used for full packing.
    usint numSlots = ringDim / 2;
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;

    cryptoContext->EvalBootstrapSetup(levelBudget);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    size_t encodedLength  = x.size();

    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1);

    ptxt->SetLength(encodedLength);
    std::cout << "Input: " << ptxt << std::endl;

    auto start                = high_resolution_clock::now();  // 开始时间戳
    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);
    auto end                  = high_resolution_clock::now();  // 结束时间戳
    auto duration             = duration_cast<microseconds>(end - start).count();
    std::cout << "OpenFHE CKKS Encryption time: " << duration << " microseconds" << std::endl;

    // TODO: Multiplicative CKKS
    // Construct the base
    std::vector<double> vec_base(numSlots, 1.0);
    Plaintext pt_base            = cryptoContext->MakeCKKSPackedPlaintext(vec_base, 1, depth - 1);
    ciph                         = cryptoContext->Encrypt(keyPair.publicKey, pt_base);
    double gaussianStdDev = 0.1;  // 默认值
    if (argc > 1) {
        gaussianStdDev = std::atof(argv[1]);  // 将命令行输入转换为浮点数
        if (gaussianStdDev <= 0) {
            std::cerr << "Invalid Gaussian standard deviation. Using default value: 0.1" << std::endl;
            gaussianStdDev = 0.1;
        }
    }
    std::cout << "Using Gaussian standard deviation: " << gaussianStdDev << std::endl;
    DiscreteGaussianGeneratorImpl<NativeVector> dgg(gaussianStdDev);  // 高斯噪声标准差

    start = high_resolution_clock::now();  // 开始时间戳

    // Construct the ciphertext through multiplicative caching
    auto ct_product = cryptoContext->EvalMult(ptxt, ciph);
    /***********************
     * BEGIN Randomization
     */

    // Step 1: 提取密文分量
    auto elements = ct_product->GetElements();
    DCRTPoly c0   = elements[0];
    DCRTPoly c1   = elements[1];

    // Step 2: 获取参数
    const auto cryptoParams  = cryptoContext->GetCryptoParameters();
    const auto elementParams = c0.GetParams();
    const auto numTowers     = elementParams->GetParams().size();  // CRT 塔的数量

    // Step 4: 构建随机噪声 DCRTPoly
    DCRTPoly randomNoise(elementParams, Format::COEFFICIENT);

    for (size_t i = 0; i < numTowers; ++i) {
        auto ringDim = elementParams->GetParams()[i]->GetRingDimension();
        auto modulus = elementParams->GetParams()[i]->GetModulus();

        // 使用高斯生成器生成 NativeVector 类型的噪声向量
        NativeVector noiseVector = dgg.GenerateVector(ringDim, modulus);

        // 创建 NativePoly 并设置噪声值
        NativePoly noisePoly(elementParams->GetParams()[i], Format::COEFFICIENT);
        noisePoly.SetValues(noiseVector, Format::COEFFICIENT);

        // 更新 DCRTPoly 的对应塔
        randomNoise.SetElementAtIndex(i, noisePoly);
    }

    // **将随机噪声转换为 EVALUATION 格式**
    randomNoise.SetFormat(Format::EVALUATION);

    // Step 5: 修改原始密文的 c0 和 c1
    DCRTPoly newC0 = c0 + randomNoise;  // 在 c0 添加噪声
    DCRTPoly newC1 = c1 - randomNoise;  // 在 c1 平衡噪声

    // Step 6: 更新密文
    newC0.SetFormat(Format::EVALUATION);
    newC1.SetFormat(Format::EVALUATION);

    elements[0] = newC0;
    elements[1] = newC1;
    ct_product->SetElements(elements);

    end = high_resolution_clock::now();  // 结束时间戳
    duration = duration_cast<microseconds>(end - start).count();

    std::cout << "Successfully added random noise to the ciphertext." << std::endl;

    std::cout << "Nemesis CKKS Encryption time: " << duration << " microseconds" << std::endl;

    /**
     * END Randomization
     *************************/

    // std::cout << "Initial number of levels remaining: " << depth - ciph->GetLevel() << std::endl;

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    // auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

    // std::cout << "Number of levels remaining after bootstrapping: "
    //           << depth - ciphertextAfter->GetLevel() - (ciphertextAfter->GetNoiseScaleDeg() - 1) << std::endl
    //           << std::endl;
    auto ciphertextAfter = ciph;

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(encodedLength);
    std::cout << "Original CKKS recovery: \n\t" << result << std::endl;

    cryptoContext->Decrypt(keyPair.secretKey, ct_product, &result);
    result->SetLength(encodedLength);
    std::cout << "Nemesis CKKS recovery: \n\t" << result << std::endl;

    // TODO: The real game starts here

    // 定义三个固定的文件路径
    std::vector<std::string> paths = {"/home/cc/PFLlib/results/numpy_MNIST.npy",
                                      "/home/cc/PFLlib/results/numpy_FashionMNIST.npy",
                                      "/home/cc/PFLlib/results/numpy_Cifar10.npy"};

    // 提示用户选择路径
    std::cout << "Select the file to load (enter 1, 2, or 3):\n";
    std::cout << "1. " << paths[0] << "\n";
    std::cout << "2. " << paths[1] << "\n";
    std::cout << "3. " << paths[2] << "\n";

    int choice = 0;
    std::cin >> choice;

    // 验证输入
    if (choice < 1 || choice > 3) {
        std::cerr << "Invalid choice. Will use 1." << std::endl;
        choice = 1;
    }

    // 获取选定的路径
    std::string file_path = paths[choice - 1];
    std::cout << "Using file path: " << file_path << std::endl;

    // 调用 LoadNumpyFile 函数加载数据
    std::vector<float> data = LoadNumpyFile(file_path);

    // 输出向量大小
    std::cout << "Loaded vector size: " << data.size() << std::endl;

    // 调用函数
    auto ciphertexts = EncryptWithNoise(cryptoContext, keyPair.publicKey, data, ciph, numSlots, gaussianStdDev);

    std::cout << "Generated " << ciphertexts.size() << " ciphertexts." << std::endl;
}
