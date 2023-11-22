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
  Simple examples for Conjugate-Invariant CKKS variant which doubles the maximum packing capacity 
  in ciphertext. 
 */

#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // Step 1: Setup CryptoContext

    // A. Specify main parameters
    /* A1) Multiplicative depth:
   * The CKKS scheme we setup here will work for any computation
   * that has a multiplicative depth equal to 'multDepth'.
   * This is the maximum possible depth of a given multiplication,
   * but not the total number of multiplications supported by the
   * scheme.
   *
   * For example, computation f(x, y) = x^2 + x*y + y^2 + x + y has
   * a multiplicative depth of 1, but requires a total of 3 multiplications.
   * On the other hand, computation g(x_i) = x1*x2*x3*x4 can be implemented
   * either as a computation of multiplicative depth 3 as
   * g(x_i) = ((x1*x2)*x3)*x4, or as a computation of multiplicative depth 2
   * as g(x_i) = (x1*x2)*(x3*x4).
   *
   * For performance reasons, it's generally preferable to perform operations
   * in the shorted multiplicative depth possible.
   */
    uint32_t multDepth = 3;

    /* A2) Bit-length of scaling factor.
   * CKKS works for real numbers, but these numbers are encoded as integers.
   * For instance, real number m=0.01 is encoded as m'=round(m*D), where D is
   * a scheme parameter called scaling factor. Suppose D=1000, then m' is 10 (an
   * integer). Say the result of a computation based on m' is 130, then at
   * decryption, the scaling factor is removed so the user is presented with
   * the real number result of 0.13.
   *
   * Parameter 'scaleModSize' determines the bit-length of the scaling
   * factor D, but not the scaling factor itself. The latter is implementation
   * specific, and it may also vary between ciphertexts in certain versions of
   * CKKS (e.g., in FLEXIBLEAUTO).
   *
   * Choosing 'scaleModSize' depends on the desired accuracy of the
   * computation, as well as the remaining parameters like multDepth or security
   * standard. This is because the remaining parameters determine how much noise
   * will be incurred during the computation (remember CKKS is an approximate
   * scheme that incurs small amounts of noise with every operation). The
   * scaling factor should be large enough to both accommodate this noise and
   * support results that match the desired accuracy.
   */
    uint32_t scaleModSize = 55;
    uint32_t firstModSize = 60;

    /* A3) Number of plaintext slots used in the ciphertext.
   * CKKS packs multiple plaintext values in each ciphertext.
   * The maximum number of slots depends on a security parameter called ring
   * dimension. In this instance, we don't specify the ring dimension directly,
   * but let the library choose it for us, based on the security level we
   * choose, the multiplicative depth we want to support, and the scaling factor
   * size.
   *
   * Please use method GetRingDimension() to find out the exact ring dimension
   * being used for these parameters. Give ring dimension N, the maximum batch
   * size is N/2, because of the way CKKS works.
   */
    uint32_t batchSize = 16;

    /* A4) Desired security level based on FHE standards.
   * This parameter can take four values. Three of the possible values
   * correspond to 128-bit, 192-bit, and 256-bit security, and the fourth value
   * corresponds to "NotSet", which means that the user is responsible for
   * choosing security parameters. Naturally, "NotSet" should be used only in
   * non-production environments, or by experts who understand the security
   * implications of their choices.
   *
   * If a given security level is selected, the library will consult the current
   * security parameter tables defined by the FHE standards consortium
   * (https://homomorphicencryption.org/introduction/) to automatically
   * select the security parameters. Please see "TABLES of RECOMMENDED
   * PARAMETERS" in  the following reference for more details:
   * http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
   */
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetScalingTechnique(ScalingTechnique::FIXEDMANUAL);
    parameters.SetRingDim(2*batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    // B. Step 2: Key Generation
    /* B1) Generate encryption keys.
   * These are used for encryption/decryption, as well as in generating
   * different kinds of keys.
   */
    auto keys = cc->KeyGen();

    /* B2) Generate the digit size
   * In CKKS, whenever someone multiplies two ciphertexts encrypted with key s,
   * we get a result with some components that are valid under key s, and
   * with an additional component that's valid under key s^2.
   *
   * In most cases, we want to perform relinearization of the multiplicaiton
   * result, i.e., we want to transform the s^2 component of the ciphertext so
   * it becomes valid under original key s. To do so, we need to create what we
   * call a relinearization key with the following line.
   */
    cc->EvalMultKeyGen(keys.secretKey);

    /* B3) Generate the rotation keys
   * CKKS supports rotating the contents of a packed ciphertext, but to do so,
   * we need to create what we call a rotation key. This is done with the
   * following call, which takes as input a vector with indices that correspond
   * to the rotation offset we want to support. Negative indices correspond to
   * right shift and positive to left shift. Look at the output of this demo for
   * an illustration of this.
   *
   * Keep in mind that rotations work over the batch size or entire ring dimension (if the batch size is not specified).
   * This means that, if ring dimension is 8 and batch
   * size is not specified, then an input (1,2,3,4,0,0,0,0) rotated by 2 will become
   * (3,4,0,0,0,0,1,2) and not (3,4,1,2,0,0,0,0).
   * If ring dimension is 8 and batch
   * size is set to 4, then the rotation of (1,2,3,4) by 2 will become (3,4,1,2).
   * Also, as someone can observe
   * in the output of this demo, since CKKS is approximate, zeros are not exact
   * - they're just very small numbers.
   */
    cc->EvalRotateKeyGen(keys.secretKey, {1, -2});

    // Step 3: Encoding and encryption of inputs

    // debugging logic
    {
        std::cout << "parameters: \n" << parameters << "\n";
        std::cout << "cc->GetCryptoParameters(): \n" << *cc->GetCryptoParameters() << "\n";
        std::cout << "cc->GetElementParams(): \n" << *cc->GetElementParams() << "\n";
        std::cout << "cc->GetEncodingParams(): \n" << *cc->GetEncodingParams() << "\n";

        auto print_moduli_chain = [](const lbcrypto::DCRTPoly& poly){
            int num_primes = poly.GetNumOfElements();
            double total_bit_len = 0.0;
            for (int i = 0; i < num_primes; i++) {
                auto qi = poly.GetParams()->GetParams()[i]->GetModulus();
                std::cout << "q_" << i << ": " 
                            << qi
                            << ",  log q_" << i <<": " << log(qi.ConvertToDouble()) / log(2)
                            << std::endl;
                total_bit_len += log(qi.ConvertToDouble()) / log(2);
            }   
            std::cout << "Total bit length: " << total_bit_len << std::endl;
        };

        const std::vector<lbcrypto::DCRTPoly>& ckks_pk = keys.publicKey->GetPublicElements();
        std::cout << "Moduli chain of pk: " << std::endl;
        print_moduli_chain(ckks_pk[0]);

    }

    // Inputs 
    std::vector<double> x1 = {0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
    std::vector<double> x2 = {1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.00, 1.00, 1.00, 1.00, 1.00, 1.00};
    std::vector<double> x3 = {4.0, 4.0, 4.0, 4.0, 4.0, 4.0, 4.0, 4.0, 4.0, 4.0, 4.00, 4.00, 4.00, 4.00, 4.00, 4.00};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    // std::cout << "ptxt1 DCRTPoly: " << ptxt1->GetElement<DCRTPoly>() << "\n";
    // std::cout << "ptxt1 NativePoly: " << ptxt1->GetElement<NativePoly>() << "\n";
    // std::cout << "ptxt1 Poly: " << ptxt1->GetElement<Poly>() << "\n";

    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);
    Plaintext ptxt3 = cc->MakeCKKSPackedPlaintext(x3);

    std::cout << "Input x1: " << ptxt1 << std::endl;
    std::cout << "Input x2: " << ptxt2 << std::endl;
    std::cout << "Input x3: " << ptxt3 << std::endl;

/*
    // TODO need to call decode here to check for result.
    auto dcrtPoly = ptxt1->GetElement<DCRTPoly>();
    auto poly = dcrtPoly.CRTInterpolate();
    std::cout << "ptxt1 as poly: " << poly << "\n";
    Plaintext decrypted = cc->GetPlaintextForDecrypt(ptxt1->GetEncodingType(),
                                      ptxt1->GetElement<DCRTPoly>().GetParams(), ptxt1->GetEncodingParams());
    auto reconstructedInput = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
    reconstructedInput->SetNoiseScaleDeg(decrypted->GetNoiseScaleDeg());
    reconstructedInput->SetLevel(decrypted->GetLevel());
    reconstructedInput->SetScalingFactor(decrypted->GetScalingFactor());
    reconstructedInput->SetSlots(decrypted->GetSlots());
    reconstructedInput->GetElement<Poly>() = poly;
    
    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
      cc->GetCryptoParameters());

    std::cout << "reconstructedInput DCRTPoly: " << reconstructedInput->GetElement<DCRTPoly>() << "\n";
    // std::cout << "reconstructedInput NativePoly: " << reconstructedInput->GetElement<NativePoly>() << "\n";
    // std::cout << "reconstructedInput Poly: " << reconstructedInput->GetElement<Poly>() << "\n";
    

    reconstructedInput->Decode(decrypted->GetNoiseScaleDeg(), decrypted->GetScalingFactor(),
        cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());

    reconstructedInput->SetLength(batchSize);
    std::cout << "dec(enc(x)): " << reconstructedInput->GetRealPackedValue() << std::endl;

    return 0;
    */

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    // Step 4: Evaluation

    // Homomorphic addition
    auto cAdd = cc->EvalAdd(c1, c2);
    
    // Homomorphic subtraction
    auto cSub = cc->EvalSub(c1, c2);

    // Homomorphic scalar multiplication
    auto cScalar = cc->EvalMult(c1, 4.0);
    cScalar = cc->Rescale(cScalar);

    auto cPtxtMulCtxt = cc->EvalMult(c2, ptxt3);
    cPtxtMulCtxt = cc->Rescale(cPtxtMulCtxt);

    // Homomorphic multiplication
    auto cMul = cc->EvalMult(c1, c2);
    cMul = cc->Rescale(cMul);

    // Homomorphic rotations
    auto cRot1 = cc->EvalRotate(c1, 1);
    auto cRot2 = cc->EvalRotate(c1, -2);

    // Step 5: Decryption and output
    Plaintext result;
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    std::cout.precision(8);

    std::cout << std::endl << "Results of homomorphic computations: " << std::endl;

    cc->Decrypt(keys.secretKey, c1, &result);
    result->SetLength(batchSize);
    std::cout << "x1 = " << result;
    std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;

    // Decrypt the result of addition
    cc->Decrypt(keys.secretKey, cAdd, &result);
    result->SetLength(batchSize);
    std::cout << "x1 + x2 = " << result;
    std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;

    // Decrypt the result of subtraction
    cc->Decrypt(keys.secretKey, cSub, &result);
    result->SetLength(batchSize);
    std::cout << "x1 - x2 = " << result << std::endl;

    // Decrypt the result of scalar multiplication
    cc->Decrypt(keys.secretKey, cScalar, &result);
    result->SetLength(batchSize);
    std::cout << "4 * x1 = " << result << std::endl;

    cc->Decrypt(keys.secretKey, cPtxtMulCtxt, &result);
    result->SetLength(batchSize);
    std::cout << "ptxt(4) * x2 = " << result << std::endl;

    // Decrypt the result of multiplication
    cc->Decrypt(keys.secretKey, cMul, &result);
    result->SetLength(batchSize);
    std::cout << "x1 * x2 = " << result << std::endl;

    // Decrypt the result of rotations

    cc->Decrypt(keys.secretKey, cRot1, &result);
    result->SetLength(batchSize);
    std::cout << std::endl << "In rotations, very small outputs (~10^-10 here) correspond to 0's:" << std::endl;
    std::cout << "x1 rotate by 1 = " << result << std::endl;

    cc->Decrypt(keys.secretKey, cRot2, &result);
    result->SetLength(batchSize);
    std::cout << "x2 rotate by -2 = " << result << std::endl;

    return 0;
}
