// @file  simple-real-numbers.cpp - Simple examples for CKKS.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
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
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#define PROFILE

#include "palisade.h"

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
  uint32_t multDepth = 1;

  /* A2) Bit-length of scaling factor.
   * CKKS works for real numbers, but these numbers are encoded as integers.
   * For instance, real number m=0.01 is encoded as m'=round(m*D), where D is
   * a scheme parameter called scaling factor. Suppose D=1000, then m' is 10 (an
   * integer). Say the result of a computation based on m' is 130, then at
   * decryption, the scaling factor is removed so the user is presented with
   * the real number result of 0.13.
   *
   * Parameter 'scaleFactorBits' determines the bit-length of the scaling
   * factor D, but not the scaling factor itself. The latter is implementation
   * specific, and it may also vary between ciphertexts in certain versions of
   * CKKS (e.g., in EXACTRESCALE).
   *
   * Choosing 'scaleFactorBits' depends on the desired accuracy of the
   * computation, as well as the remaining parameters like multDepth or security
   * standard. This is because the remaining parameters determine how much noise
   * will be incurred during the computation (remember CKKS is an approximate
   * scheme that incurs small amounts of noise with every operation). The
   * scaling factor should be large enough to both accommodate this noise and
   * support results that match the desired accuracy.
   */
  uint32_t scaleFactorBits = 50;

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
  uint32_t batchSize = 8;

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
  SecurityLevel securityLevel = HEStd_128_classic;

  // The following call creates a CKKS crypto context based on the
  // arguments defined above.
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          multDepth, scaleFactorBits, batchSize, securityLevel);

  std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension()
            << std::endl
            << std::endl;

  // Enable the features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // B. Step 2: Key Generation
  /* B1) Generate encryption keys.
   * These are used for encryption/decryption, as well as in generating
   * different kinds of keys.
   */
  auto keys = cc->KeyGen();

  /* B2) Generate the relinearization key
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
   * Keep in mind that rotations work on the entire ring dimension, not the
   * specified batch size. This means that, if ring dimension is 8 and batch
   * size is 4, then an input (1,2,3,4,0,0,0,0) rotated by 2 will become
   * (3,4,0,0,0,0,1,2) and not (3,4,1,2,0,0,0,0). Also, as someone can observe
   * in the output of this demo, since CKKS is approximate, zeros are not exact
   * - they're just very small numbers.
   */
  cc->EvalAtIndexKeyGen(keys.secretKey, {1, -2});

  // Step 3: Encoding and encryption of inputs

  // Inputs
  vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
  vector<double> x2 = {5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25};

  // Encoding as plaintexts
  Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
  Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);

  std::cout << "Input x1: " << ptxt1 << std::endl;
  std::cout << "Input x2: " << ptxt2 << std::endl;

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

  // Homomorphic multiplication
  auto cMul = cc->EvalMult(c1, c2);

  // Homomorphic rotations
  auto cRot1 = cc->EvalAtIndex(c1, 1);
  auto cRot2 = cc->EvalAtIndex(c1, -2);

  // Step 5: Decryption and output
  Plaintext result;
  // We set the cout precision to 8 decimal digits for a nicer output.
  // If you want to see the error/noise introduced by CKKS, bump it up
  // to 15 and it should become visible.
  std::cout.precision(8);
  std::cout << std::endl
            << "Results of homomorphic computations: " << std::endl;

  // Decrypt the result of addition
  cc->Decrypt(keys.secretKey, cAdd, &result);
  result->SetLength(batchSize);
  std::cout << "x1 + x2 = " << result;
  std::cout << "Estimated precision in bits: " << result->GetLogPrecision()
            << std::endl;

  // Decrypt the result of subtraction
  cc->Decrypt(keys.secretKey, cSub, &result);
  result->SetLength(batchSize);
  std::cout << "x1 - x2 = " << result << std::endl;

  // Decrypt the result of scalar multiplication
  cc->Decrypt(keys.secretKey, cScalar, &result);
  result->SetLength(batchSize);
  std::cout << "4 * x1 = " << result << std::endl;

  // Decrypt the result of multiplication
  cc->Decrypt(keys.secretKey, cMul, &result);
  result->SetLength(batchSize);
  std::cout << "x1 * x2 = " << result << std::endl;

  // Decrypt the result of rotations
  cc->Decrypt(keys.secretKey, cRot1, &result);
  result->SetLength(batchSize);
  std::cout
      << std::endl
      << "In rotations, very small outputs (~10^-10 here) correspond to 0's:"
      << std::endl;
  std::cout << "x1 rotate by 1 = " << result << std::endl;

  cc->Decrypt(keys.secretKey, cRot2, &result);
  result->SetLength(batchSize);
  std::cout << "x1 rotate by -2 = " << result << std::endl;

  return 0;
}
