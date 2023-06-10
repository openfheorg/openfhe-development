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
  Simple example for BFVrns (integer arithmetic)
 */

#include "openfhe.h"

using namespace lbcrypto;

void EvalNoiseBFV(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, Plaintext ptxt, usint ptm,
                  double& noise, double& logQ);

int main() {
    CCParams<CryptoContextBFVRNS> parameters;
    uint64_t ptm = 786433;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicationTechnique(HPSPOVERQ);  // BEHZ, HPS, HPSPOVERQ, HPSPOVERQLEVELED
    parameters.SetMultiplicativeDepth(67);             // 50, 100, 150

    // For speed
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    parameters.SetRingDim(1024);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    // First plaintext vector is encoded
    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    // Second plaintext vector is encoded
    std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    // Homomorphic multiplications
    auto ciphertextMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);

    // Decrypt the result of multiplications
    Plaintext plaintextMultResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMultResult);
    plaintextMultResult->SetLength(vectorOfInts1.size());
    std::vector<int64_t> decvec = plaintextMultResult->GetPackedValue();
    Plaintext dRes              = cryptoContext->MakePackedPlaintext(decvec);

    // Decrypt the result of 1 and 2
    Plaintext plaintext1Result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintext1Result);
    plaintext1Result->SetLength(vectorOfInts1.size());
    std::vector<int64_t> decvec1 = plaintext1Result->GetPackedValue();
    Plaintext dRes1              = cryptoContext->MakePackedPlaintext(decvec1);

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "#1:      " << plaintext1Result << std::endl;
    std::cout << "#1 * #2: " << plaintextMultResult << std::endl;

    double noise = 0, logQ = 0;
    EvalNoiseBFV(keyPair.secretKey, ciphertextMul12, dRes, ptm, noise, logQ);
    EvalNoiseBFV(keyPair.secretKey, ciphertext1, dRes1, ptm, noise, logQ);
    return 0;
}

void EvalNoiseBFV(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, Plaintext ptxt, usint ptm,
                  double& noise, double& logQ) {
    const auto cryptoParams = std::static_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    DCRTPoly s                      = privateKey->GetPrivateElement();

    size_t sizeQl = cv[0].GetParams()->GetParams().size();
    size_t sizeQs = s.GetParams()->GetParams().size();

    size_t diffQl = sizeQs - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    DCRTPoly sPower(scopy);

    DCRTPoly b = cv[0];
    b.SetFormat(Format::EVALUATION);

    DCRTPoly ci;
    for (size_t i = 1; i < cv.size(); i++) {
        ci = cv[i];
        ci.SetFormat(Format::EVALUATION);

        b += sPower * ci;
        sPower *= scopy;
    }

    const auto encParams                = cryptoParams->GetElementParams();
    NativeInteger NegQModt              = cryptoParams->GetNegQModt();
    NativeInteger NegQModtPrecon        = cryptoParams->GetNegQModtPrecon();
    const NativeInteger t               = cryptoParams->GetPlaintextModulus();
    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();

    DCRTPoly plain = ptxt->GetElement<DCRTPoly>();
    plain.SetFormat(Format::COEFFICIENT);
    plain.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
    plain.SetFormat(Format::EVALUATION);
    DCRTPoly res;
    res = b - plain;

    // Converts back to coefficient representation
    res.SetFormat(Format::COEFFICIENT);
    size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
    noise        = (log2(res.Norm()));

    logQ = 0;
    for (usint i = 0; i < sizeQ; i++) {
        double logqi = log2(cryptoParams->GetElementParams()->GetParams()[i]->GetModulus().ConvertToInt());
        logQ += logqi;
    }

    std::cout << "logQ: " << logQ << std::endl;
    std::cout << "noise: " << noise << std::endl;
}
