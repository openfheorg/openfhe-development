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

Example for CKKS bootstrapping

*/

#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

using DggType               = typename DCRTPoly::DggType;
using DugType               = typename DCRTPoly::DugType;

void SimpleBootstrapExample();

std::vector<std::complex<double>> DecryptWithoutDecode(const CryptoContextImpl<DCRTPoly>& cc,
                                                       ConstCiphertext<DCRTPoly> cTemp,
                                                       const PrivateKey<DCRTPoly> privateKey, uint32_t slots,
                                                       uint32_t ringDim);

std::vector<Poly> EncryptBFV(std::vector<int64_t> input, BigInteger Q,
		BigInteger p, const PrivateKey<DCRTPoly> privateKey) {

	// Generate encryption of 0 using the existing CKKS cryptocontext

    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(privateKey->GetCryptoParameters());

    const DCRTPoly& s   = privateKey->GetPrivateElement();

    auto elementParams = cryptoParams->GetElementParams();

    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;

    DCRTPoly a(dug, elementParams, Format::EVALUATION);
    DCRTPoly e(dgg, elementParams, Format::EVALUATION);

    DCRTPoly b = e - a * s; //encryption of 0 using Q'

    a.SetFormat(Format::COEFFICIENT);
    b.SetFormat(Format::COEFFICIENT);

    auto aPoly = a.CRTInterpolate();
    auto bPoly = b.CRTInterpolate();
    BigInteger bigQPrime = b.GetModulus();

    // Do modulus switching from Q' to Q
    bPoly = bPoly.MultiplyAndRound(Q, bigQPrime);
    bPoly.SwitchModulus(Q, 1, 0, 0);

    aPoly = aPoly.MultiplyAndRound(Q, bigQPrime);
    aPoly.SwitchModulus(Q, 1, 0, 0);

    auto mPoly = bPoly;
    mPoly.SetValuesToZero();

    BigInteger delta = Q/p;

    for (size_t i = 0; i < input.size() && i < mPoly.GetLength(); i++) {

        BigInteger entry{input[i]};

        if (input[i] < 0) {
			entry = mPoly.GetModulus() - BigInteger(static_cast<uint64_t>(llabs(input[i])));
        }
        mPoly[i] = delta*entry;
    }

    bPoly += mPoly; //Adds the message

    return {bPoly,aPoly};

}

std::vector<int64_t> DecryptBFV(const std::vector<Poly> &input, BigInteger Q,
		BigInteger p, const PrivateKey<DCRTPoly> privateKey, uint32_t numSlots) {

    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(privateKey->GetCryptoParameters());

    const DCRTPoly& s   = privateKey->GetPrivateElement();

    BigInteger bigQPrime = s.GetModulus();

    Poly bPoly = input[0];
    bPoly.SwitchModulus(bigQPrime, 1, 0, 0); //need to switch to modulus before because the new modulus is bigger
    bPoly = bPoly.MultiplyAndRound(bigQPrime, Q);

    Poly aPoly = input[1];
    aPoly.SwitchModulus(bigQPrime, 1, 0, 0); //need to switch to modulus before because the new modulus is bigger
    aPoly = aPoly.MultiplyAndRound(bigQPrime, Q);

    // Going back to Double-CRT
    DCRTPoly b = DCRTPoly(bPoly, s.GetParams());
    DCRTPoly a = DCRTPoly(aPoly, s.GetParams());

    // Switching to NTT representation
    b.SetFormat(Format::EVALUATION);
    a.SetFormat(Format::EVALUATION);

    auto m = b + a*s;

    m.SetFormat(Format::COEFFICIENT);

    auto mPoly = m.CRTInterpolate();

    mPoly = mPoly.MultiplyAndRound(Q, bigQPrime);
    mPoly.SwitchModulus(Q, 1, 0, 0);

    mPoly = mPoly.MultiplyAndRound(p, Q);
    mPoly.SwitchModulus(p, 1, 0, 0);

    BigInteger half                 = p >> 1;

    std::vector<int64_t> output(numSlots);

    for (size_t i = 0; i < output.size(); i++) {
        int64_t val;
    	if (mPoly[i] > half)
    		val = (-(p - mPoly[i]).ConvertToInt());
        else
            val = mPoly[i].ConvertToInt();
    	output[i] = val;
    }

    return output;
}


int main(int argc, char* argv[]) {
    SimpleBootstrapExample();
}

void SimpleBootstrapExample() {
    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = SPARSE_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(16);

    uint32_t dcrtBits = 45;
    uint32_t firstMod = 45;
    uint32_t numSlots = 8;

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(firstMod);
    parameters.SetNumLargeDigits(3);
    parameters.SetBatchSize(numSlots);

    std::vector<uint32_t> levelBudget = {1, 1};

    uint32_t levelsAvailableAfterBootstrap = 2;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint ringDim = cryptoContext->GetRingDimension();
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;

    cryptoContext->EvalBootstrapSetup(levelBudget, {0, 0}, numSlots, 0);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    //=======BFV LOGIC STARTS HERE--------------

    // Encrypting and decrypting using BFV-like encryption
    BigInteger Q("1152921504606846976"); // 2^60
    BigInteger p("1048576"); // 2^20

    std::vector<int64_t> input = {256, 456, 4, 8, 16, 32, 64, 128};

    std::cerr << "plaintext before BFV encryption: " << input << std::endl;

    auto encrypted = EncryptBFV(input, Q, p, keyPair.secretKey);

    auto decrypted = DecryptBFV(encrypted, Q, p, keyPair.secretKey, numSlots);

    std::cerr << "plaintext after BFV encryption + decryption: " << decrypted << std::endl;

    // Changing (\log Q, \log p) from  (45,60) to (45,5), i.e., doing mod q

    // Mod 2^45
    BigInteger Bigq          = BigInteger("35184372088832");
    BigInteger pNew("32"); // 2^5
    // Apply mod q
    encrypted[0].SwitchModulus(Bigq, 1, 0, 0);
    encrypted[1].SwitchModulus(Bigq, 1, 0, 0);

    decrypted = DecryptBFV(encrypted, Bigq, pNew, keyPair.secretKey, numSlots);

    std::cerr << "plaintext after BFV decryption of ciphertext mod q: " << decrypted << std::endl;

    // populate the CKKS ciphertext with proper metadata; then we will replace
    // its DCRTPoly's with the ones from the BFV ciphertext using the SetElements method

    std::vector<double> x = {1, 2, 4, 8, 16, 32, 64, 128};
    std::transform(x.begin(), x.end(), x.begin(),
                   std::bind(std::multiplies<double>(), std::placeholders::_1, 1/128.0));

    size_t encodedLength  = x.size();

    // depth - 1 means we have two RNS limbs here; we need to the second limb
    // for internal downscaling (scalar multiplication)
    // so that the sine wave approximation of modular reduction
    // could achieve reasonable precision
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    ptxt->SetLength(encodedLength);
    Ciphertext<DCRTPoly> ctxt = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    // Switch encryped digit from q to q'
    // To do: replace DCRTPoly's in ctxt
    // But how do we handle the second RNS limb?


    // ---- THE REMAINING LOGIC HAS NOT BEEN TOUCHED ----

    // want to check the plaintext encoding
    auto ctxt_ccheck = ctxt->Clone();
    Plaintext ccc;
    ctxt_ccheck = cryptoContext->Rescale(ctxt_ccheck);
    cryptoContext->Decrypt(keyPair.secretKey, ctxt_ccheck, &ccc);


    auto ctxtNew = ctxt->Clone();
    auto ctxt_check = ctxt->Clone();

    // double check the result before bootstrapping
    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ctxt_check, &result);


    auto ciphertextAfter1 = cryptoContext->EvalBootstrap(ctxt);
    cryptoContext->RescaleInPlace(ciphertextAfter1);

    std::cout << "Number of levels remaining after bootstrapping: "
              << depth - ciphertextAfter1->GetLevel() - (ciphertextAfter1->GetNoiseScaleDeg() - 1) << std::endl
              << std::endl;


    std::cout << "Input" << x << std::endl;

    std::cout << "scaling degree after bootstrapping: " << ciphertextAfter1->GetNoiseScaleDeg() << std::endl;

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter1, &result);
    result->SetLength(encodedLength);

    auto vec = DecryptWithoutDecode(*cryptoContext,
    		ciphertextAfter1,
			keyPair.secretKey, numSlots,
			cryptoContext->GetRingDimension());

    std::cerr << std::setprecision(15);

    std::cerr << "Result using Andreea's function " << vec <<std::endl;

    result->GetElement<Poly>().SetFormat(Format::EVALUATION);
//    std::cout << "Int number evaluation: " << result->GetElement<Poly>() << std::endl;

    result->GetElement<Poly>().SetFormat(Format::COEFFICIENT);
//    std::cout << "Int number coefficient: " << result->GetElement<Poly>() << std::endl;
//
//    std::cout << "Output after bootstrapping w/o modulus switching \n\t" << result << std::endl;


    auto ciphertextAfter2 = cryptoContext->EvalBootstrap(ctxtNew);

    std::cout << "Number of levels remaining after bootstrapping: "
              << depth - ciphertextAfter2->GetLevel() - (ciphertextAfter2->GetNoiseScaleDeg() - 1) << std::endl
              << std::endl;

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter2, &result);
    result->SetLength(encodedLength);
    std::cout << "Output after bootstrapping w/ modulus switching \n\t" << result << std::endl;
}

std::vector<std::complex<double>> DecryptWithoutDecode(const CryptoContextImpl<DCRTPoly>& cc,
                                                       ConstCiphertext<DCRTPoly> cTemp,
                                                       const PrivateKey<DCRTPoly> privateKey, uint32_t slots,
                                                       uint32_t ringDim) {
    Plaintext decrypted = cc.GetPlaintextForDecrypt(cTemp->GetEncodingType(), cTemp->GetElements()[0].GetParams(),
                                                    cc.GetEncodingParams());
    bool isNativePoly   = true;
    DecryptResult result;

    if ((cTemp->GetEncodingType() == CKKS_PACKED_ENCODING) &&
        (cTemp->GetElements()[0].GetParams()->GetParams().size() > 1)) {
        result = cc.GetScheme()->Decrypt(cTemp, privateKey, &decrypted->GetElement<Poly>());
        isNativePoly = false;
    }
    else {
        result = cc.GetScheme()->Decrypt(cTemp, privateKey, &decrypted->GetElement<NativePoly>());
        isNativePoly = true;
    }

    auto elemModulus   = decrypted->GetElementModulus();
    auto noiseScaleDeg = cTemp->GetNoiseScaleDeg();
    auto scalingFactor = cTemp->GetScalingFactor();

    decrypted->SetScalingFactorInt(result.scalingFactorInt);

    double p     = cc.GetEncodingParams()->GetPlaintextModulus();
    double powP  = 0.0;
    uint32_t Nh  = ringDim / 2;
    uint32_t gap = Nh / slots;
    std::vector<std::complex<double>> curValues(slots);

    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    auto scalTech = cryptoParamsCKKS->GetScalingTechnique();

    if (isNativePoly) {
        if (scalTech == FLEXIBLEAUTO || scalTech == FLEXIBLEAUTOEXT) {
            powP = pow(scalingFactor, -1);
        }
        else {
            powP = pow(2, -p);
        }

        const NativeInteger& q = decrypted->GetElementModulus().ConvertToInt();
        NativeInteger qHalf    = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (decrypted->GetElement<NativePoly>()[idx] > qHalf)
                cur.real(-((q - decrypted->GetElement<NativePoly>()[idx])).ConvertToDouble());
            else
                cur.real((decrypted->GetElement<NativePoly>()[idx]).ConvertToDouble());

            if (decrypted->GetElement<NativePoly>()[idx + Nh] > qHalf)
                cur.imag(-((q - decrypted->GetElement<NativePoly>()[idx + Nh])).ConvertToDouble());
            else
                cur.imag((decrypted->GetElement<NativePoly>()[idx + Nh]).ConvertToDouble());

            curValues[i] = cur * powP;
        }

        for (size_t i = 0; i < 2*slots; ++i) {
            std::cout << decrypted->GetElement<NativePoly>()[i] << " ";
        }
        std::cout << std::endl;
    }
    else {
        powP = pow(2, -p);

        // we will bring down the scaling factor to 2^p
        double scalingFactorPre = 0.0;
        if (scalTech == FLEXIBLEAUTO || scalTech == FLEXIBLEAUTOEXT)
            scalingFactorPre = pow(scalingFactor, -1) * pow(2, p);
        else
            scalingFactorPre = pow(2, -p * (noiseScaleDeg - 1));

        const BigInteger& q = decrypted->GetElementModulus();
        BigInteger qHalf    = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (decrypted->GetElement<Poly>()[idx] > qHalf)
                cur.real(-((q - decrypted->GetElement<Poly>()[idx])).ConvertToDouble() * scalingFactorPre);
            else
                cur.real((decrypted->GetElement<Poly>()[idx]).ConvertToDouble() * scalingFactorPre);

            if (decrypted->GetElement<Poly>()[idx + Nh] > qHalf)
                cur.imag(-((q - decrypted->GetElement<Poly>()[idx + Nh])).ConvertToDouble() * scalingFactorPre);
            else
                cur.imag((decrypted->GetElement<Poly>()[idx + Nh]).ConvertToDouble() * scalingFactorPre);

            // curValues[i] = cur * powP;
            curValues[i] = cur;
        }
    }
    return curValues;
}
