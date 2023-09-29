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
  Examples for scheme switching between CKKS and FHEW and back, with intermediate computations
 */

#include "openfhe.h"
#include "binfhecontext.h"

using namespace lbcrypto;

void SwitchCKKSToFHEW();
void SwitchFHEWtoCKKS();
void FloorViaSchemeSwitching();
void ComparisonViaSchemeSwitching();
void FuncViaSchemeSwitching();
void PolyViaSchemeSwitching();
void ArgminViaSchemeSwitching();
void ArgminViaSchemeSwitchingAlt();
void ArgminViaSchemeSwitchingUnit();
void ArgminViaSchemeSwitchingAltUnit();
std::vector<int32_t> RotateInt(const std::vector<int32_t>&, int32_t);

void SwitchFHEWtoCKKSTest();

Ciphertext<DCRTPoly> EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    std::vector<DCRTPoly>& cv   = result->GetElements();

    DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
    pt.SetFormat(Format::EVALUATION);

    for (auto& c : cv) {
        c *= pt;
    }
    result->SetNoiseScaleDeg(result->GetNoiseScaleDeg() + plaintext->GetNoiseScaleDeg());
    result->SetScalingFactor(result->GetScalingFactor() * plaintext->GetScalingFactor());
    return result;
}

void EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) {
    std::vector<DCRTPoly>& cv1       = ciphertext1->GetElements();
    const std::vector<DCRTPoly>& cv2 = ciphertext2->GetElements();

    for (size_t i = 0; i < cv1.size(); ++i) {
        cv1[i] += cv2[i];
    }
}

Ciphertext<DCRTPoly> EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) {
    Ciphertext<DCRTPoly> result = ciphertext1->Clone();
    EvalAddExtInPlace(result, ciphertext2);
    return result;
}

std::vector<std::vector<std::complex<double>>> EvalLTRectPrecomputeSwitch(
    const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1, double scale) {
    if (!IsPowerOfTwo(A.size()) || !IsPowerOfTwo(A[0].size())) {
        OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecompute is not padded up to powers of two");
    }
    uint32_t n     = std::min(A.size(), A[0].size());
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(n) : dim1;
    uint32_t gStep = ceil(static_cast<double>(n) / bStep);

    std::vector<std::vector<std::complex<double>>> diags(n);

    if (A.size() >= A[0].size()) {
        auto num_slices = A.size() / A[0].size();
        std::vector<std::vector<std::vector<std::complex<double>>>> A_slices(num_slices);
        for (size_t i = 0; i < num_slices; i++) {
            A_slices[i] = std::vector<std::vector<std::complex<double>>>(A.begin() + i * A[0].size(),
                                                                         A.begin() + (i + 1) * A[0].size());
        }
#pragma omp parallel for
        for (uint32_t j = 0; j < gStep; j++) {
            for (uint32_t i = 0; i < bStep; i++) {
                if (bStep * j + i < n) {
                    std::vector<std::complex<double>> diag(0);
                    for (uint32_t k = 0; k < num_slices; k++) {
                        auto tmp = ExtractShiftedDiagonal(A_slices[k], bStep * j + i);
                        diag.insert(diag.end(), tmp.begin(), tmp.end());
                    }
                    std::transform(diag.begin(), diag.end(), diag.begin(),
                                   [&](const std::complex<double>& elem) { return elem * scale; });
                    diags[bStep * j + i] = diag;
                }
            }
        }
    }
    else {
#pragma omp parallel for
        for (uint32_t j = 0; j < gStep; j++) {
            for (uint32_t i = 0; i < bStep; i++) {
                if (bStep * j + i < n) {
                    std::vector<std::complex<double>> diag = ExtractShiftedDiagonal(A, bStep * j + i);
                    std::transform(diag.begin(), diag.end(), diag.begin(),
                                   [&](const std::complex<double>& elem) { return elem * scale; });
                    diags[bStep * j + i] = diag;
                }
            }
        }
    }
    return diags;
}

Ciphertext<DCRTPoly> EvalLTRectWithPrecomputeSwitch(CryptoContextImpl<DCRTPoly>& cc,
                                                    const std::vector<std::vector<std::complex<double>>>& A,
                                                    ConstCiphertext<DCRTPoly> ct, bool wide, uint32_t dim1,
                                                    uint32_t L) {
    uint32_t n = std::min(A.size(), A[0].size());

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(n) : dim1;
    uint32_t gStep = ceil(static_cast<double>(n) / bStep);

    std::cout << "bStep = " << bStep << ", gStep = " << gStep << std::endl;

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t N = cc.GetRingDimension();

    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(ct);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);

    // Make sure the plaintext is created only with the necessary amount of moduli
    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ct->GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());
    uint32_t towersToDrop                         = 0;

    // For FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - 1;
        for (uint32_t i = 0; i < towersToDrop; i++)
            elementParams.PopLastParam();
    }
    if (cryptoParamsCKKS->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        towersToDrop += 1;
        elementParams.PopLastParam();
    }

    auto paramsQ = elementParams.GetParams();
    usint sizeQ  = paramsQ.size();
    auto paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();
    usint sizeP  = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);

    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    auto elementParamsPtr  = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
    auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);

// Hoisted automorphisms
#pragma omp parallel for
    for (uint32_t j = 1; j < bStep; j++) {
        fastRotation[j - 1] = cc.EvalFastRotationExt(ct, j, digits, true);
    }

    Ciphertext<DCRTPoly> result;
    DCRTPoly first;

    for (uint32_t j = 0; j < gStep; j++) {
        int32_t offset = (j == 0) ? 0 : -static_cast<int32_t>(bStep * j);
        auto temp      = cc.MakeCKKSPackedPlaintext(Rotate(Fill(A[bStep * j], N / 2), offset), 1, towersToDrop,
                                                    elementParamsPtr2, N / 2);
        temp->SetLength(32);
        std::cout << "temp = " << temp << std::endl;
        Ciphertext<DCRTPoly> inner = EvalMultExt(cc.KeySwitchExt(ct, true), temp);

        for (uint32_t i = 1; i < bStep; i++) {
            std::cout << "j = " << j << ", i = " << i << ", offset = " << offset << std::endl;
            if (bStep * j + i < n) {
                auto tempi = cc.MakeCKKSPackedPlaintext(Rotate(Fill(A[bStep * j + i], N / 2), offset), 1, towersToDrop,
                                                        elementParamsPtr2, N / 2);
                tempi->SetLength(32);
                std::cout << "tempi = " << tempi << std::endl;
                EvalAddExtInPlace(inner, EvalMultExt(fastRotation[i - 1], tempi));
            }
        }

        if (j == 0) {
            first         = cc.KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(elements);
            result = inner;
        }
        else {
            inner = cc.KeySwitchDown(inner);
            // Find the automorphism index that corresponds to rotation index index.
            usint autoIndex = FindAutomorphismIndex2nComplex(bStep * j, M);
            std::vector<usint> map(N);
            PrecomputeAutoMap(N, autoIndex, &map);
            DCRTPoly firstCurrent = inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
            first += firstCurrent;

            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            EvalAddExtInPlace(result, cc.EvalFastRotationExt(inner, bStep * j, innerDigits, false));
        }
    }
    result        = cc.KeySwitchDown(result);
    auto elements = result->GetElements();
    elements[0] += first;
    result->SetElements(elements);

    if (wide) {
        uint32_t logl = lbcrypto::GetMSB(A[0].size() / A.size()) - 1;  // These are powers of two, so log(l) is integer
        std::vector<Ciphertext<DCRTPoly>> ctxt(logl + 1);
        ctxt[0] = result;
        for (size_t j = 1; j <= logl; ++j) {
            ctxt[j] = cc.EvalAdd(ctxt[j - 1], cc.EvalAtIndex(ctxt[j - 1], A.size() * (1 << (j - 1))));
        }
        result = ctxt[logl];
    }

    return result;
}

int main() {
    // SwitchCKKSToFHEW();
    // SwitchFHEWtoCKKS();
    // FloorViaSchemeSwitching();
    // FuncViaSchemeSwitching();
    // PolyViaSchemeSwitching();
    // ComparisonViaSchemeSwitching();
    // ArgminViaSchemeSwitching();
    ArgminViaSchemeSwitchingAlt();
    // ArgminViaSchemeSwitchingUnit();
    // ArgminViaSchemeSwitchingAltUnit();

    // SwitchFHEWtoCKKSTest();

    return 0;
}

void SwitchFHEWtoCKKSTest() {
    std::cout << "\n-----SwitchFHEWtoCKKS-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS to be switched into

    // A. Specify main parameters
    ScalingTechnique scTech = FIXEDAUTO;
    uint32_t multDepth =
        3 + 9 + 1;  // for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 8192;
    SecurityLevel sl      = HEStd_NotSet;  // If this is not HEStd_NotSet, ensure ringDim is compatible
    uint32_t logQ_ccLWE   = 26;

    // uint32_t slots = ringDim/2; // Uncomment for fully-packed
    uint32_t slots     = 16;  // sparsely-packed
    uint32_t batchSize = slots;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto ccLWE = std::make_shared<BinFHEContext>();
    ccLWE->BinFHEContext::GenerateBinFHEContext(TOY, false, logQ_ccLWE, 0, GINX, false);

    // LWE private key
    LWEPrivateKey lwesk;
    lwesk = ccLWE->KeyGen();

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Step 3. Precompute the necessary keys and information for switching from FHEW to CKKS
    cc->EvalFHEWtoCKKSSetup(ccLWE, slots, logQ_ccLWE);

    cc->EvalFHEWtoCKKSKeyGen(keys, lwesk, slots, slots);

    // Step 4: Encoding and encryption of inputs
    // For correct CKKS decryption, the messages have to be much smaller than the FHEW plaintext modulus!

    // auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    // uint32_t pLWE2   = 256;                                           // Medium precision
    // auto modulus_LWE = 1 << logQ_ccLWE;
    // auto beta        = ccLWE->GetBeta().ConvertToInt();
    // auto pLWE3       = modulus_LWE / (2 * beta);  // Large precision
    // Inputs
    std::vector<int> x1 = {1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0};
    std::vector<int> x2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
        x2.insert(x2.end(), zeros.begin(), zeros.end());
    }

    // Encrypt
    std::vector<LWECiphertext> ctxtsLWE1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE1[i] =
            ccLWE->Encrypt(lwesk, x1[i]);  // encrypted under small plantext modulus p = 4 and ciphertext modulus
    }

    // std::vector<LWECiphertext> ctxtsLWE2(slots);
    // for (uint32_t i = 0; i < slots; i++) {
    //     ctxtsLWE2[i] =
    //         ccLWE->Encrypt(lwesk, x1[i], FRESH,
    //                        pLWE1);  // encrypted under larger plaintext modulus p = 16 but small ciphertext modulus
    // }

    // std::vector<LWECiphertext> ctxtsLWE3(slots);
    // for (uint32_t i = 0; i < slots; i++) {
    //     ctxtsLWE3[i] =
    //         ccLWE->Encrypt(lwesk, x2[i], FRESH, pLWE2,
    //                        modulus_LWE);  // encrypted under larger plaintext modulus and large ciphertext modulus
    // }

    // std::vector<LWECiphertext> ctxtsLWE4(slots);
    // for (uint32_t i = 0; i < slots; i++) {
    //     ctxtsLWE4[i] =
    //         ccLWE->Encrypt(lwesk, x2[i], FRESH, pLWE3,
    //                        modulus_LWE);  // encrypted under large plaintext modulus and large ciphertext modulus
    // }

    // Step 5. Perform the scheme switching
    auto cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE1, slots, slots);

    std::cout << "\n---Input x1: " << x1 << " encrypted under p = " << 4 << " and Q = " << ctxtsLWE1[0]->GetModulus()
              << "---" << std::endl;

    // Step 6. Decrypt
    Plaintext plaintextDec;
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(slots);
    std::cout << "Switched CKKS decryption 1: " << plaintextDec << std::endl;

    // // Step 5'. Perform the scheme switching
    // cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE2, slots, slots, pLWE1, 0, pLWE1);

    // std::cout << "\n---Input x1: " << x1 << " encrypted under p = " << NativeInteger(pLWE1)
    //           << " and Q = " << ctxtsLWE2[0]->GetModulus() << "---" << std::endl;

    // // Step 6'. Decrypt
    // cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    // plaintextDec->SetLength(slots);
    // std::cout << "Switched CKKS decryption 2: " << plaintextDec << std::endl;

    // // Step 5''. Perform the scheme switching
    // cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE3, slots, slots, pLWE2, 0, pLWE2);

    // std::cout << "\n---Input x2: " << x2 << " encrypted under p = " << pLWE2
    //           << " and Q = " << ctxtsLWE3[0]->GetModulus() << "---" << std::endl;

    // // Step 6''. Decrypt
    // cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    // plaintextDec->SetLength(slots);
    // std::cout << "Switched CKKS decryption 3: " << plaintextDec << std::endl;

    // // Step 5'''. Perform the scheme switching
    // std::setprecision(logQ_ccLWE + 10);
    // auto cTemp2 = cc->EvalFHEWtoCKKS(ctxtsLWE4, slots, slots, pLWE3, 0, pLWE3);

    // std::cout << "\n---Input x2: " << x2 << " encrypted under p = " << NativeInteger(pLWE3)
    //           << " and Q = " << ctxtsLWE4[0]->GetModulus() << "---" << std::endl;

    // // Step 6'''. Decrypt
    // Plaintext plaintextDec2;
    // cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    // plaintextDec2->SetLength(slots);
    // std::cout << "Switched CKKS decryption 4: " << plaintextDec2 << std::endl;

    uint32_t n = ctxtsLWE1[0]->GetA().GetLength();

    double K = 1.0;
    if (n == 32) {
        K = 16.0;
    }
    else {
        K = 128.0;
    }

    // Step 1. Form matrix A and vector b from the LWE ciphertexts, but only extract the first necessary number of them
    std::vector<std::vector<double>> A(slots);

    for (uint32_t i = 0; i < slots; i++) {
        auto a = ctxtsLWE1[i]->GetA();
        A[i]   = std::vector<double>(a.GetLength());
        for (uint32_t j = 0; j < a.GetLength(); j++) {
            A[i][j] = a[j].ConvertToDouble();
        }
    }

    // Generate FHEW to CKKS switching key, i.e., CKKS encryption of FHEW secret key
    auto skLWEElements = lwesk->GetElement();
    std::vector<double> skLWEDouble(n);
    for (uint32_t i = 0; i < n; i++) {
        auto tmp = skLWEElements[i].ConvertToDouble();
        if (tmp == lwesk->GetModulus().ConvertToInt() - 1)
            tmp = -1;
        skLWEDouble[i] = tmp;
    }

    std::vector<double> result(slots, 0);
    double prescale = (1.0 / ctxtsLWE1[0]->GetModulus().ConvertToDouble()) / K;

    // Test matrix-vector multiplication
    for (size_t i = 0; i < slots; ++i) {
        for (size_t j = 0; j < n; ++j) {
            result[i] += A[i][j] * skLWEDouble[j] * prescale;
        }
    }

    std::cout << "A*s = " << result << std::endl;

    std::vector<std::vector<std::complex<double>>> B = {
        {1, 2},   {3, 4},   {5, 6},  {7, 8}, {9, 10},
        {11, 12}, {13, 14}, {15, 16}};  // {{1,2,3},{4,5,6}}; // {{1,2,3,4,5,6,7},{8,9,10,11,12,13,14}}; // {{1,2,3,4,5},{6,7,8,9,10}}; //

    std::vector<std::vector<std::complex<double>>> Bcopy(B);
    uint32_t cols_po2 = 1 << static_cast<uint32_t>(std::ceil(std::log2(B[0].size())));

    if (cols_po2 != B[0].size()) {
        std::vector<std::complex<double>> padding(cols_po2 - B[0].size());
        for (size_t i = 0; i < B.size(); ++i) {
            Bcopy[i].insert(Bcopy[i].end(), padding.begin(), padding.end());
        }
    }

    std::cout << "B = " << B << std::endl;
    std::cout << "Bcopy = " << Bcopy << std::endl;

    auto diags = EvalLTRectPrecomputeSwitch(Bcopy, 0, 1);

    std::cout << "diags = " << diags << std::endl;

    // Generate FHEW to CKKS switching key, i.e., CKKS encryption of FHEW secret key. Pad up to the closest power of two
    std::vector<std::complex<double>> skLWEDoubleC(
        {1, -1});  // ({1,-1,1,0}); // ({1,-1,1,-1,1,-1,1,0}); ({1,-1,1,-1,1,0}); //;
    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    Plaintext skLWEPlainswk;
    skLWEPlainswk = cc->MakeCKKSPackedPlaintext(Fill(skLWEDoubleC, ringDim / 2), 1, 0, nullptr, ringDim / 2);
    skLWEPlainswk->SetLength(32);
    std::cout << skLWEPlainswk << std::endl;

    auto FHEWtoCKKSswk = cc->Encrypt(keys.publicKey, skLWEPlainswk);
    auto res           = EvalLTRectWithPrecomputeSwitch(*cc, diags, FHEWtoCKKSswk, (B.size() < B[0].size()), 0,
                                                        0);  // The result is repeated every Acopy.size() slots

    cc->Decrypt(keys.secretKey, res, &plaintextDec);
    plaintextDec->SetLength(slots);
    std::cout << "Enc B*s: " << plaintextDec << std::endl;
}

void SwitchCKKSToFHEW() {
    /*
  Example of switching a packed ciphertext from CKKS to multiple FHEW ciphertexts.
 */

    std::cout << "\n-----SwitchCKKSToFHEW-----\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS

    // Specify main parameters
    uint32_t multDepth    = 3;
    uint32_t firstModSize = 60;
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 4096;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE   = 25;
    // uint32_t slots        = ringDim / 2;  // Uncomment for fully-packed
    uint32_t slots     = 16;  // sparsely-packed
    uint32_t batchSize = slots;

    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto FHEWparams     = cc->EvalCKKStoFHEWSetup(sl, slBin, false, logQ_ccLWE, false, slots);
    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;
    cc->EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Compute the scaling factor to decrypt correctly in FHEW; the LWE mod switch is performed on the ciphertext at the last level
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();

    auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE2       = modulus_LWE / (2 * beta);  // Large precision

    double scFactor = cryptoParams->GetScalingFactorReal(0);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        scFactor = cryptoParams->GetScalingFactorReal(1);
    double scale1 = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE1);
    double scale2 = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE2);

    // Perform the precomputation for switching
    cc->EvalCKKStoFHEWPrecompute(scale1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1  = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0};
    std::vector<double> x2  = {0.0, 271.0, 30000.0, static_cast<double>(pLWE2) - 2};
    uint32_t encodedLength1 = x1.size();
    uint32_t encodedLength2 = x2.size();

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    // Step 4: Scheme switching from CKKS to FHEW

    // A: First scheme switching case

    // Transform the ciphertext from CKKS to FHEW
    auto cTemp = cc->EvalCKKStoFHEW(c1, encodedLength1);

    std::cout << "\n---Decrypting switched ciphertext with small precision (plaintext modulus " << NativeInteger(pLWE1)
              << ")---\n"
              << std::endl;

    std::vector<int32_t> x1Int(encodedLength1);
    std::transform(x1.begin(), x1.end(), x1Int.begin(), [&](const double& elem) {
        return static_cast<int32_t>(static_cast<int32_t>(std::round(elem)) % pLWE1);
    });
    ptxt1->SetLength(encodedLength1);
    std::cout << "Input x1: " << ptxt1->GetRealPackedValue() << "; which rounds to: " << x1Int << std::endl;
    std::cout << "FHEW decryption: ";
    LWEPlaintext result;
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE1);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // B: Second scheme switching case

    // Perform the precomputation for switching
    cc->EvalCKKStoFHEWPrecompute(scale2);

    // Transform the ciphertext from CKKS to FHEW (only for the number of inputs given)
    auto cTemp2 = cc->EvalCKKStoFHEW(c2, encodedLength2);

    std::cout << "\n---Decrypting switched ciphertext with large precision (plaintext modulus " << NativeInteger(pLWE2)
              << ")---\n"
              << std::endl;

    ptxt2->SetLength(encodedLength2);
    std::cout << "Input x2: " << ptxt2->GetRealPackedValue() << std::endl;
    std::cout << "FHEW decryption: ";
    for (uint32_t i = 0; i < cTemp2.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cTemp2[i], &result, pLWE2);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // C: Decompose the FHEW ciphertexts in smaller digits
    std::cout << "Decomposed values for digit size of " << NativeInteger(pLWE1) << ": " << std::endl;
    // Generate the bootstrapping keys (refresh and switching keys)
    ccLWE->BTKeyGen(privateKeyFHEW);

    for (uint32_t j = 0; j < cTemp2.size(); j++) {
        // Decompose the large ciphertext into small ciphertexts that fit in q
        auto decomp = ccLWE->EvalDecomp(cTemp2[j]);

        // Decryption
        auto p = ccLWE->GetMaxPlaintextSpace().ConvertToInt();
        LWECiphertext ct;
        for (size_t i = 0; i < decomp.size(); i++) {
            ct = decomp[i];
            LWEPlaintext resultDecomp;
            if (i == decomp.size() - 1) {
                p = pLWE2 /
                    std::pow((double)pLWE1, std::floor(std::log(pLWE2) /
                                          std::log(pLWE1)));  // The last digit should be up to P / p^floor(log_p(P))
            }
            ccLWE->Decrypt(privateKeyFHEW, ct, &resultDecomp, p);
            std::cout << "(" << resultDecomp << " * " << NativeInteger(pLWE1) << "^" << i << ")";
            if (i != decomp.size() - 1) {
                std::cout << " + ";
            }
        }
        std::cout << std::endl;
    }
}

void SwitchFHEWtoCKKS() {
    std::cout << "\n-----SwitchFHEWtoCKKS-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS to be switched into

    // A. Specify main parameters
    ScalingTechnique scTech = FIXEDAUTO;
    uint32_t multDepth =
        3 + 9 + 1;  // for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 8192;
    SecurityLevel sl      = HEStd_NotSet;  // If this is not HEStd_NotSet, ensure ringDim is compatible
    uint32_t logQ_ccLWE   = 28;

    // uint32_t slots = ringDim/2; // Uncomment for fully-packed
    uint32_t slots     = 16;  // sparsely-packed
    uint32_t batchSize = slots;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto ccLWE = std::make_shared<BinFHEContext>();
    ccLWE->BinFHEContext::GenerateBinFHEContext(TOY, false, logQ_ccLWE, 0, GINX, false);

    // LWE private key
    LWEPrivateKey lwesk;
    lwesk = ccLWE->KeyGen();

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Step 3. Precompute the necessary keys and information for switching from FHEW to CKKS
    cc->EvalFHEWtoCKKSSetup(ccLWE, slots, logQ_ccLWE);

    cc->EvalFHEWtoCKKSKeyGen(keys, lwesk);

    // Step 4: Encoding and encryption of inputs
    // For correct CKKS decryption, the messages have to be much smaller than the FHEW plaintext modulus!

    auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    uint32_t pLWE2   = 256;                                           // Medium precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE3       = modulus_LWE / (2 * beta);  // Large precision
    // Inputs
    std::vector<int> x1 = {1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0};
    std::vector<int> x2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
        x2.insert(x2.end(), zeros.begin(), zeros.end());
    }

    // Encrypt
    std::vector<LWECiphertext> ctxtsLWE1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE1[i] =
            ccLWE->Encrypt(lwesk, x1[i]);  // encrypted under small plantext modulus p = 4 and ciphertext modulus
    }

    std::vector<LWECiphertext> ctxtsLWE2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE2[i] =
            ccLWE->Encrypt(lwesk, x1[i], FRESH,
                           pLWE1);  // encrypted under larger plaintext modulus p = 16 but small ciphertext modulus
    }

    std::vector<LWECiphertext> ctxtsLWE3(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE3[i] =
            ccLWE->Encrypt(lwesk, x2[i], FRESH, pLWE2,
                           modulus_LWE);  // encrypted under larger plaintext modulus and large ciphertext modulus
    }

    std::vector<LWECiphertext> ctxtsLWE4(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE4[i] =
            ccLWE->Encrypt(lwesk, x2[i], FRESH, pLWE3,
                           modulus_LWE);  // encrypted under large plaintext modulus and large ciphertext modulus
    }

    // Step 5. Perform the scheme switching
    auto cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE1, slots, slots);

    std::cout << "\n---Input x1: " << x1 << " encrypted under p = " << 4 << " and Q = " << ctxtsLWE1[0]->GetModulus()
              << "---" << std::endl;

    // Step 6. Decrypt
    Plaintext plaintextDec;
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(slots);
    std::cout << "Switched CKKS decryption 1: " << plaintextDec << std::endl;

    // Step 5'. Perform the scheme switching
    cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE2, slots, slots, pLWE1, 0, pLWE1);

    std::cout << "\n---Input x1: " << x1 << " encrypted under p = " << NativeInteger(pLWE1)
              << " and Q = " << ctxtsLWE2[0]->GetModulus() << "---" << std::endl;

    // Step 6'. Decrypt
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(slots);
    std::cout << "Switched CKKS decryption 2: " << plaintextDec << std::endl;

    // Step 5''. Perform the scheme switching
    cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE3, slots, slots, pLWE2, 0, pLWE2);

    std::cout << "\n---Input x2: " << x2 << " encrypted under p = " << pLWE2
              << " and Q = " << ctxtsLWE3[0]->GetModulus() << "---" << std::endl;

    // Step 6''. Decrypt
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(slots);
    std::cout << "Switched CKKS decryption 3: " << plaintextDec << std::endl;

    // Step 5'''. Perform the scheme switching
    std::setprecision(logQ_ccLWE + 10);
    auto cTemp2 = cc->EvalFHEWtoCKKS(ctxtsLWE4, slots, slots, pLWE3, 0, pLWE3);

    std::cout << "\n---Input x2: " << x2 << " encrypted under p = " << NativeInteger(pLWE3)
              << " and Q = " << ctxtsLWE4[0]->GetModulus() << "---" << std::endl;

    // Step 6'''. Decrypt
    Plaintext plaintextDec2;
    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots);
    std::cout << "Switched CKKS decryption 4: " << plaintextDec2 << std::endl;
}

void FloorViaSchemeSwitching() {
    std::cout << "\n-----FloorViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    ScalingTechnique scTech = FIXEDAUTO;

    uint32_t multDepth =
        3 + 9 + 1;  // for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 8192;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE   = 23;
    uint32_t slots        = 16;  // sparsely-packed
    uint32_t batchSize    = slots;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    bool arbFunc    = false;
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(sl, slBin, arbFunc, logQ_ccLWE, false, slots);

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, slots);

    // Generate bootstrapping key for EvalFloor
    ccLWE->BTKeyGen(privateKeyFHEW);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Set the scaling factor to be able to decrypt; the LWE mod switch is performed on the ciphertext at the last level
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();

    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    double scFactor = cryptoParams->GetScalingFactorReal(0);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        scFactor = cryptoParams->GetScalingFactorReal(1);
    double scaleCF = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE);

    cc->EvalCKKStoFHEWPrecompute(scaleCF);

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Scheme switching from CKKS to FHEW
    auto cTemp = cc->EvalCKKStoFHEW(c1);

    // Step 5: Evaluate the floor function
    uint32_t bits = 2;

    std::vector<LWECiphertext> cFloor(cTemp.size());
    for (uint32_t i = 0; i < cTemp.size(); i++) {
        cFloor[i] = ccLWE->EvalFloor(cTemp[i], bits);
    }

    std::cout << "Input x1: " << ptxt1->GetRealPackedValue() << std::endl;
    std::cout << "Expected result for EvalFloor with " << bits << " bits: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(ptxt1->GetRealPackedValue()[i]) >> bits) << " ";
    }
    LWEPlaintext pFloor;
    std::cout << "\nFHEW decryption p = " << NativeInteger(pLWE)
              << "/(1 << bits) = " << NativeInteger(pLWE) / (1 << bits) << ": ";
    for (uint32_t i = 0; i < cFloor.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cFloor[i], &pFloor, pLWE / (1 << bits));
        std::cout << pFloor << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 6: Scheme switching from FHEW to CKKS
    auto cTemp2 = cc->EvalFHEWtoCKKS(cFloor, slots, slots, pLWE / (1 << bits), 0, pLWE / (1 << bits));

    Plaintext plaintextDec2;
    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots);
    std::cout << "Switched floor decryption modulus_LWE mod " << NativeInteger(pLWE) / (1 << bits) << ": "
              << plaintextDec2 << std::endl;
}

void FuncViaSchemeSwitching() {
    std::cout << "\n-----FuncViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    uint32_t multDepth    = 9 + 3 + 2;  // 1 for CKKS to FHEW, 14 for FHEW to CKKS
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 2048;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE   = 25;
    bool arbFunc          = true;
    uint32_t slots        = 8;  // sparsely-packed
    uint32_t batchSize    = slots;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << std::endl << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(sl, slBin, arbFunc, logQ_ccLWE, false, slots);

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, slots);

    // Generate the bootstrapping keys for EvalFunc in FHEW
    ccLWE->BTKeyGen(privateKeyFHEW);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Set the scaling factor to be able to decrypt; the LWE mod switch is performed on the ciphertext at the last level
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();
    auto pLWE =
        ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision because GenerateLUTviaFunction needs p < q
    double scFactor = cryptoParams->GetScalingFactorReal(0);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        scFactor = cryptoParams->GetScalingFactorReal(1);
    double scaleCF = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE);

    cc->EvalCKKStoFHEWPrecompute(scaleCF);

    // Step 3: Initialize the function

    // Initialize Function f(x) = x^3 + 2x + 1 % p
    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        if (m < p1)
            return (m * m * m + 2 * m * m + 1) % p1;
        else
            return ((m - p1 / 2) * (m - p1 / 2) * (m - p1 / 2) + 2 * (m - p1 / 2) * (m - p1 / 2) + 1) % p1;
    };

    // Generate LUT from function f(x)
    auto lut = ccLWE->GenerateLUTviaFunction(fp, pLWE);

    // Step 4: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 0.3, 2.0, 4.0, 5.0, 6.0, 7.0, 8.0};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 5: Scheme switching from CKKS to FHEW
    auto cTemp = cc->EvalCKKStoFHEW(c1);

    std::cout << "Input x1: " << ptxt1->GetRealPackedValue() << std::endl;
    std::cout << "FHEW decryption: ";
    LWEPlaintext result;
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE);
        std::cout << result << " ";
    }

    // Step 6: Evaluate the function
    std::vector<LWECiphertext> cFunc(cTemp.size());
    for (uint32_t i = 0; i < cTemp.size(); i++) {
        cFunc[i] = ccLWE->EvalFunc(cTemp[i], lut);
    }

    std::cout << "\nExpected result x^3 + 2*x + 1 mod p: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << fp(static_cast<int>(x1[i]) % pLWE, pLWE) << " ";
    }
    LWEPlaintext pFunc;
    std::cout << "\nFHEW decryption mod " << NativeInteger(pLWE) << ": ";
    for (uint32_t i = 0; i < cFunc.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cFunc[i], &pFunc, pLWE);
        std::cout << pFunc << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 7: Scheme switching from FHEW to CKKS
    auto cTemp2 = cc->EvalFHEWtoCKKS(cFunc, slots, slots, pLWE, 0, pLWE);

    Plaintext plaintextDec2;
    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots);
    std::cout << "\nSwitched decryption modulus_LWE mod " << NativeInteger(pLWE)
              << " works only for messages << p: " << plaintextDec2 << std::endl;

    // Transform through arcsine
    cTemp2 = cc->EvalFHEWtoCKKS(cFunc, slots, slots, 4, 0, 2);

    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots);
    std::cout << "Arcsin(switched result) * p/2pi gives the correct result if messages are < p/4: ";
    for (uint32_t i = 0; i < slots; i++) {
        double x = std::max(std::min(plaintextDec2->GetRealPackedValue()[i], 1.0), -1.0);
        std::cout << std::asin(x) * pLWE / (2 * Pi) << " ";
    }
    std::cout << "\n";
}

void ComparisonViaSchemeSwitching() {
    std::cout << "\n-----ComparisonViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    ScalingTechnique scTech = FIXEDAUTO;
    uint32_t multDepth      = 17;
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 8192;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE   = 25;
    uint32_t slots        = 16;  // sparsely-packed
    uint32_t batchSize    = slots;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetNumLargeDigits(3);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(sl, slBin, false, logQ_ccLWE, false, slots);

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;
    ccLWE->BTKeyGen(privateKeyFHEW);

    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, slots);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Set the scaling factor to be able to decrypt; the LWE mod switch is performed on the ciphertext at the last level
    auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE2       = modulus_LWE / (2 * beta);  // Large precision

    double scaleSignFHEW    = 1.0;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    uint32_t init_level     = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    cc->EvalCompareSwitchPrecompute(pLWE2, init_level, scaleSignFHEW);

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
    std::vector<double> x2(slots, 5.25);

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, slots);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2, 1, 0, nullptr, slots);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    // Compute the difference to compare to zero
    auto cDiff = cc->EvalSub(c1, c2);

    // Step 4: CKKS to FHEW switching and sign evaluation to test correctness
    Plaintext pDiff;
    cc->Decrypt(keys.secretKey, cDiff, &pDiff);
    pDiff->SetLength(slots);
    std::cout << "Difference of inputs: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << pDiff->GetRealPackedValue()[i] << " ";
    }

    const double eps = 0.0001;
    std::cout << "\nExpected sign result from CKKS: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << int(std::round(pDiff->GetRealPackedValue()[i] / eps) * eps < 0) << " ";
    }
    std::cout << "\n";

    auto LWECiphertexts = cc->EvalCKKStoFHEW(cDiff, slots);

    LWEPlaintext plainLWE;
    std::cout << "\nFHEW decryption with plaintext modulus " << NativeInteger(pLWE2) << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, LWECiphertexts[i], &plainLWE, pLWE2);
        std::cout << plainLWE << " ";
    }

    std::cout << "\nExpected sign result in FHEW with plaintext modulus " << NativeInteger(pLWE2) << " and scale "
              << scaleSignFHEW << ": ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(std::round(pDiff->GetRealPackedValue()[i] * scaleSignFHEW)) % pLWE2 -
                          pLWE2 / 2.0 >=
                      0)
                  << " ";
    }
    std::cout << "\n";

    std::cout << "Obtained sign result in FHEW with plaintext modulus " << NativeInteger(pLWE2) << " and scale "
              << scaleSignFHEW << ": ";
    std::vector<LWECiphertext> LWESign(LWECiphertexts.size());
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        LWESign[i] = ccLWE->EvalSign(LWECiphertexts[i]);
        ccLWE->Decrypt(privateKeyFHEW, LWESign[i], &plainLWE, 2);
        std::cout << plainLWE << " ";
    }
    std::cout << "\n";

    // Step 5: Direct comparison via CKKS->FHEW->CKKS
    auto cResult = cc->EvalCompareSchemeSwitching(c1, c2, slots, slots);

    Plaintext plaintextDec3;
    cc->Decrypt(keys.secretKey, cResult, &plaintextDec3);
    plaintextDec3->SetLength(slots);
    std::cout << "Decrypted switched result: " << plaintextDec3 << std::endl;

    // Step 2': Recompute the scaled matrix using a larger scaling
    scaleSignFHEW = 8.0;
    cc->EvalCompareSwitchPrecompute(pLWE2, init_level, scaleSignFHEW);

    // Step 4': CKKS to FHEW switching and sign evaluation to test correctness
    LWECiphertexts = cc->EvalCKKStoFHEW(cDiff, slots);

    std::cout << "\nFHEW decryption with plaintext modulus " << NativeInteger(pLWE2) << " and scale " << scaleSignFHEW
              << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, LWECiphertexts[i], &plainLWE, pLWE2);
        std::cout << plainLWE << " ";
    }
    std::cout << "\nExpected sign result in FHEW with plaintext modulus " << NativeInteger(pLWE2) << " and scale "
              << scaleSignFHEW << ": ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(std::round(pDiff->GetRealPackedValue()[i] * scaleSignFHEW)) % pLWE2 -
                          pLWE2 / 2.0 >=
                      0)
                  << " ";
    }
    std::cout << "\n";
    std::cout << "Obtained sign result in FHEW with plaintext modulus " << NativeInteger(pLWE2) << " and scale "
              << scaleSignFHEW << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        LWESign[i] = ccLWE->EvalSign(LWECiphertexts[i]);
        ccLWE->Decrypt(privateKeyFHEW, LWESign[i], &plainLWE, 2);
        std::cout << plainLWE << " ";
    }
    std::cout << "\n";

    // Step 5': Direct comparison via CKKS->FHEW->CKKS
    cResult = cc->EvalCompareSchemeSwitching(c1, c2, slots, slots);

    cc->Decrypt(keys.secretKey, cResult, &plaintextDec3);
    plaintextDec3->SetLength(slots);
    std::cout << "Decrypted switched result: " << plaintextDec3 << std::endl;

    // Step 2'': Recompute the scaled matrix using other parameters
    std::cout
        << "\nFor very small LWE plaintext modulus and initial fractional inputs, the sign does not always behave properly close to the boundaries at 0 and p/2."
        << std::endl;
    scaleSignFHEW = 1.0;
    cc->EvalCompareSwitchPrecompute(pLWE1, init_level, scaleSignFHEW);

    // Step 4'': CKKS to FHEW switching and sign evaluation to test correctness
    LWECiphertexts = cc->EvalCKKStoFHEW(cDiff, slots);

    std::cout << "\nFHEW decryption with plaintext modulus " << NativeInteger(pLWE1) << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, LWECiphertexts[i], &plainLWE, pLWE1);
        std::cout << plainLWE << " ";
    }
    std::cout << "\nExpected sign result in FHEW with plaintext modulus " << NativeInteger(pLWE1) << " and scale "
              << scaleSignFHEW << ": ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(std::round(pDiff->GetRealPackedValue()[i] * scaleSignFHEW)) % pLWE1 -
                          pLWE1 / 2.0 >=
                      0)
                  << " ";
    }
    std::cout << "\n";
    std::cout << "Obtained sign result in FHEW with plaintext modulus " << NativeInteger(pLWE1) << " and scale "
              << scaleSignFHEW << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        LWESign[i] = ccLWE->EvalSign(LWECiphertexts[i]);
        ccLWE->Decrypt(privateKeyFHEW, LWESign[i], &plainLWE, 2);
        std::cout << plainLWE << " ";
    }
    std::cout << "\n";

    // Step 5'': Direct comparison via CKKS->FHEW->CKKS
    cResult = cc->EvalCompareSchemeSwitching(c1, c2, slots, slots, 0, scaleSignFHEW);

    cc->Decrypt(keys.secretKey, cResult, &plaintextDec3);
    plaintextDec3->SetLength(slots);
    std::cout << "Decrypted switched result: " << plaintextDec3 << std::endl;
}

void ArgminViaSchemeSwitching() {
    std::cout << "\n-----ArgminViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 8192;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE   = 25;
    bool arbFunc          = false;
    bool oneHot           = true;  // Change to false if the output should not be one-hot encoded

    uint32_t slots          = 16;  // sparsely-packed
    uint32_t batchSize      = slots;
    uint32_t numValues      = 16;
    ScalingTechnique scTech = FIXEDAUTO;
    uint32_t multDepth =
        9 + 3 + 1 + static_cast<int>(std::log2(numValues));  // 13 for FHEW to CKKS, log2(numValues) for argmin
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto FHEWparams     = cc->EvalSchemeSwitchingSetup(sl, slBin, arbFunc, logQ_ccLWE, false, slots);
    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, numValues, true, oneHot);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scaleSign = 512.0;
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    uint32_t init_level     = 0;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    // This formulation is for clarity
    cc->EvalCompareSwitchPrecompute(pLWE, init_level, scaleSign);
    // But we can also include the scaleSign in pLWE (here we use the fact both pLWE and scaleSign are powers of two)
    // cc->EvalCompareSwitchPrecompute(pLWE / scaleSign, init_level, 1);

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < numValues) {
        std::vector<int> zeros(numValues - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::min_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::max_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl
              << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);  // Only if we we set batchsize
    // Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, slots); // If batchsize is not set

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation
    auto result = cc->EvalMinSchemeSwitching(c1, keys.publicKey, numValues, slots, oneHot);

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);
    if (oneHot) {
        ptxtMin->SetLength(numValues);
        std::cout << "Argmin indicator vector: " << ptxtMin << std::endl;
    }
    else {
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }

    result = cc->EvalMaxSchemeSwitching(c1, keys.publicKey, numValues, slots, oneHot);

    Plaintext ptxtMax;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    ptxtMax->SetLength(1);
    std::cout << "Maximum value: " << ptxtMax << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMax);
    if (oneHot) {
        ptxtMax->SetLength(numValues);
        std::cout << "Argmax indicator vector: " << ptxtMax << std::endl;
    }
    else {
        ptxtMax->SetLength(1);
        std::cout << "Argmax: " << ptxtMax << std::endl;
    }
}

void ArgminViaSchemeSwitchingAlt() {
    std::cout << "\n-----ArgminViaSchemeSwitchingAlt-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 8192;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE   = 25;
    bool arbFunc          = false;
    bool oneHot           = true;  // Change to false if the output should not be one-hot encoded
    bool alt =
        true;  // alternative mode of argmin which has fewer rotation keys and does more operations in FHEW than in CKKS

    uint32_t slots          = 16;  // sparsely-packed
    uint32_t batchSize      = slots;
    uint32_t numValues      = 16;
    ScalingTechnique scTech = FIXEDAUTO;
    uint32_t multDepth =
        9 + 3 + 1 + static_cast<int>(std::log2(numValues));  // 13 for FHEW to CKKS, log2(numValues) for argmin
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto FHEWparams     = cc->EvalSchemeSwitchingSetup(sl, slBin, arbFunc, logQ_ccLWE, false, slots);
    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, numValues, true, oneHot, alt);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scaleSign = 512.0;
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    uint32_t init_level     = 0;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    // This formulation is for clarity
    cc->EvalCompareSwitchPrecompute(pLWE, init_level, scaleSign);
    // But we can also include the scaleSign in pLWE (here we use the fact both pLWE and scaleSign are powers of two)
    // cc->EvalCompareSwitchPrecompute(pLWE / scaleSign, init_level, 1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < numValues) {
        std::vector<int> zeros(numValues - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::min_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::max_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl
              << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);  // Only if we we set batchsize
    // Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, slots); // If batchsize is not set

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation
    auto result = cc->EvalMinSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots, oneHot);

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);
    if (oneHot) {
        ptxtMin->SetLength(numValues);
        std::cout << "Argmin indicator vector: " << ptxtMin << std::endl;
    }
    else {
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }

    result = cc->EvalMaxSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots, oneHot);

    Plaintext ptxtMax;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    ptxtMax->SetLength(1);
    std::cout << "Maximum value: " << ptxtMax << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMax);
    if (oneHot) {
        ptxtMax->SetLength(numValues);
        std::cout << "Argmax indicator vector: " << ptxtMax << std::endl;
    }
    else {
        ptxtMax->SetLength(1);
        std::cout << "Argmax: " << ptxtMax << std::endl;
    }
}

void ArgminViaSchemeSwitchingUnit() {
    std::cout << "\n-----ArgminViaSchemeSwitchingUnit-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 8192;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE   = 25;
    bool arbFunc          = false;
    bool oneHot           = true;

    uint32_t slots          = 32;  // sparsely-packed
    uint32_t batchSize      = slots;
    uint32_t numValues      = 32;
    ScalingTechnique scTech = FLEXIBLEAUTOEXT;
    uint32_t multDepth =
        9 + 3 + 1 +
        static_cast<int>(std::log2(numValues));  // 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(numValues) for argmin
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);
    cc->Enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(sl, slBin, arbFunc, logQ_ccLWE, false, slots);

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, numValues, true, oneHot);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    uint32_t init_level     = 0;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    // Here we assume the message does not need scaling, as they are in the unit circle.
    cc->EvalCompareSwitchPrecompute(1, init_level, 1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    std::cout << "Input: " << x1 << std::endl;

    /* Here we to assume each element of x1 is between (-0.5, 0.5]. The user will use heuristics on the size of the plaintext to achieve this.
     * This will mean that even the difference of the messages will be between (-1,1].
     * However, if a good enough approximation of the maximum is not available and the scaled inputs are too small, the precision of the result
     * might not be good enough.
     */
    double p = 1 << (firstModSize - scaleModSize - 1);
    std::transform(x1.begin(), x1.end(), x1.begin(), [&](const double& elem) { return elem / (2 * p); });

    std::cout << "Input scaled: " << x1 << std::endl;
    std::cout << "Expected minimum value " << *(std::min_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::min_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::max_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl
              << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation
    auto result = cc->EvalMinSchemeSwitching(c1, keys.publicKey, numValues, slots, oneHot);

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);
    if (oneHot) {
        ptxtMin->SetLength(numValues);
        std::cout << "Argmin indicator vector: " << ptxtMin << std::endl;
    }
    else {
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }

    result = cc->EvalMaxSchemeSwitching(c1, keys.publicKey, numValues, slots, oneHot);

    Plaintext ptxtMax;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    ptxtMax->SetLength(1);
    std::cout << "Maximum value: " << ptxtMax << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMax);
    if (oneHot) {
        ptxtMax->SetLength(numValues);
        std::cout << "Argmax indicator vector: " << ptxtMax << std::endl;
    }
    else {
        ptxtMax->SetLength(1);
        std::cout << "Argmax: " << ptxtMax << std::endl;
    }
}

void ArgminViaSchemeSwitchingAltUnit() {
    std::cout << "\n-----ArgminViaSchemeSwitchingAltUnit-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 8192;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE   = 25;
    bool arbFunc          = false;
    bool oneHot           = true;
    bool alt =
        true;  // alternative mode of argmin which has fewer rotation keys and does more operations in FHEW than in CKKS

    uint32_t slots          = 32;  // sparsely-packed
    uint32_t batchSize      = slots;
    uint32_t numValues      = 32;
    ScalingTechnique scTech = FLEXIBLEAUTOEXT;
    uint32_t multDepth =
        9 + 3 + 1 +
        static_cast<int>(std::log2(numValues));  // 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(numValues) for argmin
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);
    cc->Enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(sl, slBin, arbFunc, logQ_ccLWE, false, slots);

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, numValues, true, oneHot, alt);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    uint32_t init_level     = 0;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    // Here we assume the message does not need scaling, as they are in the unit circle.
    cc->EvalCompareSwitchPrecompute(1, init_level, 1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    std::cout << "Input: " << x1 << std::endl;

    /* Here we to assume each element of x1 is between (-0.5, 0.5]. The user will use heuristics on the size of the plaintext to achieve this.
     * This will mean that even the difference of the messages will be between (-1,1].
     * However, if a good enough approximation of the maximum is not available and the scaled inputs are too small, the precision of the result
     * might not be good enough.
     */
    double p = 1 << (firstModSize - scaleModSize - 1);
    std::transform(x1.begin(), x1.end(), x1.begin(), [&](const double& elem) { return elem / (2 * p); });

    std::cout << "Input scaled: " << x1 << std::endl;
    std::cout << "Expected minimum value " << *(std::min_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::min_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::max_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl
              << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation
    auto result = cc->EvalMinSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots, oneHot);

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);
    if (oneHot) {
        ptxtMin->SetLength(numValues);
        std::cout << "Argmin indicator vector: " << ptxtMin << std::endl;
    }
    else {
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }

    result = cc->EvalMaxSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots, oneHot);

    Plaintext ptxtMax;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    ptxtMax->SetLength(1);
    std::cout << "Maximum value: " << ptxtMax << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMax);
    if (oneHot) {
        ptxtMax->SetLength(numValues);
        std::cout << "Argmax indicator vector: " << ptxtMax << std::endl;
    }
    else {
        ptxtMax->SetLength(1);
        std::cout << "Argmax: " << ptxtMax << std::endl;
    }
}

void PolyViaSchemeSwitching() {
    std::cout << "\n-----PolyViaSchemeSwitching-----\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS to be switched into

    // A. Specify main parameters
    ScalingTechnique scTech = FIXEDAUTO;
    uint32_t multDepth =
        3 + 9 + 1 +
        2;  // for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling, 3 levels for functionality
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 2048;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE   = 25;

    uint32_t slots     = 16;  // sparsely-packed
    uint32_t batchSize = slots;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(sl, slBin, false, logQ_ccLWE, false, slots);

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    // Step 3. Precompute the necessary keys and information for switching from FHEW to CKKS and back
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, slots);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE2       = modulus_LWE / (2 * beta);  // Large precision

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();
    double scFactor                               = cryptoParams->GetScalingFactorReal(0);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        scFactor = cryptoParams->GetScalingFactorReal(1);
    double scale1 = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE1);
    double scale2 = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE2);

    // Generate keys for the CKKS intermediate computation
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1, 2});

    // Step 4: Encoding and encryption of inputs
    // For correct CKKS decryption, the messages have to be much smaller than the FHEW plaintext modulus!
    // Inputs
    std::vector<int32_t> x1 = {1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0};
    std::vector<int32_t> x2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    std::vector<int32_t> x1Rot(RotateInt(x1, 1));
    std::transform(x1Rot.begin(), x1Rot.end(), x1.begin(), x1Rot.begin(), std::plus<int>());
    std::vector<int32_t> x1Int(slots);
    std::transform(x1Rot.begin(), x1Rot.end(), x1Int.begin(), [&](const int32_t& elem) {
        return static_cast<int32_t>(static_cast<int32_t>(std::round(0.25 * elem * elem)) % pLWE1);
    });

    std::vector<int32_t> x2Rot(RotateInt(x2, 2));
    std::transform(x2Rot.begin(), x2Rot.end(), x2.begin(), x2Rot.begin(), std::plus<int>());
    std::vector<int32_t> x2Int(slots);
    std::transform(x2Rot.begin(), x2Rot.end(), x2Int.begin(), [&](const int32_t& elem) {
        return static_cast<int32_t>(static_cast<int32_t>(std::round(0.25 * elem * elem)) % pLWE2);
    });

    // Encrypt
    std::vector<LWECiphertext> ctxtsLWE1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE1[i] = ccLWE->Encrypt(privateKeyFHEW,
                                      x1[i]);  // encrypted under small plantext modulus p = 4 and ciphertext modulus
    }

    std::vector<LWECiphertext> ctxtsLWE2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE2[i] =
            ccLWE->Encrypt(privateKeyFHEW, x2[i], FRESH, pLWE2,
                           modulus_LWE);  // encrypted under large plaintext modulus and large ciphertext modulus
    }

    // Step 5. Perform the scheme switching
    auto cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE1, slots, slots);

    std::cout << "\nInput x1: " << x1 << " encrypted under p = " << 4 << " and Q = " << ctxtsLWE1[0]->GetModulus()
              << std::endl;
    std::cout << "round( 0.5 * (x1 + rot(x1,1) )^2 ): " << x1Int << std::endl;

    // Step 6. Perform the desired computation in CKKS
    auto cPoly = cc->EvalAdd(cTemp, cc->EvalRotate(cTemp, 1));
    cPoly      = cc->EvalMult(cc->EvalMult(cPoly, cPoly), 0.25);

    // Perform the precomputation for switching back to CKKS
    cc->EvalCKKStoFHEWPrecompute(scale1);

    // Transform the ciphertext from CKKS to FHEW
    auto cTemp1 = cc->EvalCKKStoFHEW(cPoly, slots);

    LWEPlaintext result;
    std::cout << "FHEW decryption with plaintext modulus " << NativeInteger(pLWE1) << ": ";
    for (uint32_t i = 0; i < cTemp1.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cTemp1[i], &result, pLWE1);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 5'. Perform the scheme switching
    cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE2, slots, slots, pLWE2, 0, pLWE2);

    std::cout << "\nInput x2: " << x2 << " encrypted under p = " << NativeInteger(pLWE2)
              << " and Q = " << ctxtsLWE2[0]->GetModulus() << std::endl;
    std::cout << "round( 0.5 * (x1 + rot(x2,2) )^2 ): " << x2Int << std::endl;

    // Step 6'. Perform the desired computation in CKKS
    cPoly = cc->EvalAdd(cTemp, cc->EvalRotate(cTemp, 2));
    cPoly = cc->EvalMult(cc->EvalMult(cPoly, cPoly), 0.25);

    // Perform the precomputation for switching back to CKKS
    cc->EvalCKKStoFHEWPrecompute(scale2);

    // Transform the ciphertext from CKKS to FHEW
    auto cTemp2 = cc->EvalCKKStoFHEW(cPoly, slots);

    std::cout << "FHEW decryption with plaintext modulus " << NativeInteger(pLWE2) << ": ";
    for (uint32_t i = 0; i < cTemp2.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cTemp2[i], &result, pLWE2);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;
}

std::vector<int32_t> RotateInt(const std::vector<int32_t>& a, int32_t index) {
    int32_t slots = a.size();

    std::vector<int32_t> result(slots);

    if (index < 0 || index > slots) {
        index = ReduceRotation(index, slots);
    }

    if (index == 0) {
        result = a;
    }

    else {
        // two cases: i+index <= slots and i+index > slots
        for (int32_t i = 0; i < slots - index; i++) {
            result[i] = a[i + index];
        }
        for (int32_t i = slots - index; i < slots; i++) {
            result[i] = a[i + index - slots];
        }
    }

    return result;
}
