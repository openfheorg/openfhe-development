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

#define PROFILE

#include "openfhe.h"
#include "binfhecontext.h"
#include "fhew_bt_coeff.h"
#include <queue>
// #include <malloc.h>

using namespace lbcrypto;
using namespace std;

// GLOBAL VARIABLES
std::vector<std::vector<int64_t>> m_UT;
std::vector<ConstPlaintext> m_UTPre;
uint32_t m_dim1BF;
uint32_t m_LBF;
int64_t PTXT_MOD          = 65537;
uint64_t cntInnerPoly     = 0;
double timeMultConst      = 0;
double timeAddConst       = 0;
double timeRotations      = 0;
double timeMultPtxt       = 0;
double timePolyClear      = 0;
double timeMultCtxt       = 0;
double timeSquareCtxt     = 0;
double timeAddCtxt        = 0;
double timeClone          = 0;
double timeRotationPrec   = 0;
double timePackedPtxt     = 0;
double timePackedPrePtxt  = 0;
double timeDeg            = 0;
double timeLongDiv        = 0;
uint64_t cntMultConst     = 0;
uint64_t cntAddConst      = 0;
uint64_t cntRotations     = 0;
uint64_t cntMultPtxt      = 0;
uint64_t cntMultCtxt      = 0;
uint64_t cntSquareCtxt    = 0;
uint64_t cntAddCtxt       = 0;
uint64_t cntClone         = 0;
uint64_t cntRotationPrec  = 0;
uint64_t cntPackedPtxt    = 0;
uint64_t cntPackedPrePtxt = 0;
uint64_t cntDeg           = 0;
uint32_t cntLongDiv       = 0;

// FUNCTIONS
void NANDthroughBFV();
void LUTthroughBFV();

Ciphertext<DCRTPoly> EvalFHEWtoBFV(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<LWECiphertext>& lweCtxt,
                                   const std::vector<Ciphertext<DCRTPoly>>& keyCtxt);
Ciphertext<DCRTPoly> EvalPartialHomDecryptionOrig(const CryptoContextImpl<DCRTPoly>& cc,
                                                  const std::vector<std::vector<int64_t>>& A,
                                                  const std::vector<Ciphertext<DCRTPoly>>& ct);
Ciphertext<DCRTPoly> EvalMatMultCol(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<Plaintext>& A,
                                    const std::vector<Ciphertext<DCRTPoly>>& ct);
std::vector<Plaintext> EvalMatMultColPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                const std::vector<std::vector<int64_t>>& A, uint32_t L);
Ciphertext<DCRTPoly> EvalMatMultColWithoutPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                     const std::vector<std::vector<int64_t>>& A,
                                                     const std::vector<Ciphertext<DCRTPoly>>& ct);

std::vector<ConstPlaintext> EvalLTNPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                              const std::vector<std::vector<int64_t>>& A, uint32_t dim1, uint32_t L,
                                              double scale = 1);
void EvalSlotsToCoeffsPrecompute(const CryptoContextImpl<DCRTPoly>& cc, double scale, bool precompute);
Ciphertext<DCRTPoly> EvalLTNWithPrecompute(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                           const std::vector<ConstPlaintext>& A, uint32_t dim1);
Ciphertext<DCRTPoly> EvalLTNWithoutPrecompute(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                              const std::vector<std::vector<int64_t>>& A, uint32_t dim1);
Ciphertext<DCRTPoly> EvalSlotsToCoeffs(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                       bool precompute = false);

uint64_t ModDownConst(const int64_t constant, const NativeInteger t);
int64_t ModDownHalfConst(const int64_t constant, const NativeInteger t);
Ciphertext<DCRTPoly> EvalAddConstBFV(ConstCiphertext<DCRTPoly> ciphertext, const int64_t constant);
void EvalAddInPlaceConstBFV(Ciphertext<DCRTPoly>& ciphertext, const int64_t constant);

Ciphertext<DCRTPoly> EvalLinearWSumBFV(const std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                       const std::vector<int64_t>& constants);
Ciphertext<DCRTPoly> EvalLinearWSumMutableBFV(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                              const std::vector<int64_t>& constants);
void EvalMultCoreInPlaceBFV(Ciphertext<DCRTPoly>& ciphertext, const int64_t constant);
Ciphertext<DCRTPoly> EvalMultConstBFV(ConstCiphertext<DCRTPoly> ciphertext, const int64_t constant);

Ciphertext<DCRTPoly> InnerEvalPolyPSBFV(ConstCiphertext<DCRTPoly> x, const std::vector<int64_t>& coefficients,
                                        uint32_t k, uint32_t m, std::vector<Ciphertext<DCRTPoly>>& powers,
                                        std::vector<Ciphertext<DCRTPoly>>& powers2);
Ciphertext<DCRTPoly> EvalPolyPSBFV(ConstCiphertext<DCRTPoly> x, const std::vector<int64_t>& coefficients,
                                   bool symmetric = false);

void InnerEvalPolyPSBFVPrecompute(const std::vector<int64_t>& coefficients, uint32_t k, uint32_t m);
void EvalPolyPSBFVPrecompute(const std::vector<int64_t>& coefficients);
Ciphertext<DCRTPoly> InnerEvalPolyPSBFVWithPrecompute(ConstCiphertext<DCRTPoly> x, uint32_t k, uint32_t m,
                                                      std::vector<Ciphertext<DCRTPoly>>& powers,
                                                      std::vector<Ciphertext<DCRTPoly>>& powers2);
Ciphertext<DCRTPoly> EvalPolyPSBFVWithPrecompute(ConstCiphertext<DCRTPoly> x, bool symmetric = false);

struct longDivMod {
    std::vector<int64_t> q;
    std::vector<int64_t> r;
    longDivMod() {}
    longDivMod(const std::vector<int64_t>& q0, const std::vector<int64_t>& r0) : q(q0), r(r0) {}
};
uint32_t m_nPS;
uint32_t m_kPS;
uint32_t m_mPS;
std::vector<queue<std::shared_ptr<longDivMod>>> qr;
std::vector<queue<std::shared_ptr<longDivMod>>> cs;
std::shared_ptr<longDivMod> LongDivisionPolyMod(const std::vector<int64_t>& f, const std::vector<int64_t>& g,
                                                int64_t q = PTXT_MOD);

uint32_t Degree(const std::vector<int64_t>& coefficients);
uint32_t FindFirstNonZero(const std::vector<int64_t>& coefficients);
uint32_t CountNonZero(const std::vector<int64_t>& coefficients);
std::vector<int64_t> Rotate(const std::vector<int64_t>& a, int32_t index);
std::vector<int64_t> Fill(const std::vector<int64_t>& a, int32_t slots);
std::vector<int64_t> ExtractShiftedDiagonalN(const std::vector<std::vector<int64_t>>& A, int32_t idx_in,
                                             int32_t idx_out);
std::vector<int32_t> FindLTNRotationIndices(uint32_t dim1, uint32_t N);
uint32_t getRatioBSGSPow2(uint32_t slots);

struct schemeSwitchKeys {
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>
        FHEWtoBFVKey;  // Only for column method, otherwise it is a single ciphertext
    lbcrypto::EvalKey<lbcrypto::DCRTPoly> BFVtoFHEWSwk;
    schemeSwitchKeys() {}
    schemeSwitchKeys(const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& key1,
                     const lbcrypto::EvalKey<lbcrypto::DCRTPoly>& key2)
        : FHEWtoBFVKey(key1), BFVtoFHEWSwk(key2) {}
};
std::shared_ptr<schemeSwitchKeys> EvalAmortizedFHEWBootKeyGen(CryptoContextImpl<DCRTPoly>& cc,
                                                              const KeyPair<DCRTPoly>& keyPair,
                                                              ConstLWEPrivateKey& lwesk,
                                                              const PrivateKey<DCRTPoly> privateKeyKS, uint32_t dim1,
                                                              uint32_t L);

std::vector<LWECiphertext> EvalBFVtoFHEW(const CryptoContextImpl<DCRTPoly>& cc, const CryptoContextImpl<DCRTPoly>& ccKS,
                                         ConstCiphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly> ctxtKS,
                                         lbcrypto::EvalKey<lbcrypto::DCRTPoly> BFVtoFHEWSwk,
                                         NativeInteger modulus_BFV_to, NativeInteger modulus_FHEW, uint32_t n);
void ModSwitchDown(ConstCiphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly>& ctxtKS, NativeInteger modulus_to);
std::vector<std::shared_ptr<LWECiphertextImpl>> ExtractAndScaleLWE(const CryptoContextImpl<DCRTPoly>& cc,
                                                                   ConstCiphertext<DCRTPoly> ctxt, uint32_t n,
                                                                   NativeInteger modulus_from,
                                                                   NativeInteger modulus_to);
std::shared_ptr<LWECiphertextImpl> ExtractLWECiphertextShort(const std::vector<std::vector<NativeInteger>>& aANDb,
                                                             NativeInteger modulus, uint32_t n, uint32_t index);
std::vector<std::vector<NativeInteger>> ExtractLWEpacked(ConstCiphertext<DCRTPoly> ct);

EvalKey<DCRTPoly> switchingKeyGenRLWEcc(const PrivateKey<DCRTPoly>& bfvSKto, const PrivateKey<DCRTPoly>& bfvSKfrom,
                                        ConstLWEPrivateKey& LWEsk);
NativeInteger RoundqQAlter(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q);

std::vector<LWECiphertext> EvalNANDAmortized(std::vector<LWECiphertext> ctxtsLWE1, std::vector<LWECiphertext> ctxtsLWE2,
                                             NativeInteger q, bool opt = true);

NativePoly DecryptWithoutDecoding(ConstCiphertext<DCRTPoly> ctxt, const PrivateKey<DCRTPoly> privateKey);
std::vector<int64_t> EvalPolyCleartextMod(std::vector<int64_t> input, std::vector<int64_t> coeff, const int64_t t,
                                          bool symmetric = false);

uint32_t FindLevelsToDrop(usint multiplicativeDepth, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                          uint32_t dcrtBits, bool keySwitch = false);

int main() {
    // NANDthroughBFV();
    LUTthroughBFV();

    return 0;
}

void NANDthroughBFV() {
    std::cout << "\n*****AMORTIZED NAND*****\n" << std::endl;

    TimeVar tVar, tOnline;
    TIC(tVar);

    // Step 0. Meta-parameter
    bool opt = true;  // false;

    cntInnerPoly      = 0;
    timeMultConst     = 0;
    timeAddConst      = 0;
    timeRotations     = 0;
    timeMultPtxt      = 0;
    timeMultCtxt      = 0;
    timeSquareCtxt    = 0;
    timePolyClear     = 0;
    timeAddCtxt       = 0;
    timeClone         = 0;
    timeRotationPrec  = 0;
    timePackedPtxt    = 0;
    timePackedPrePtxt = 0;
    timeLongDiv       = 0;
    cntMultConst      = 0;
    cntAddConst       = 0;
    cntRotations      = 0;
    cntMultPtxt       = 0;
    cntMultCtxt       = 0;
    cntSquareCtxt     = 0;
    cntAddCtxt        = 0;
    cntClone          = 0;
    cntRotationPrec   = 0;
    cntPackedPtxt     = 0;
    cntPackedPrePtxt  = 0;
    cntLongDiv        = 0;

    // Step 1. FHEW cryptocontext generation
    auto ccLWE            = BinFHEContext();
    const uint32_t n      = 1024;
    const uint32_t NN     = 1024;  // RSGW ring dim. Not used
    const uint32_t p      = 3;
    const NativeInteger q = 65537;
    const NativeInteger Q = 18014398509404161;

    ccLWE.BinFHEContext::GenerateBinFHEContext(n, NN, q, Q, 3.19, 32, 32, 32, UNIFORM_TERNARY, GINX, 10);
    auto params = ccLWE.GetParams();
    auto QFHEW  = ccLWE.GetParams()->GetLWEParams()->Getq();

    // Print the FHEW Params
    std::cout << "FHEW params:\np = " << p << ", n = " << n << ", q = " << q << std::endl << std::endl;

    // LWE private key
    LWEPrivateKey lwesk;
    lwesk = ccLWE.KeyGen();

    // Step 2. Main BFV cryptocontext generation
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(
        q.ConvertToInt());  // The BFV plaintext modulus needs to be the same as the FHEW ciphertext modulus
    parameters.SetMultiplicativeDepth(18);
    parameters.SetMaxRelinSkDeg(3);
    parameters.SetFirstModSize(60);
    parameters.SetKeySwitchTechnique(HYBRID);  // BV doesn't work for Compress then KeySwitch
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(32768);
    CryptoContext<DCRTPoly> ccBFV = GenCryptoContext(parameters);

    uint32_t ringDim   = ccBFV->GetRingDimension();
    uint32_t numValues = 8;

    ccBFV->Enable(PKE);
    ccBFV->Enable(KEYSWITCH);
    ccBFV->Enable(LEVELEDSHE);
    ccBFV->Enable(ADVANCEDSHE);

    // BFV private and public keys
    auto keys = ccBFV->KeyGen();

    // Print the BFV params
    std::cout << "BFV params:\nt = " << ccBFV->GetCryptoParameters()->GetPlaintextModulus() << ", N = " << ringDim
              << ", log2 q = " << log2(ccBFV->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl
              << std::endl;

    // Step 3. Intermediate BFV cruptocontext generation
    CCParams<CryptoContextBFVRNS> parameters_KS;
    parameters_KS.SetPlaintextModulus(
        q.ConvertToInt());  // The BFV plaintext modulus needs to be the same as the FHEW ciphertext modulus
    parameters_KS.SetMultiplicativeDepth(0);
    parameters_KS.SetMaxRelinSkDeg(3);
    parameters_KS.SetRingDim(ringDim);
    parameters_KS.SetFirstModSize(27);
    parameters_KS.SetKeySwitchTechnique(HYBRID);  // BV doesn't work for Compress then KeySwitch
    parameters_KS.SetSecurityLevel(HEStd_NotSet);
    parameters_KS.SetMultiplicationTechnique(HPSPOVERQ);  // Don't need HPSPOVERQLEVELED here
    CryptoContext<DCRTPoly> ccBFV_KS = GenCryptoContext(parameters_KS);

    ccBFV_KS->Enable(PKE);
    ccBFV_KS->Enable(KEYSWITCH);
    ccBFV_KS->Enable(LEVELEDSHE);
    ccBFV_KS->Enable(ADVANCEDSHE);

    auto keys_KS = ccBFV_KS->KeyGen();

    // Ciphertext with intermediate cryptocontext used to switch the ciphertext from the large cryptocontext
    Plaintext ptxtZeroKS = ccBFV_KS->MakePackedPlaintext(std::vector<int64_t>{0});
    auto ctxtKS          = ccBFV_KS->Encrypt(keys_KS.publicKey, ptxtZeroKS);
    ctxtKS               = ccBFV_KS->Compress(ctxtKS, 1);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ccBFV->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_BFV_from                         = paramsQ[0]->GetModulus();

    const auto cryptoParams2 = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ccBFV_KS->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams2 = *(cryptoParams2->GetElementParams());
    auto paramsQ2                                  = elementParams2.GetParams();
    auto modulus_BFV_to                            = paramsQ2[0]->GetModulus();

    std::cout << "modulus_BFV_from: " << modulus_BFV_from << ", modulus_BFV_to: " << modulus_BFV_to << std::endl;

    double timeCC = TOC_NS(tVar);
    std::cout << "---Time to generate cryptocontexts: " << timeCC / 1000000000.0 << " s\n" << std::endl;

    // Step 4. Key generation for switching and precomputations
    TIC(tVar);
    auto keyStruct = EvalAmortizedFHEWBootKeyGen(
        *ccBFV, keys, lwesk, keys_KS.secretKey, 0,
        0);  // Automorphism keys for homomorphic decoding, FHEW to BFV key and BFV to FHEW key
    auto ctxt_vec_LWE_sk = keyStruct->FHEWtoBFVKey;
    auto BFVtoFHEWSwk    = keyStruct->BFVtoFHEWSwk;

    EvalSlotsToCoeffsPrecompute(*ccBFV, 1, true);

    std::vector<int64_t> coeff;
    if (opt) {
        coeff = DRaMgate_coeff_opt;
    }
    else {
        coeff = DRaMgate_coeff_t;
    }
    if (q == 17) {
        coeff = DRaMgate_coeff_test_17;
    }
    EvalPolyPSBFVPrecompute(coeff);

    // std::cout << "\nDecoding matrix = " << m_UT << std::endl;
    double timePrecomp = TOC_NS(tVar);
    std::cout << "---Time for key generation and precomputations: " << timePrecomp / 1000000000.0 << " s" << std::endl;
    std::cout << "out of which the time for " << cntPackedPrePtxt
              << " plaintexts encodings is: " << timePackedPrePtxt / 1000000000.0 << " s" << std::endl
              << std::endl;

    // Step 5. Inputs and encryption
    TIC(tOnline);
    TIC(tVar);
    std::vector<int32_t> x1 = {1, 1, 1, 1, 1, 1, 1, 1};
    if (x1.size() < numValues) {
        vector<int32_t> zeros(numValues - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }

    std::vector<int32_t> x2 = {1, 1, 1, 1, 0, 0, 0, 0};
    if (x2.size() < numValues) {
        vector<int32_t> zeros(numValues - x2.size(), 0);
        x2.insert(x2.end(), zeros.begin(), zeros.end());
    }

    // LWE SKE
    std::vector<LWECiphertext> ctxtsLWE1(numValues);
    for (uint32_t i = 0; i < numValues; i++) {
        ctxtsLWE1[i] = ccLWE.Encrypt(lwesk, x1[i], FRESH, p);
    }
    std::vector<LWECiphertext> ctxtsLWE2(numValues);
    for (uint32_t i = 0; i < numValues; i++) {
        ctxtsLWE2[i] = ccLWE.Encrypt(lwesk, x2[i], FRESH, p);
    }

    std::cout << "Encrypted LWE messages" << std::endl;
    std::vector<LWEPlaintext> LWEptxt(numValues);
    for (uint32_t i = 0; i < numValues; i++) {
        ccLWE.Decrypt(lwesk, ctxtsLWE1[i], &LWEptxt[i], p);
    }
    std::cout << LWEptxt << std::endl;
    for (uint32_t i = 0; i < numValues; i++) {
        ccLWE.Decrypt(lwesk, ctxtsLWE2[i], &LWEptxt[i], p);
    }
    std::cout << LWEptxt << std::endl;

    double timeEnc = TOC_NS(tVar);
    std::cout << "---Time for encryption: " << timeEnc / 1000000000.0 << " s\n" << std::endl;

    // Step 5. Start evaluating NAND: add the LWE ciphertexts (+ range alignment depending on opt)
    TIC(tVar);
    auto preBootCtxt = EvalNANDAmortized(ctxtsLWE1, ctxtsLWE2, q, opt);

    // std::cout << "Positive sum of LWE messages" << std::endl;
    // for (uint32_t i = 0; i < numValues; i++) {
    //     ccLWE.Decrypt(lwesk, preBootCtxt[i], &LWEptxt[i]);
    // }
    // std::cout << LWEptxt << std::endl;

    // malloc_trim(0);

    // Step 6. Conversion from LWE to RLWE
    Ciphertext<DCRTPoly> BminusAdotS = EvalFHEWtoBFV(*ccBFV, preBootCtxt, ctxt_vec_LWE_sk);

    // malloc_trim(0);

    // Plaintext ptxt;
    // ccBFV->Decrypt(keys.secretKey, BminusAdotS, &ptxt);
    // ptxt->SetLength(numValues);
    // std::cout << "B - A*s: " << ptxt << std::endl;

    double timeFHEWtoBFV = TOC_NS(tVar);
    std::cout << "---Time FHEWtoBFV: " << timeFHEWtoBFV / 1000000000.0 << " s\n" << std::endl;

    // // Test the matrix-vector multiplication
    // std::vector<int64_t> LWE_sk(n);
    // for (size_t i = 0; i < n; ++i) {
    //     Plaintext LWE_sk_ptxt;
    //     ccBFV->Decrypt(keys.secretKey, ctxt_vec_LWE_sk[i], &LWE_sk_ptxt);
    //     LWE_sk_ptxt->SetLength(1);
    //     LWE_sk[i] = LWE_sk_ptxt->GetPackedValue()[0];
    // }

    // std::vector<std::vector<int64_t>> A(numValues);
    // vector<int64_t> b(numValues);
    // NativeVector a_v(n);
    // for(size_t i = 0; i < numValues; ++i){
    // A[i].resize(n);
    // a_v = preBootCtxt[i]->GetA();
    // for(size_t j = 0; j < n; ++j){
    //  A[i][j] = a_v[j].ConvertToInt();
    // }
    // b[i] = preBootCtxt[i]->GetB().ConvertToInt();
    // }

    // std::vector<int64_t> res(A.size(), 0);
    // for (size_t i = 0; i < A.size(); ++i) {
    // for (size_t j = 0; j < A[0].size(); ++j) {
    //  res[i] += A[i][j] * LWE_sk[j];
    // }
    // res[i] = ModDownHalfConst(b[i] - res[i], q);
    // }
    // std::cout << "Cleartext B - A*s % q: " << res << std::endl;

    // Step 7. Polynomial evaluation for division, rounding and modding down
    TIC(tVar);
    // auto ctxt_poly = EvalPolyPSBFV(BminusAdotS, coeff, opt);  // symmetric function which has zero odd coefficients
    auto ctxt_poly = EvalPolyPSBFVWithPrecompute(BminusAdotS, opt);

    // malloc_trim(0);

    Plaintext ptxt_res;
    // ccBFV->Decrypt(keys.secretKey, ctxt_poly, &ptxt_res);
    // ptxt_res->SetLength(numValues);
    // std::cout << "\nEvaluated polynomial: " << ptxt_res << std::endl;

    std::cout << "Number of recursions in EvalPolyPS: " << cntInnerPoly << std::endl;

    double timePS = TOC_NS(tVar);
    std::cout << "---Time to evaluate the polynomial of degree " << coeff.size() - 1 << " for opt = " << opt << ": "
              << timePS / 1000000000.0 << " s\n"
              << std::endl;
    timePolyClear += timePS;

    // std::vector<int64_t> decoded_int(numValues);
    // for (size_t i = 0; i < numValues; ++i) {
    //     decoded_int[i] = ModDownConst(ptxt->GetPackedValue()[i], q.ConvertToInt());
    // }
    // auto clear_res = EvalPolyCleartextMod(decoded_int, coeff, q.ConvertToInt(), opt);
    // std::cout << "Cleartext evaluated polynomial: " << clear_res << std::endl;

    // Step 7. Decoding
    TIC(tVar);
    auto decoded = EvalSlotsToCoeffs(*ccBFV, ctxt_poly, true);

    // malloc_trim(0);

    // Plaintext ptxt_dec;
    // ccBFV->Decrypt(keys.secretKey, decoded, &ptxt_dec);
    // ptxt_dec->SetLength(numValues);
    // std::cout << "Decoded: " << ptxt_dec << std::endl;

    double timeDecode = TOC_NS(tVar);
    std::cout << "---Time for slots to coeff: " << timeDecode / 1000000000.0 << " s\n" << std::endl;

    // std::vector<int64_t> prod(m_UT.size(), 0);
    // for (size_t i = 0; i < m_UT.size(); ++i) {
    //     for (size_t j = 0; j < m_UT[0].size(); ++j) {
    //         prod[i] += m_UT[i][j] * ptxt_res->GetPackedValue()[j];
    //     }
    //     prod[i] = ModDownHalfConst(prod[i], q);
    // }
    // std::cout << "Cleartext prod: " << prod << std::endl;

    // auto element     = DecryptWithoutDecoding(decoded, keys.secretKey);
    // auto element_vec = element.GetValues();
    // std::vector<int64_t> signed_vec(element_vec.GetLength());
    // for (size_t i = 0; i < element_vec.GetLength(); ++i) {
    //     signed_vec[i] = ModDownHalfConst(element_vec[i].ConvertToInt(), q);
    // }
    // std::cout << "Decrypt without decoding the decoded result (should be the same as evaluated poly) = \n"
    //           << signed_vec << std::endl;

    // Step 8. Translating back to FHEW
    TIC(tVar);
    auto ctxtsFHEW = EvalBFVtoFHEW(*ccBFV, *ccBFV_KS, decoded, ctxtKS, BFVtoFHEWSwk, modulus_BFV_to, QFHEW, n);

    // malloc_trim(0);

    std::cout << "\nDecrypting switched ciphertexts" << std::endl;
    vector<LWEPlaintext> ptxtsFHEW(numValues);
    for (uint32_t i = 0; i < numValues; i++) {
        ccLWE.Decrypt(lwesk, ctxtsFHEW[i], &ptxtsFHEW[i], p);
    }
    std::cout << ptxtsFHEW << std::endl;

    double timeBFVtoFHEW = TOC_NS(tVar);
    std::cout << "---Time BFVtoFHEW: " << timeBFVtoFHEW / 1000000000.0 << " s\n" << std::endl;

    double timeOnline = TOC_NS(tOnline);
    std::cout << "---Time for online computation: " << timeOnline / 1000000000.0 << " s; amortized for " << ringDim
              << " slots: " << timeOnline / ringDim / 1000000000.0 << " s \n"
              << std::endl;

    std::cout << "-Time for " << cntMultConst << " multiplications by a constant: " << timeMultConst / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntAddConst << " additions by a constant: " << timeAddConst / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntRotations << " fast rotations: " << timeRotations / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntRotationPrec << " fast rotation precomputation: " << timeRotationPrec / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntMultPtxt << " multiplications by plaintexts: " << timeMultPtxt / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntMultCtxt << " ciphertext multiplications: " << timeMultCtxt / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntAddCtxt
              << " ciphertext additions not counted before: " << timeAddCtxt / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for cleartext poly operations: " << timePolyClear / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntClone << " ciphertext cloning: " << timeClone / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntLongDiv << " retrieving and popping coefficients: " << timeLongDiv / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntPackedPtxt
              << " plaintexts encodings in hom. decoding: " << timePackedPtxt / 1000000000.0 << " s" << std::endl
              << std::endl;
}

void LUTthroughBFV() {
    std::cout << "\n*****AMORTIZED LUT*****\n" << std::endl;

    TimeVar tVar, tOnline;
    TIC(tVar);

    cntInnerPoly      = 0;
    timeMultConst     = 0;
    timeAddConst      = 0;
    timeRotations     = 0;
    timeMultPtxt      = 0;
    timeMultCtxt      = 0;
    timeSquareCtxt    = 0;
    timePolyClear     = 0;
    timeAddCtxt       = 0;
    timeClone         = 0;
    timeRotationPrec  = 0;
    timePackedPrePtxt = 0;
    timePackedPtxt    = 0;
    timeDeg           = 0;
    timeLongDiv       = 0;
    cntMultConst      = 0;
    cntAddConst       = 0;
    cntRotations      = 0;
    cntMultPtxt       = 0;
    cntMultCtxt       = 0;
    cntSquareCtxt     = 0;
    cntAddCtxt        = 0;
    cntClone          = 0;
    cntRotationPrec   = 0;
    cntPackedPtxt     = 0;
    cntPackedPrePtxt  = 0;
    cntDeg            = 0;
    cntLongDiv        = 0;

    // Step 1. FHEW cryptocontext generation
    auto ccLWE            = BinFHEContext();
    const uint32_t n      = 1024;
    const uint32_t NN     = 1024;  // RSGW ring dim. Not used
    const uint32_t p      = 512;
    const NativeInteger q = 65537;
    const NativeInteger Q = 18014398509404161;

    ccLWE.BinFHEContext::GenerateBinFHEContext(n, NN, q, Q, 3.19, 32, 32, 32, UNIFORM_TERNARY, GINX, 10);
    auto params = ccLWE.GetParams();
    auto QFHEW  = ccLWE.GetParams()->GetLWEParams()->Getq();

    // Print the FHEW Params
    std::cout << "FHEW params:\np = " << p << ", n = " << n << ", q = " << q << std::endl << std::endl;

    // LWE private key
    LWEPrivateKey lwesk;
    lwesk = ccLWE.KeyGen();

    // Step 2. Main BFV cryptocontext generation
    uint32_t numDigits = 3;
    uint32_t maxRelin  = 2;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(
        q.ConvertToInt());  // The BFV plaintext modulus needs to be the same as the FHEW ciphertext modulus
    parameters.SetMultiplicativeDepth(18);
    parameters.SetMaxRelinSkDeg(maxRelin);
    parameters.SetNumLargeDigits(numDigits);
    parameters.SetFirstModSize(60);
    parameters.SetKeySwitchTechnique(HYBRID);  // BV doesn't work for Compress then KeySwitch
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(32768);
    CryptoContext<DCRTPoly> ccBFV = GenCryptoContext(parameters);

    uint32_t ringDim   = ccBFV->GetRingDimension();
    uint32_t numValues = 8;

    ccBFV->Enable(PKE);
    ccBFV->Enable(KEYSWITCH);
    ccBFV->Enable(LEVELEDSHE);
    ccBFV->Enable(ADVANCEDSHE);

    // BFV private and public keys
    auto keys = ccBFV->KeyGen();

    // Print the BFV params
    std::cout << "BFV params:\nt = " << ccBFV->GetCryptoParameters()->GetPlaintextModulus() << ", N = " << ringDim
              << ", log2 q = " << log2(ccBFV->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl
              << std::endl;

    std::cout << "Number of digits for keyswitch: " << numDigits << std::endl;
    std::cout << "MaxRelinSkDeg: " << maxRelin << std::endl << std::endl;

    // Step 3. Intermediate BFV cruptocontext generation
    CCParams<CryptoContextBFVRNS> parameters_KS;
    parameters_KS.SetPlaintextModulus(
        q.ConvertToInt());  // The BFV plaintext modulus needs to be the same as the FHEW ciphertext modulus
    parameters_KS.SetMultiplicativeDepth(0);
    parameters_KS.SetMaxRelinSkDeg(2);
    parameters_KS.SetRingDim(ringDim);
    parameters_KS.SetFirstModSize(27);
    parameters_KS.SetKeySwitchTechnique(HYBRID);  // BV doesn't work for Compress then KeySwitch
    parameters_KS.SetSecurityLevel(HEStd_NotSet);
    parameters_KS.SetMultiplicationTechnique(HPSPOVERQ);  // Don't need HPSPOVERQLEVELED here
    CryptoContext<DCRTPoly> ccBFV_KS = GenCryptoContext(parameters_KS);

    ccBFV_KS->Enable(PKE);
    ccBFV_KS->Enable(KEYSWITCH);
    ccBFV_KS->Enable(LEVELEDSHE);
    ccBFV_KS->Enable(ADVANCEDSHE);

    auto keys_KS = ccBFV_KS->KeyGen();

    // Ciphertext with intermediate cryptocontext used to switch the ciphertext from the large cryptocontext
    Plaintext ptxtZeroKS = ccBFV_KS->MakePackedPlaintext(std::vector<int64_t>{0});
    auto ctxtKS          = ccBFV_KS->Encrypt(keys_KS.publicKey, ptxtZeroKS);
    ctxtKS               = ccBFV_KS->Compress(ctxtKS, 1);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ccBFV->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_BFV_from                         = paramsQ[0]->GetModulus();

    const auto cryptoParams2 = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ccBFV_KS->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams2 = *(cryptoParams2->GetElementParams());
    auto paramsQ2                                  = elementParams2.GetParams();
    auto modulus_BFV_to                            = paramsQ2[0]->GetModulus();

    std::cout << "modulus_BFV_from: " << modulus_BFV_from << ", modulus_BFV_to: " << modulus_BFV_to << std::endl;

    double timeCC = TOC_NS(tVar);
    std::cout << "---Time to generate cryptocontexts: " << timeCC / 1000000000.0 << " s\n" << std::endl;

    // Step 4. Key generation for switching and precomputations
    TIC(tVar);
    auto keyStruct = EvalAmortizedFHEWBootKeyGen(
        *ccBFV, keys, lwesk, keys_KS.secretKey, 128,
        0);  // Automorphism keys for homomorphic decoding, FHEW to BFV key and BFV to FHEW key
    auto ctxt_vec_LWE_sk = keyStruct->FHEWtoBFVKey;
    auto BFVtoFHEWSwk    = keyStruct->BFVtoFHEWSwk;

    EvalSlotsToCoeffsPrecompute(*ccBFV, 1, true);

    // LUT to evaluate
    std::vector<int64_t> coeff(DRaMLUT_coeff_sqrt_9);
    EvalPolyPSBFVPrecompute(coeff);

    double timePrecomp = TOC_NS(tVar);
    std::cout << "---Time for key generation and precomputation: " << timePrecomp / 1000000000.0 << " s" << std::endl;
    std::cout << "out of which the time for " << cntPackedPrePtxt
              << " plaintexts encodings is: " << timePackedPrePtxt / 1000000000.0 << " s" << std::endl
              << std::endl;
    // Step 5. Inputs and encryption
    TIC(tOnline);
    TIC(tVar);
    vector<int32_t> x1 = {-4, 0, 1, 4, 9, 16, 121, 144};
    if (x1.size() < numValues) {
        vector<int32_t> zeros(numValues - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }

    // LWE SKE
    std::vector<LWECiphertext> ctxtsLWE1(numValues);
    for (uint32_t i = 0; i < numValues; i++) {
        ctxtsLWE1[i] = ccLWE.Encrypt(lwesk, x1[i], FRESH,
                                     p);  // encrypted under small plantext modulus p and automatic ciphertext modulus
    }

    std::cout << "Encrypted LWE message" << std::endl;
    std::vector<LWEPlaintext> LWEptxt(numValues);
    for (uint32_t i = 0; i < numValues; i++) {
        ccLWE.Decrypt(lwesk, ctxtsLWE1[i], &LWEptxt[i], p);
    }
    std::cout << LWEptxt << std::endl;

    double timeEnc = TOC_NS(tVar);
    std::cout << "---Time for encryption: " << timeEnc / 1000000000.0 << " s\n" << std::endl;

    // Step 6. Conversion from LWE to RLWE
    TIC(tVar);
    Ciphertext<DCRTPoly> BminusAdotS = EvalFHEWtoBFV(*ccBFV, ctxtsLWE1, ctxt_vec_LWE_sk);

    // Plaintext ptxt;
    // ccBFV->Decrypt(keys.secretKey, BminusAdotS, &ptxt);
    // ptxt->SetLength(numValues);
    // std::cout << "B - A*s: " << ptxt << std::endl;

    double timeFHEWtoBFV = TOC_NS(tVar);
    std::cout << "---Time FHEWtoBFV: " << timeFHEWtoBFV / 1000000000.0 << " s\n" << std::endl;

    std::cout << "---Online time so far: " << TOC_NS(tOnline) / 1000000000.0 << " s\n" << std::endl;

    std::cout << "-Time for " << cntMultConst << " multiplications by a constant: " << timeMultConst / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntAddConst << " additions by a constant: " << timeAddConst / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntRotations << " fast rotations: " << timeRotations / 1000000000.0 << "s"
              << std::endl;
    std::cout << "-Time for " << cntRotationPrec << " fast rotation precomputation: " << timeRotationPrec / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntMultPtxt << " multiplications by plaintexts: " << timeMultPtxt / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntMultCtxt << " ciphertext multiplications: " << timeMultCtxt / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntSquareCtxt << " ciphertext squarings: " << timeSquareCtxt / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntAddCtxt
              << " ciphertext additions not counted before: " << timeAddCtxt / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for cleartext poly operations: " << timePolyClear / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntClone << " ciphertext cloning: " << timeClone / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntDeg << " degree computation: " << timeDeg / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntLongDiv << " retrieving and popping coefficients: " << timeLongDiv / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntPackedPtxt
              << " plaintexts encodings in hom. decoding: " << timePackedPtxt / 1000000000.0 << " s" << std::endl
              << std::endl;

    // // Test the matrix-vector multiplication
    // std::vector<int64_t> LWE_sk(n);
    // for (size_t i = 0; i < n; ++i) {
    //     Plaintext LWE_sk_ptxt;
    //     ccBFV->Decrypt(keys.secretKey, ctxt_vec_LWE_sk[i], &LWE_sk_ptxt);
    //     LWE_sk_ptxt->SetLength(1);
    //     LWE_sk[i] = LWE_sk_ptxt->GetPackedValue()[0];
    // }

    // std::vector<std::vector<int64_t>> A(numValues);
    // vector<int64_t> b(numValues);
    // NativeVector a_v(n);
    // for(size_t i = 0; i < numValues; ++i){
    //  A[i].resize(n);
    //  a_v = ctxtsLWE1[i]->GetA();
    //  for(size_t j = 0; j < n; ++j){
    //      A[i][j] = a_v[j].ConvertToInt();
    //  }
    //  b[i] = ctxtsLWE1[i]->GetB().ConvertToInt();
    // }

    // std::vector<int64_t> res(A.size(), 0);
    // for (size_t i = 0; i < A.size(); ++i) {
    //  for (size_t j = 0; j < A[0].size(); ++j) {
    //      res[i] += A[i][j] * LWE_sk[j];
    //  }
    //  res[i] = ModDownHalfConst(b[i] - res[i], q);
    // }
    // std::cout << "Cleartext B - A*s % q: " << res << std::endl;

    // Step 7. Polynomial evaluation for rounding and modding down
    TIC(tVar);
    // auto ctxt_poly = EvalPolyPSBFV(BminusAdotS, coeff, false);
    auto ctxt_poly = EvalPolyPSBFVWithPrecompute(BminusAdotS, false);

    // Plaintext ptxt_res;
    // ccBFV->Decrypt(keys.secretKey, ctxt_poly, &ptxt_res);
    // ptxt_res->SetLength(numValues);
    // std::cout << "\nEvaluated polynomial: " << ptxt_res << std::endl;

    std::cout << "Number of recursions in EvalPolyPS: " << cntInnerPoly << std::endl;

    double timePS = TOC_NS(tVar);
    std::cout << "---Time to evaluate the polynomial of degree " << coeff.size() - 1 << ": " << timePS / 1000000000.0
              << " s\n"
              << std::endl;
    timePolyClear += timePS;

    std::cout << "---Online time so far: " << TOC_NS(tOnline) / 1000000000.0 << " s\n" << std::endl;

    std::cout << "-Time for " << cntMultConst << " multiplications by a constant: " << timeMultConst / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntAddConst << " additions by a constant: " << timeAddConst / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntRotations << " fast rotations: " << timeRotations / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntRotationPrec << " fast rotation precomputation: " << timeRotationPrec / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntMultPtxt << " multiplications by plaintexts: " << timeMultPtxt / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntMultCtxt << " ciphertext multiplications: " << timeMultCtxt / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntSquareCtxt << " ciphertext squarings: " << timeSquareCtxt / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntAddCtxt
              << " ciphertext additions not counted before: " << timeAddCtxt / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for cleartext poly operations: " << timePolyClear / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntClone << " ciphertext cloning: " << timeClone / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntDeg << " degree computation: " << timeDeg / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntLongDiv << " retrieving and popping coefficients: " << timeLongDiv / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntPackedPtxt
              << " plaintexts encodings in hom. decoding: " << timePackedPtxt / 1000000000.0 << " s" << std::endl
              << std::endl;

    // std::vector<int64_t> decoded_int(ringDim);
    // for(size_t i = 0; i < ringDim; ++i) {
    //     decoded_int[i] = ModDownConst(ptxt->GetPackedValue()[i], q.ConvertToInt());
    // }
    // auto clear_res = EvalPolyCleartextMod(decoded_int, coeff, q.ConvertToInt());
    // std::cout << "Cleartext evaluated polynomial: " << clear_res << std::endl;

    // Step 7. Decoding
    TIC(tVar);
    auto decoded = EvalSlotsToCoeffs(*ccBFV, ctxt_poly, true);

    // Plaintext ptxt_dec;
    // ccBFV->Decrypt(keys.secretKey, decoded, &ptxt_dec);
    // ptxt_dec->SetLength(numValues);
    // std::cout << "Decoded: " << ptxt_dec << std::endl;

    double timeDecode = TOC_NS(tVar);
    std::cout << "---Time for slots to coeff: " << timeDecode / 1000000000.0 << " s\n" << std::endl;

    std::cout << "---Online time so far: " << TOC_NS(tOnline) / 1000000000.0 << " s\n" << std::endl;

    std::cout << "-Time for " << cntMultConst << " multiplications by a constant: " << timeMultConst / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntAddConst << " additions by a constant: " << timeAddConst / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntRotations << " fast rotations: " << timeRotations / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntRotationPrec << " fast rotation precomputation: " << timeRotationPrec / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntMultPtxt << " multiplications by plaintexts: " << timeMultPtxt / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntMultCtxt << " ciphertext multiplications: " << timeMultCtxt / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntSquareCtxt << " ciphertext squarings: " << timeSquareCtxt / 1000000000.0 << " s"
              << std::endl;
    std::cout << "-Time for " << cntAddCtxt
              << " ciphertext additions not counted before: " << timeAddCtxt / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for cleartext poly operations: " << timePolyClear / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntClone << " ciphertext cloning: " << timeClone / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntDeg << " degree computation: " << timeDeg / 1000000000.0 << " s" << std::endl;
    std::cout << "-Time for " << cntLongDiv << " retrieving and popping coefficients: " << timeLongDiv / 1000000000.0
              << " s" << std::endl;
    std::cout << "-Time for " << cntPackedPtxt
              << " plaintexts encodings in hom. decoding: " << timePackedPtxt / 1000000000.0 << " s" << std::endl
              << std::endl;

    // std::vector<int64_t> prod(m_UT.size(), 0);
    // for (size_t i = 0; i < m_UT.size(); ++i) {
    //  for (size_t j = 0; j < m_UT[0].size(); ++j) {
    //      prod[i] += m_UT[i][j] * ptxt_res->GetPackedValue()[j];
    //  }
    //  prod[i] = ModDownHalfConst(prod[i], q);
    // }
    // std::cout << "Cleartext prod: " << prod << std::endl;

    // auto element = DecryptWithoutDecoding(decoded, keys.secretKey);
    // auto element_vec = element.GetValues();
    // std::vector<int64_t> signed_vec(element_vec.GetLength());
    // for (size_t i = 0; i < element_vec.GetLength(); ++i) {
    //  signed_vec[i] = ModDownHalfConst(element_vec[i].ConvertToInt(), q);
    // }
    // std::cout << "Decrypt without decoding the decoded result (should be the same as evaluated poly) = \n" << signed_vec << std::endl;

    // Step 8. Translating back to FHEW
    TIC(tVar);
    auto ctxtsFHEW = EvalBFVtoFHEW(*ccBFV, *ccBFV_KS, decoded, ctxtKS, BFVtoFHEWSwk, modulus_BFV_to, QFHEW, n);
    std::cout << "\nDecrypting switched ciphertexts" << std::endl;
    vector<LWEPlaintext> ptxtsFHEW(numValues);
    for (uint32_t i = 0; i < numValues; i++) {
        ccLWE.Decrypt(lwesk, ctxtsFHEW[i], &ptxtsFHEW[i], p);
    }
    std::cout << ptxtsFHEW << std::endl;
    double timeBFVtoFHEW = TOC_NS(tVar);
    std::cout << "---Time BFVtoFHEW: " << timeBFVtoFHEW / 1000000000.0 << " s" << std::endl;

    double timeOnline = TOC_NS(tOnline);
    std::cout << "---Time for online computation: " << timeOnline / 1000000000.0 << " s; amortized for " << ringDim
              << " slots: " << timeOnline / ringDim / 1000000000.0 << " s \n"
              << std::endl;
}

//------------------------------------------------------------------------------
// BFV OPERATIONS
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> EvalLinearWSumBFV(const std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                       const std::vector<int64_t>& constants) {
    auto size = std::min(ciphertexts.size(), constants.size());

    std::vector<Ciphertext<DCRTPoly>> cts(size);
    std::vector<int64_t> constantsNZ(size);

    TimeVar tVar;
    TIC(tVar);
    uint32_t pos = 0;
    for (uint32_t i = 0; i < size; i++) {
        if (constants[i] != 0) {
            cts[pos]         = ciphertexts[i]->Clone();
            constantsNZ[pos] = constants[i];
            pos += 1;
        }
    }
    timeClone += TOC_NS(tVar);
    cntClone += pos;

    return EvalLinearWSumMutableBFV(cts, constantsNZ);
}

// This does not actually modify ciphertexts, and it would be incorrect if it would
Ciphertext<DCRTPoly> EvalLinearWSumMutableBFV(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                              const std::vector<int64_t>& constants) {
    TimeVar tVar;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertexts[0]->GetCryptoParameters());

    auto cc   = ciphertexts[0]->GetCryptoContext();
    auto algo = cc->GetScheme();

    auto pos = FindFirstNonZero(constants);

    if (pos < ciphertexts.size()) {
        Ciphertext<DCRTPoly> weightedSum = EvalMultConstBFV(ciphertexts[pos], constants[pos]);

        Ciphertext<DCRTPoly> tmp;
        for (uint32_t i = pos + 1; i < ciphertexts.size(); i++) {
            if (constants[i] != 0) {
                tmp = EvalMultConstBFV(ciphertexts[i], constants[i]);
                TIC(tVar);
                cc->EvalAddInPlace(weightedSum, tmp);
                timeAddCtxt += TOC_NS(tVar);
                cntAddCtxt++;
            }
        }

        return weightedSum;
    }
    else {
        return ciphertexts[0]->CloneZero();
    }
}

Ciphertext<DCRTPoly> EvalMultConstBFV(ConstCiphertext<DCRTPoly> ciphertext, const int64_t constant) {
    TimeVar tVar;
    TIC(tVar);
    Ciphertext<DCRTPoly> ciphertext_res = ciphertext->Clone();
    timeClone += TOC_NS(tVar);
    cntClone++;
    EvalMultCoreInPlaceBFV(ciphertext_res, constant);
    return ciphertext_res;
}

Ciphertext<DCRTPoly> EvalAddConstBFV(ConstCiphertext<DCRTPoly> ciphertext, const int64_t constant) {
    TimeVar tVar;
    TIC(tVar);
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    timeClone += TOC_NS(tVar);
    cntClone++;
    EvalAddInPlaceConstBFV(result, constant);
    return result;
}

uint64_t ModDownConst(const int64_t constant, const NativeInteger t) {
    int64_t int_t        = t.ConvertToInt();
    int64_t mod_constant = constant % int_t;

    if (mod_constant < 0) {
        mod_constant += int_t;
    }
    return mod_constant;
}

int64_t ModDownHalfConst(const int64_t constant, const NativeInteger t) {
    int64_t int_t        = t.ConvertToInt();
    int64_t mod_constant = constant % int_t;

    if (mod_constant < -static_cast<int32_t>(int_t / 2)) {
        mod_constant += int_t;
    }
    else if (mod_constant >= int_t / 2) {
        mod_constant -= int_t;
    }
    return mod_constant;
}

void EvalMultCoreInPlaceBFV(Ciphertext<DCRTPoly>& ciphertext, const int64_t constant) {
    TimeVar tVar;
    TIC(tVar);

    // Ensure the constant is in the required range
    const NativeInteger t = ciphertext->GetCryptoParameters()->GetPlaintextModulus();

    NativeInteger mod_constant = ModDownConst(constant, t);

    std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    // for (usint i = 0; i < cv.size(); ++i) {
    //     cv[i] *= mod_constant;
    // }
    for (auto& c : cv) {
        c *= mod_constant;
    }

    timeMultConst += TOC_NS(tVar);
    cntMultConst++;

    // ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + 1); // If this is set, it might lead to more moduli being dropped
}

void EvalAddInPlaceConstBFV(Ciphertext<DCRTPoly>& ciphertext, const int64_t constant) {
    TimeVar tVar;
    TIC(tVar);
    const shared_ptr<ILDCRTParams<BigInteger>> params = ciphertext->GetElements()[0].GetParams();
    const auto cryptoParams   = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoParameters());
    std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    const NativeInteger& NegQModt              = cryptoParams->GetNegQModt();
    const NativeInteger& NegQModtPrecon        = cryptoParams->GetNegQModtPrecon();
    const std::vector<NativeInteger>& tInvModq = cryptoParams->GettInvModq();
    const NativeInteger t                      = cryptoParams->GetPlaintextModulus();

    // Ensure the constant is in the required range
    auto mod_constant = ModDownConst(constant, t);

    DCRTPoly constDCRTPoly(params, Format::COEFFICIENT, true);
    DCRTPoly tmp(constDCRTPoly);
    std::vector<int64_t> in;
    in.push_back(mod_constant);
    tmp.SetFormat(Format::COEFFICIENT);
    tmp = in;

    tmp.TimesQovert(cryptoParams->GetElementParams(), tInvModq, t, NegQModt, NegQModtPrecon);
    tmp.SetFormat(Format::EVALUATION);
    constDCRTPoly = std::move(tmp);
    cv[0] += constDCRTPoly;

    timeAddConst += TOC_NS(tVar);
    cntAddConst++;
}

//------------------------------------------------------------------------------
// UTILS + FUNCTIONS THAT SHOULD BE USED WITH TEMPLATES IN ckksrns-utils
//------------------------------------------------------------------------------
std::vector<int64_t> Rotate(const std::vector<int64_t>& a, int32_t index) {
    int32_t slots = a.size();

    std::vector<int64_t> result(slots);

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

std::vector<int64_t> Fill(const std::vector<int64_t>& a, int32_t slots) {
    int usedSlots = a.size();

    std::vector<int64_t> result(slots);

    for (int i = 0; i < slots; i++) {
        result[i] = a[i % usedSlots];
    }

    return result;
}

std::vector<int32_t> FindLTNRotationIndices(uint32_t dim1, uint32_t N) {
    // Computing the baby-step g and the giant-step h
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSPow2(N / 2) : dim1;
    uint32_t gStep = ceil(static_cast<double>(N / 2) / bStep);

    std::cout << "bStep = " << bStep << ", gStep = " << gStep << ", N = " << N << std::endl;

    // Computing all indices for baby-step giant-step procedure
    std::vector<int32_t> indexList;
    indexList.reserve(bStep + gStep - 1);
    for (uint32_t i = 0; i < bStep; i++) {
        indexList.emplace_back(i + 1);
    }
    for (uint32_t i = 2; i < gStep; i++) {
        indexList.emplace_back(bStep * i);
    }
    indexList.emplace_back(N / 2);

    // Remove possible duplicates
    sort(indexList.begin(), indexList.end());
    indexList.erase(unique(indexList.begin(), indexList.end()), indexList.end());

    // Remove automorphisms corresponding to 0
    indexList.erase(std::remove(indexList.begin(), indexList.end(), 0), indexList.end());

    return indexList;
}

uint32_t getRatioBSGSPow2(uint32_t slots) {
    return 1 << (lbcrypto::GetMSB(static_cast<uint32_t>(sqrt(slots))) - 1);
}

// Method to arrange diagonals of a matrix NxN such that it is compatible with BFV rotations, N is a power of 2
std::vector<int64_t> ExtractShiftedDiagonalN(const std::vector<std::vector<int64_t>>& A, int32_t idx_out,
                                             int32_t idx_in) {
    int32_t cols = A[0].size();
    int32_t rows = A.size();
    if (rows != cols)
        OPENFHE_THROW(config_error, "ExtractShiftedDiagonalN is implemented only for square matrices.");

    std::vector<int64_t> result(cols);

#pragma omp parallel for
    for (int32_t j = 0; j < cols; ++j) {
        auto row_idx = (j - idx_out) % (rows / 2);
        row_idx      = (row_idx < 0) ? row_idx + rows / 2 : row_idx;  // Because modulo can return negative value
        row_idx      = (j >= cols / 2) ? row_idx + rows / 2 : row_idx;
        auto col_idx = (j + idx_in) % (cols / 2);  // Because modulo can return negative value
        col_idx      = (col_idx < 0) ? col_idx + cols / 2 : col_idx;
        if (idx_in < rows / 2) {
            col_idx = (j >= cols / 2) ? col_idx + cols / 2 : col_idx;
        }
        else {
            col_idx = (j < cols / 2) ? col_idx + cols / 2 : col_idx;
        }
        result[j] = A[row_idx][col_idx];
    }

    return result;
}

/* f and g are vectors of coefficients of the two polynomials. We assume their dominant
coefficient is not zero. LongDivisionPoly returns the vector of coefficients for the
quotient and remainder of the division f/g. longDiv is a struct that contains the
vectors of coefficients for the quotient and rest. When input coefficients are integers, the
output coefficients are also integer. Moreover, we work modulo t. */
std::shared_ptr<longDivMod> LongDivisionPolyMod(const std::vector<int64_t>& f, const std::vector<int64_t>& g,
                                                int64_t t) {
    uint32_t n = Degree(f);
    uint32_t k = Degree(g);

    if (n != f.size() - 1) {
        OPENFHE_THROW(math_error, "LongDivisionPolyMod: The dominant coefficient of the divident is zero.");
    }

    if (k != g.size() - 1) {
        OPENFHE_THROW(math_error, "LongDivisionPolyMod: The dominant coefficient of the divisor is zero.");
    }

    std::vector<int64_t> q;
    std::vector<int64_t> r = f;
    std::vector<int64_t> d;

    if (int32_t(n - k) >= 0) {
        std::vector<int64_t> q2(n - k + 1, 0.0);
        q = q2;

        while (int32_t(n - k) >= 0) {
            d = g;
            d.insert(d.begin(), n - k, 0);  // d is g padded with zeros before up to n
            q[n - k] = r.back();

            if (g[k] != 1) {
                q[n - k] = (q[n - k] / g.back()) % t;
            }

            std::transform(d.begin(), d.end(), d.begin(), [&](const int64_t& elem) { return (elem * q[n - k]) % t; });
            // f-=d
            std::transform(r.begin(), r.end(), d.begin(), r.begin(),
                           [&](const auto& elem1, const auto& elem2) { return (elem1 - elem2) % t; });
            if (r.size() > 1) {
                n = Degree(r);
                r.resize(n + 1);
            }
        }
    }
    else {
        std::vector<int64_t> q2(1, 0.0);
        q = q2;
        r = f;
    }

    return std::make_shared<longDivMod>(q, r);
}

/*Return the degree of the polynomial described by coefficients,
which is the index of the last non-zero element in the coefficients - 1.
Don't throw an error if all the coefficients are zero, but return 0. */
uint32_t Degree(const std::vector<int64_t>& coefficients) {
    TimeVar tVar;
    TIC(tVar);
    uint32_t deg = 1;
    for (int32_t i = coefficients.size() - 1; i > 0; i--) {
        if (coefficients[i] == 0) {
            deg += 1;
        }
        else
            break;
    }
    timeDeg += TOC_NS(tVar);
    cntDeg++;
    return coefficients.size() - deg;
}

/*Return the position of the first non-zero coefficient.
Don't throw an error if all the coefficients are zero, but return coefficients.size(). */
uint32_t FindFirstNonZero(const std::vector<int64_t>& coefficients) {
    for (size_t i = 0; i < coefficients.size(); ++i) {
        if (coefficients[i] != 0) {
            return i;
        }
    }
    return coefficients.size();
}

/*Return the number of all non-zero coefficients
Don't throw an error if all the coefficients are zero, but return coefficients.size(). */
uint32_t CountNonZero(const std::vector<int64_t>& coefficients) {
    uint32_t cnt = 0;
    for (size_t i = 0; i < coefficients.size(); ++i) {
        if (coefficients[i] != 0) {
            cnt += 1;
        }
    }
    return cnt;
}

//------------------------------------------------------------------------------
// PRECOMPUTATION FOR POLYNOMIAL EVALUATION FOR BFV
//------------------------------------------------------------------------------

void InnerEvalPolyPSBFVPrecompute(const std::vector<int64_t>& coefficients, uint32_t k, uint32_t m) {
    // Compute k*2^m because we use it often
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Divide coefficients by x^{k*2^{m-1}}
    std::vector<int64_t> xkm(static_cast<int32_t>(k2m2k + k) + 1, 0.0);
    xkm.back() = 1;

    auto divqr = LongDivisionPolyMod(coefficients, xkm);
    qr[m].push(divqr);

    // Subtract x^{k(2^{m-1} - 1)} from r
    std::vector<int64_t> r2 = divqr->r;
    if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
        r2[int32_t(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(int32_t(k2m2k + 1), 0.0);
        r2.back() = -1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionPolyMod(r2, divqr->q);
    cs[m].push(divcs);

    // Add x^{k(2^{m-1} - 1)} to s
    std::vector<int64_t> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0.0);
    s2.back() = 1;

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    if (Degree(divqr->q) > k) {
        InnerEvalPolyPSBFVPrecompute(divqr->q, k, m - 1);
    }

    uint64_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
    }
    else {
        if (ds > k) {
            InnerEvalPolyPSBFVPrecompute(s2, k, m - 1);
        }
    }
}

void EvalPolyPSBFVPrecompute(const std::vector<int64_t>& coefficients) {
    uint32_t n = Degree(coefficients);

    std::vector<int64_t> f2 = coefficients;

    // Make sure the coefficients do not have the dominant terms zero
    if (coefficients[coefficients.size() - 1] == 0)
        f2.resize(n + 1);

    std::vector<uint32_t> degs = ComputeDegreesPS(n);
    uint32_t k                 = degs[0];
    uint32_t m                 = degs[1];
    m_nPS                      = n;
    m_kPS                      = k;
    m_mPS                      = m;
    qr.resize(m + 1);
    cs.resize(m + 1);

    std::cerr << "\nDegree: n = " << n << ", k = " << k << ", m = " << m << endl;

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Add x^{k(2^m - 1)} to the polynomial that has to be evaluated
    f2.resize(2 * k2m2k + k + 1, 0.0);
    f2.back() = 1;

    // Divide f2 by x^{k*2^{m-1}}
    std::vector<int64_t> xkm(int32_t(k2m2k + k) + 1, 0.0);
    xkm.back() = 1;

    auto divqr = LongDivisionPolyMod(f2, xkm);
    qr[m].push(divqr);

    // Subtract x^{k(2^{m-1} - 1)} from r
    std::vector<int64_t> r2 = divqr->r;
    if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
        r2[int32_t(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(int32_t(k2m2k + 1), 0.0);
        r2.back() = -1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionPolyMod(r2, divqr->q);
    cs[m].push(divcs);

    // Add x^{k(2^{m-1} - 1)} to s
    std::vector<int64_t> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0.0);
    s2.back() = 1;

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.

    if (Degree(divqr->q) > k) {
        InnerEvalPolyPSBFVPrecompute(divqr->q, k, m - 1);
    }

    uint32_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
    }
    else {
        if (ds > k) {
            InnerEvalPolyPSBFVPrecompute(s2, k, m - 1);
        }
    }
}

//------------------------------------------------------------------------------
// POLYNOMIAL EVALUATION FOR BFV
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> InnerEvalPolyPSBFV(ConstCiphertext<DCRTPoly> x, const std::vector<int64_t>& coefficients,
                                        uint32_t k, uint32_t m, std::vector<Ciphertext<DCRTPoly>>& powers,
                                        std::vector<Ciphertext<DCRTPoly>>& powers2) {
    TimeVar tVar, tVar2;

    cntInnerPoly++;

    // std::cout << "---Inner poly---" << std::endl;
    auto cc = x->GetCryptoContext();

    // Compute k*2^m because we use it often
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Divide coefficients by x^{k*2^{m-1}}
    std::vector<int64_t> xkm(static_cast<int32_t>(k2m2k + k) + 1, 0.0);
    xkm.back() = 1;

    auto divqr = LongDivisionPolyMod(coefficients, xkm);

    // Subtract x^{k(2^{m-1} - 1)} from r
    std::vector<int64_t> r2 = divqr->r;
    if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
        r2[int32_t(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(int32_t(k2m2k + 1), 0.0);
        r2.back() = -1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionPolyMod(r2, divqr->q);

    // Add x^{k(2^{m-1} - 1)} to s
    std::vector<int64_t> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0.0);
    s2.back() = 1;

    Ciphertext<DCRTPoly> cu;
    uint64_t dc = Degree(divcs->q);
    bool flag_c = false;

    if (dc >= 1) {
        if (dc == 1) {
            if (divcs->q[1] != 1) {
                TIC(tVar);
                cu = EvalMultConstBFV(powers.front(), divcs->q[1]);
                timePolyClear -= TOC_NS(tVar);
            }
            else {
                TIC(tVar);
                cu         = powers.front()->Clone();
                auto tempT = TOC_NS(tVar);
                timeClone += tempT;
                cntClone++;
                timePolyClear -= tempT;
            }
        }
        else {
            // TIC(tVar);
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);
            for (size_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }
            // auto tempT = TOC_NS(tVar);
            // timeClone += tempT;
            // cntClone += 2 * dc;
            // timePolyClear -= tempT;
            TIC(tVar);
            cu = EvalLinearWSumMutableBFV(ctxs, weights);
            timePolyClear -= TOC_NS(tVar);
        }

        // adds the free term (at x^0)
        TIC(tVar);
        EvalAddInPlaceConstBFV(cu, divcs->q.front());
        timePolyClear -= TOC_NS(tVar);
        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalPolyPSBFV(x, divqr->q, k, m - 1, powers, powers2);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            // TIC(tVar);
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (size_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }
            // auto tempT = TOC_NS(tVar);
            // timeClone += tempT;
            // cntClone += 2 * Degree(qcopy);
            // timePolyClear -= tempT;
            TIC(tVar);

            qu = EvalLinearWSumMutableBFV(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            TIC(tVar2);
            cc->EvalAddInPlace(qu, powers[k - 1]);
            timeAddCtxt += TOC_NS(tVar2);
            cntAddCtxt++;
            timePolyClear -= TOC_NS(tVar);
        }
        else {
            TIC(tVar);
            qu         = powers[k - 1]->Clone();
            auto tempT = TOC_NS(tVar);
            timeClone += tempT;
            cntClone++;
            timePolyClear -= tempT;
        }
        // adds the free term (at x^0)
        TIC(tVar);
        EvalAddInPlaceConstBFV(qu, divqr->q.front());
        timePolyClear -= TOC_NS(tVar);
    }

    uint64_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        TIC(tVar);
        su         = qu->Clone();
        auto tempT = TOC_NS(tVar);
        timeClone += tempT;
        cntClone++;
        timePolyClear -= tempT;
    }
    else {
        if (ds > k) {
            su = InnerEvalPolyPSBFV(x, s2, k, m - 1, powers, powers2);
        }
        else {
            // ds = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
            auto scopy = s2;
            scopy.resize(k);
            if (Degree(scopy) > 0) {
                // TIC(tVar);
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (size_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }
                // auto tempT = TOC_NS(tVar);
                // timeClone += tempT;
                // cntClone += 2 * Degree(scopy);
                TIC(tVar);
                su = EvalLinearWSumMutableBFV(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                TIC(tVar2);
                cc->EvalAddInPlace(su, powers[k - 1]);
                timeAddCtxt += TOC_NS(tVar2);
                cntAddCtxt++;
                timePolyClear -= TOC_NS(tVar);
            }
            else {
                TIC(tVar);
                su         = powers[k - 1]->Clone();
                auto tempT = TOC_NS(tVar);
                timeClone += tempT;
                cntClone++;
                timePolyClear -= tempT;
            }
            // adds the free term (at x^0)
            TIC(tVar);
            EvalAddInPlaceConstBFV(su, s2.front());
            timePolyClear -= TOC_NS(tVar);
        }
    }

    Ciphertext<DCRTPoly> result;

    TIC(tVar);
    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
        timeAddCtxt += TOC_NS(tVar);
        cntAddCtxt++;
    }
    else {
        result = EvalAddConstBFV(powers2[m - 1], divcs->q.front());
    }
    timePolyClear -= TOC_NS(tVar);

    TIC(tVar);
    result     = cc->EvalMult(result, qu);
    auto tempT = TOC_NS(tVar);
    timeMultCtxt += tempT;
    cntMultCtxt++;
    timePolyClear -= tempT;

    TIC(tVar);
    cc->EvalAddInPlace(result, su);
    tempT = TOC_NS(tVar);
    timeAddCtxt += tempT;
    cntAddCtxt++;
    timePolyClear -= tempT;

    // std::cout << "---Out of inner poly---" << std::endl;

    return result;
}

Ciphertext<DCRTPoly> EvalPolyPSBFV(ConstCiphertext<DCRTPoly> x, const std::vector<int64_t>& coefficients,
                                   bool symmetric) {
    TimeVar tIn, tVar, tVar2;

    TIC(tVar);
    auto xClone = x;  // ->Clone()
    // auto tempT  = TOC_NS(tVar);
    // timeClone += tempT;
    // cntClone++;
    // timePolyClear -= tempT;

    auto cc = x->GetCryptoContext();

    if (symmetric) {
        TIC(tVar);
        xClone     = cc->EvalSquare(xClone);
        auto tempT = TOC_NS(tVar);
        timeSquareCtxt += tempT;
        cntSquareCtxt++;
        timePolyClear -= tempT;
    }

    uint32_t n = Degree(coefficients);

    std::vector<int64_t> f2 = coefficients;

    // Make sure the coefficients do not have the dominant terms zero
    if (coefficients[coefficients.size() - 1] == 0)
        f2.resize(n + 1);

    std::vector<uint32_t> degs = ComputeDegreesPS(n);
    uint32_t k                 = degs[0];
    uint32_t m                 = degs[1];

    std::cerr << "\nDegree: n = " << n << ", k = " << k << ", m = " << m << endl;

    TIC(tIn);
    // set the indices for the powers of x that need to be computed to 1
    std::vector<int32_t> indices(k, 0);
    for (size_t i = k; i > 0; i--) {
        if (!(i & (i - 1))) {
            // if i is a power of 2
            indices[i - 1] = 1;
        }
        else {
            // non-power of 2
            indices[i - 1]   = 1;
            int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
            int64_t rem      = i % powerOf2;
            if (indices[rem - 1] == 0)
                indices[rem - 1] = 1;

            // while rem is not a power of 2
            // set indices required to compute rem to 1
            while ((rem & (rem - 1))) {
                powerOf2 = 1 << (int64_t)std::floor(std::log2(rem));
                rem      = rem % powerOf2;
                if (indices[rem - 1] == 0)
                    indices[rem - 1] = 1;
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers(k);
    TIC(tVar);
    powers[0] = xClone->Clone();
    timeClone += TOC_NS(tVar);
    cntClone++;

    // computes all powers up to k for x
    for (size_t i = 2; i <= k; i++) {
        if (!(i & (i - 1))) {
            // if i is a power of two
            TIC(tVar);
            powers[i - 1] = cc->EvalSquare(powers[i / 2 - 1]);
            timeSquareCtxt += TOC_NS(tVar);
            cntSquareCtxt++;
        }
        else {
            if (indices[i - 1] == 1) {
                // non-power of 2
                int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
                int64_t rem      = i % powerOf2;
                TIC(tVar);
                powers[i - 1] = cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]);
                timeMultCtxt += TOC_NS(tVar);
                cntMultCtxt++;
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers2(m);

    // computes powers of form k*2^i for x
    TIC(tVar);
    powers2.front() = powers.back()->Clone();
    timeClone += TOC_NS(tVar);
    cntClone++;
    for (uint32_t i = 1; i < m; i++) {
        TIC(tVar);
        powers2[i] = cc->EvalSquare(powers2[i - 1]);
        timeSquareCtxt += TOC_NS(tVar);
        cntSquareCtxt++;
    }

    // computes the product of the powers in power2, that yield x^{k(2*m - 1)}
    TIC(tVar);
    auto power2km1 = powers2.front()->Clone();
    timeClone += TOC_NS(tVar);
    cntClone++;
    for (uint32_t i = 1; i < m; i++) {
        TIC(tVar);
        power2km1 = cc->EvalMult(power2km1, powers2[i]);
        timeMultCtxt += TOC_NS(tVar);
        cntMultCtxt++;
    }

    double timePowers = TOC_NS(tIn);
    std::cout << "-----Time to compute the powers for poly eval: " << timePowers / 1000000000.0 << " s" << std::endl;
    timePolyClear -= timePowers;

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Add x^{k(2^m - 1)} to the polynomial that has to be evaluated
    f2.resize(2 * k2m2k + k + 1, 0.0);
    f2.back() = 1;

    // Divide f2 by x^{k*2^{m-1}}
    std::vector<int64_t> xkm(int32_t(k2m2k + k) + 1, 0.0);
    xkm.back() = 1;

    auto divqr = LongDivisionPolyMod(f2, xkm);

    // Subtract x^{k(2^{m-1} - 1)} from r
    std::vector<int64_t> r2 = divqr->r;
    if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
        r2[int32_t(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(int32_t(k2m2k + 1), 0.0);
        r2.back() = -1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionPolyMod(r2, divqr->q);

    // Add x^{k(2^{m-1} - 1)} to s
    std::vector<int64_t> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0.0);
    s2.back() = 1;

    // Evaluate c at u
    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs->q);
    bool flag_c = false;

    if (dc >= 1) {
        if (dc == 1) {
            if (divcs->q[1] != 1) {
                TIC(tVar);
                cu = EvalMultConstBFV(powers.front(), static_cast<int64_t>(divcs->q[1]));
                timePolyClear -= TOC_NS(tVar);
            }
            else {
                TIC(tVar);
                cu = powers.front()->Clone();
                timeClone += TOC_NS(tVar);
                cntClone++;
                timePolyClear -= TOC_NS(tVar);
            }
        }
        else {
            // TIC(tVar);
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);

            for (uint32_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }
            // timeClone += TOC_NS(tVar);
            // cntClone += dc;
            // timePolyClear -= TOC_NS(tVar);
            TIC(tVar);
            cu = EvalLinearWSumMutableBFV(ctxs, weights);
            timePolyClear -= TOC_NS(tVar);
        }

        // adds the free term (at x^0)
        TIC(tVar);
        EvalAddInPlaceConstBFV(cu, static_cast<int64_t>(divcs->q.front()));
        timePolyClear -= TOC_NS(tVar);
        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalPolyPSBFV(x, divqr->q, k, m - 1, powers, powers2);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            // TIC(tVar);
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }
            // auto tempT = TOC_NS(tVar);
            // timeClone += tempT;
            // cntClone += 2 * Degree(qcopy);
            // timePolyClear -= tempT;

            TIC(tVar);
            qu = EvalLinearWSumMutableBFV(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            TIC(tVar2);
            cc->EvalAddInPlace(qu, powers[k - 1]);
            timeAddCtxt += TOC_NS(tVar2);
            cntAddCtxt++;
            timePolyClear -= TOC_NS(tVar);
        }
        else {
            TIC(tVar);
            qu         = powers[k - 1]->Clone();
            auto tempT = TOC_NS(tVar);
            timeClone += tempT;
            cntClone++;
            timePolyClear -= tempT;
        }
        // adds the free term (at x^0)
        TIC(tVar);
        EvalAddInPlaceConstBFV(qu, divqr->q.front());
        timePolyClear -= TOC_NS(tVar);
    }

    uint32_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        TIC(tVar);
        su         = qu->Clone();
        auto tempT = TOC_NS(tVar);
        timeClone += tempT;
        cntClone++;
        timePolyClear -= tempT;
    }
    else {
        if (ds > k) {
            su = InnerEvalPolyPSBFV(x, s2, k, m - 1, powers, powers2);
        }
        else {
            // ds = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
            auto scopy = s2;
            scopy.resize(k);
            if (Degree(scopy) > 0) {
                // TIC(tVar);
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (uint32_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }
                // auto tempT = TOC_NS(tVar);
                // timeClone += tempT;
                // cntClone += 2 * Degree(scopy);
                // timePolyClear -= tempT;

                TIC(tVar);
                su = EvalLinearWSumMutableBFV(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                TIC(tVar2);
                cc->EvalAddInPlace(su, powers[k - 1]);
                timeAddCtxt += TOC_NS(tVar2);
                cntAddCtxt++;
                timePolyClear -= TOC_NS(tVar);
            }
            else {
                TIC(tVar);
                su         = powers[k - 1]->Clone();
                auto tempT = TOC_NS(tVar);
                timeClone += tempT;
                cntClone++;
                timePolyClear -= tempT;
            }
            // adds the free term (at x^0)
            TIC(tVar);
            EvalAddInPlaceConstBFV(su, s2.front());
            timePolyClear -= TOC_NS(tVar);
        }
    }

    /*Ciphertext<DCRTPoly> result;

    TIC(tVar);
    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
        timeAddCtxt += TOC_NS(tVar);
        cntAddCtxt++;
    }
    else {
        result = EvalAddConstBFV(powers2[m - 1], divcs->q.front());
    }
    timePolyClear -= TOC_NS(tVar);

    TIC(tVar);
    result = cc->EvalMult(result, qu);
    tempT  = TOC_NS(tVar);
    timeMultCtxt += tempT;
    cntMultCtxt++;
    timePolyClear -= tempT;

    TIC(tVar);
    cc->EvalAddInPlace(result, su);
    cc->EvalSubInPlace(result, power2km1);
    tempT = TOC_NS(tVar);
    timeAddCtxt += tempT;
    cntAddCtxt += 2;
    timePolyClear -= tempT;

    return result;
    */

    // Save some cloning since powers2[m-1] is not used again
    TIC(tVar);
    if (flag_c) {
        cc->EvalAddInPlace(powers2[m - 1], cu);
        timeAddCtxt += TOC_NS(tVar);
        cntAddCtxt++;
    }
    else {
        EvalAddInPlaceConstBFV(powers2[m - 1], divcs->q.front());
    }
    timePolyClear -= TOC_NS(tVar);

    TIC(tVar);
    powers2[m - 1] = cc->EvalMult(powers2[m - 1], qu);
    auto tempT     = TOC_NS(tVar);
    timeMultCtxt += tempT;
    cntMultCtxt++;
    timePolyClear -= tempT;

    TIC(tVar);
    cc->EvalAddInPlace(powers2[m - 1], su);
    cc->EvalSubInPlace(powers2[m - 1], power2km1);
    tempT = TOC_NS(tVar);
    timeAddCtxt += tempT;
    cntAddCtxt += 2;
    timePolyClear -= tempT;

    return powers2[m - 1];
}

Ciphertext<DCRTPoly> InnerEvalPolyPSBFVWithPrecompute(ConstCiphertext<DCRTPoly> x, uint32_t k, uint32_t m,
                                                      std::vector<Ciphertext<DCRTPoly>>& powers,
                                                      std::vector<Ciphertext<DCRTPoly>>& powers2) {
    TimeVar tVar, tVar2;

    cntInnerPoly++;

    // std::cout << "---Inner poly---" << std::endl;
    auto cc = x->GetCryptoContext();

    // Compute k*2^m because we use it often
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    TIC(tVar);
    auto divqr = qr[m].front();
    qr[m].pop();

    auto divcs = cs[m].front();
    cs[m].pop();
    timeLongDiv += TOC_NS(tVar);
    cntLongDiv += 2;

    // Add x^{k(2^{m-1} - 1)} to s
    std::vector<int64_t> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0.0);
    s2.back() = 1;

    Ciphertext<DCRTPoly> cu;
    uint64_t dc = Degree(divcs->q);
    bool flag_c = false;

    if (dc >= 1) {
        if (dc == 1) {
            if (divcs->q[1] != 1) {
                TIC(tVar);
                cu = EvalMultConstBFV(powers.front(), divcs->q[1]);
                timePolyClear -= TOC_NS(tVar);
            }
            else {
                TIC(tVar);
                cu         = powers.front()->Clone();
                auto tempT = TOC_NS(tVar);
                timeClone += tempT;
                cntClone++;
                timePolyClear -= tempT;
            }
        }
        else {
            // TIC(tVar);
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);
            for (size_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }
            // auto tempT = TOC_NS(tVar);
            // timeClone += tempT;
            // cntClone += 2 * dc;
            // timePolyClear -= tempT;
            TIC(tVar);
            cu = EvalLinearWSumMutableBFV(ctxs, weights);
            timePolyClear -= TOC_NS(tVar);
        }

        // adds the free term (at x^0)
        TIC(tVar);
        EvalAddInPlaceConstBFV(cu, divcs->q.front());
        timePolyClear -= TOC_NS(tVar);
        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalPolyPSBFVWithPrecompute(x, k, m - 1, powers, powers2);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            // TIC(tVar);
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (size_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }
            // auto tempT = TOC_NS(tVar);
            // timeClone += tempT;
            // cntClone += 2 * Degree(qcopy);
            // timePolyClear -= tempT;
            TIC(tVar);

            qu = EvalLinearWSumMutableBFV(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            TIC(tVar2);
            cc->EvalAddInPlace(qu, powers[k - 1]);
            timeAddCtxt += TOC_NS(tVar2);
            cntAddCtxt++;
            timePolyClear -= TOC_NS(tVar);
        }
        else {
            TIC(tVar);
            qu         = powers[k - 1]->Clone();
            auto tempT = TOC_NS(tVar);
            timeClone += tempT;
            cntClone++;
            timePolyClear -= tempT;
        }
        // adds the free term (at x^0)
        TIC(tVar);
        EvalAddInPlaceConstBFV(qu, divqr->q.front());
        timePolyClear -= TOC_NS(tVar);
    }

    uint64_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        TIC(tVar);
        su         = qu->Clone();
        auto tempT = TOC_NS(tVar);
        timeClone += tempT;
        cntClone++;
        timePolyClear -= tempT;
    }
    else {
        if (ds > k) {
            su = InnerEvalPolyPSBFVWithPrecompute(x, k, m - 1, powers, powers2);
        }
        else {
            // ds = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
            auto scopy = s2;
            scopy.resize(k);
            if (Degree(scopy) > 0) {
                // TIC(tVar);
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (size_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }
                // auto tempT = TOC_NS(tVar);
                // timeClone += tempT;
                // cntClone += 2 * Degree(scopy);
                TIC(tVar);
                su = EvalLinearWSumMutableBFV(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                TIC(tVar2);
                cc->EvalAddInPlace(su, powers[k - 1]);
                timeAddCtxt += TOC_NS(tVar2);
                cntAddCtxt++;
                timePolyClear -= TOC_NS(tVar);
            }
            else {
                TIC(tVar);
                su         = powers[k - 1]->Clone();
                auto tempT = TOC_NS(tVar);
                timeClone += tempT;
                cntClone++;
                timePolyClear -= tempT;
            }
            // adds the free term (at x^0)
            TIC(tVar);
            EvalAddInPlaceConstBFV(su, s2.front());
            timePolyClear -= TOC_NS(tVar);
        }
    }

    Ciphertext<DCRTPoly> result;

    TIC(tVar);
    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
        timeAddCtxt += TOC_NS(tVar);
        cntAddCtxt++;
    }
    else {
        result = EvalAddConstBFV(powers2[m - 1], divcs->q.front());
    }
    timePolyClear -= TOC_NS(tVar);

    TIC(tVar);
    result     = cc->EvalMult(result, qu);
    auto tempT = TOC_NS(tVar);
    timeMultCtxt += tempT;
    cntMultCtxt++;
    timePolyClear -= tempT;

    TIC(tVar);
    cc->EvalAddInPlace(result, su);
    tempT = TOC_NS(tVar);
    timeAddCtxt += tempT;
    cntAddCtxt++;
    timePolyClear -= tempT;

    // std::cout << "---Out of inner poly---" << std::endl;

    return result;
}

Ciphertext<DCRTPoly> EvalPolyPSBFVWithPrecompute(ConstCiphertext<DCRTPoly> x, bool symmetric) {
    TimeVar tIn, tVar, tVar2;

    TIC(tVar);
    auto xClone = x;  // ->Clone()
    // auto tempT  = TOC_NS(tVar);
    // timeClone += tempT;
    // cntClone++;
    // timePolyClear -= tempT;

    auto cc = x->GetCryptoContext();

    if (symmetric) {
        TIC(tVar);
        xClone     = cc->EvalSquare(xClone);
        auto tempT = TOC_NS(tVar);
        timeSquareCtxt += tempT;
        cntSquareCtxt++;
        timePolyClear -= tempT;
    }

    uint32_t n = m_nPS;
    uint32_t k = m_kPS;
    uint32_t m = m_mPS;

    std::cerr << "\nDegree: n = " << n << ", k = " << k << ", m = " << m << endl;

    TIC(tIn);
    // set the indices for the powers of x that need to be computed to 1
    std::vector<int32_t> indices(k, 0);
    for (size_t i = k; i > 0; i--) {
        if (!(i & (i - 1))) {
            // if i is a power of 2
            indices[i - 1] = 1;
        }
        else {
            // non-power of 2
            indices[i - 1]   = 1;
            int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
            int64_t rem      = i % powerOf2;
            if (indices[rem - 1] == 0)
                indices[rem - 1] = 1;

            // while rem is not a power of 2
            // set indices required to compute rem to 1
            while ((rem & (rem - 1))) {
                powerOf2 = 1 << (int64_t)std::floor(std::log2(rem));
                rem      = rem % powerOf2;
                if (indices[rem - 1] == 0)
                    indices[rem - 1] = 1;
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers(k);
    TIC(tVar);
    powers[0] = xClone->Clone();
    timeClone += TOC_NS(tVar);
    cntClone++;

    // computes all powers up to k for x
    for (size_t i = 2; i <= k; i++) {
        if (!(i & (i - 1))) {
            // if i is a power of two
            TIC(tVar);
            powers[i - 1] = cc->EvalSquare(powers[i / 2 - 1]);
            timeSquareCtxt += TOC_NS(tVar);
            cntSquareCtxt++;
        }
        else {
            if (indices[i - 1] == 1) {
                // non-power of 2
                int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
                int64_t rem      = i % powerOf2;
                TIC(tVar);
                powers[i - 1] = cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]);
                timeMultCtxt += TOC_NS(tVar);
                cntMultCtxt++;
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers2(m);

    // computes powers of form k*2^i for x
    TIC(tVar);
    powers2.front() = powers.back()->Clone();
    timeClone += TOC_NS(tVar);
    cntClone++;
    for (uint32_t i = 1; i < m; i++) {
        TIC(tVar);
        powers2[i] = cc->EvalSquare(powers2[i - 1]);
        timeSquareCtxt += TOC_NS(tVar);
        cntSquareCtxt++;
    }

    // computes the product of the powers in power2, that yield x^{k(2*m - 1)}
    TIC(tVar);
    auto power2km1 = powers2.front()->Clone();
    timeClone += TOC_NS(tVar);
    cntClone++;
    for (uint32_t i = 1; i < m; i++) {
        TIC(tVar);
        power2km1 = cc->EvalMult(power2km1, powers2[i]);
        timeMultCtxt += TOC_NS(tVar);
        cntMultCtxt++;
    }

    double timePowers = TOC_NS(tIn);
    std::cout << "-----Time to compute the powers for poly eval: " << timePowers / 1000000000.0 << " s" << std::endl;
    timePolyClear -= timePowers;

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    TIC(tVar);
    auto divqr = qr[m].front();
    qr[m].pop();

    auto divcs = cs[m].front();
    cs[m].pop();
    timeLongDiv += TOC_NS(tVar);
    cntLongDiv += 2;

    // Add x^{k(2^{m-1} - 1)} to s
    std::vector<int64_t> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0.0);
    s2.back() = 1;

    // Evaluate c at u
    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs->q);
    bool flag_c = false;

    if (dc >= 1) {
        if (dc == 1) {
            if (divcs->q[1] != 1) {
                TIC(tVar);
                cu = EvalMultConstBFV(powers.front(), static_cast<int64_t>(divcs->q[1]));
                timePolyClear -= TOC_NS(tVar);
            }
            else {
                TIC(tVar);
                cu = powers.front()->Clone();
                timeClone += TOC_NS(tVar);
                cntClone++;
                timePolyClear -= TOC_NS(tVar);
            }
        }
        else {
            // TIC(tVar);
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);

            for (uint32_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }
            // timeClone += TOC_NS(tVar);
            // cntClone += dc;
            // timePolyClear -= TOC_NS(tVar);
            TIC(tVar);
            cu = EvalLinearWSumMutableBFV(ctxs, weights);
            timePolyClear -= TOC_NS(tVar);
        }

        // adds the free term (at x^0)
        TIC(tVar);
        EvalAddInPlaceConstBFV(cu, static_cast<int64_t>(divcs->q.front()));
        timePolyClear -= TOC_NS(tVar);
        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalPolyPSBFVWithPrecompute(x, k, m - 1, powers, powers2);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            // TIC(tVar);
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }
            // auto tempT = TOC_NS(tVar);
            // timeClone += tempT;
            // cntClone += 2 * Degree(qcopy);
            // timePolyClear -= tempT;

            TIC(tVar);
            qu = EvalLinearWSumMutableBFV(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            TIC(tVar2);
            cc->EvalAddInPlace(qu, powers[k - 1]);
            timeAddCtxt += TOC_NS(tVar2);
            cntAddCtxt++;
            timePolyClear -= TOC_NS(tVar);
        }
        else {
            TIC(tVar);
            qu         = powers[k - 1]->Clone();
            auto tempT = TOC_NS(tVar);
            timeClone += tempT;
            cntClone++;
            timePolyClear -= tempT;
        }
        // adds the free term (at x^0)
        TIC(tVar);
        EvalAddInPlaceConstBFV(qu, divqr->q.front());
        timePolyClear -= TOC_NS(tVar);
    }

    uint32_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        TIC(tVar);
        su         = qu->Clone();
        auto tempT = TOC_NS(tVar);
        timeClone += tempT;
        cntClone++;
        timePolyClear -= tempT;
    }
    else {
        if (ds > k) {
            su = InnerEvalPolyPSBFVWithPrecompute(x, k, m - 1, powers, powers2);
        }
        else {
            // ds = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
            auto scopy = s2;
            scopy.resize(k);
            if (Degree(scopy) > 0) {
                // TIC(tVar);
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (uint32_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }
                // auto tempT = TOC_NS(tVar);
                // timeClone += tempT;
                // cntClone += 2 * Degree(scopy);
                // timePolyClear -= tempT;

                TIC(tVar);
                su = EvalLinearWSumMutableBFV(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                TIC(tVar2);
                cc->EvalAddInPlace(su, powers[k - 1]);
                timeAddCtxt += TOC_NS(tVar2);
                cntAddCtxt++;
                timePolyClear -= TOC_NS(tVar);
            }
            else {
                TIC(tVar);
                su         = powers[k - 1]->Clone();
                auto tempT = TOC_NS(tVar);
                timeClone += tempT;
                cntClone++;
                timePolyClear -= tempT;
            }
            // adds the free term (at x^0)
            TIC(tVar);
            EvalAddInPlaceConstBFV(su, s2.front());
            timePolyClear -= TOC_NS(tVar);
        }
    }

    // Save some cloning since powers2[m-1] is not used again
    TIC(tVar);
    if (flag_c) {
        cc->EvalAddInPlace(powers2[m - 1], cu);
        timeAddCtxt += TOC_NS(tVar);
        cntAddCtxt++;
    }
    else {
        EvalAddInPlaceConstBFV(powers2[m - 1], divcs->q.front());
    }
    timePolyClear -= TOC_NS(tVar);

    TIC(tVar);
    powers2[m - 1] = cc->EvalMult(powers2[m - 1], qu);
    auto tempT     = TOC_NS(tVar);
    timeMultCtxt += tempT;
    cntMultCtxt++;
    timePolyClear -= tempT;

    TIC(tVar);
    cc->EvalAddInPlace(powers2[m - 1], su);
    cc->EvalSubInPlace(powers2[m - 1], power2km1);
    tempT = TOC_NS(tVar);
    timeAddCtxt += tempT;
    cntAddCtxt += 2;
    timePolyClear -= tempT;

    return powers2[m - 1];
}

//------------------------------------------------------------------------------
// KEY GENERATION AND PRECOMPUTATIONS FOR LINEAR TRANSFORM FOR BFV
//------------------------------------------------------------------------------

std::shared_ptr<schemeSwitchKeys> EvalAmortizedFHEWBootKeyGen(CryptoContextImpl<DCRTPoly>& cc,
                                                              const KeyPair<DCRTPoly>& keyPair,
                                                              ConstLWEPrivateKey& lwesk,
                                                              const PrivateKey<DCRTPoly> privateKeyKS, uint32_t dim1,
                                                              uint32_t L) {
    auto privateKey = keyPair.secretKey;
    auto publicKey  = keyPair.publicKey;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());

    // Compute automorphism keys for homomorphic decoding;
    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t N = cc.GetRingDimension();
    // Computing the baby-step
    if (dim1 == 0)
        dim1 = getRatioBSGSPow2(N / 2);
    m_dim1BF = dim1;
    m_LBF    = L;

    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> indexRotationS2C = FindLTNRotationIndices(m_dim1BF, N);
    indexRotationS2C.push_back(M);

    // std::cout << indexRotationS2C << std::endl;
    cc.EvalAtIndexKeyGen(privateKey, indexRotationS2C);

    // Compute multiplication key
    cc.EvalMultKeyGen(privateKey);

    // Compute BFV encryption of FHEW key
    uint32_t n           = lwesk->GetElement().GetLength();
    NativeVector temp_sk = lwesk->GetElement();  // re-encode to binary
    std::vector<int64_t> LWE_sk(n);
    std::vector<Ciphertext<DCRTPoly>> FHEWtoBFVKey(n);
    // This encoding is for the column method: obtain n ciphertext each containing one repeated element of the vector of LWE sk
    for (size_t i = 0; i < n; i++) {
        auto temp = temp_sk[i].ConvertToInt();
        if (temp > 1) {
            temp = -1;
        }
        LWE_sk[i] = temp;
        std::vector<int64_t> vec_LWE_sk(N, temp);
        FHEWtoBFVKey[i] = cc.Encrypt(publicKey, cc.MakePackedPlaintext(vec_LWE_sk));
    }

    // Compute switching key hint between main BFV secret key to the intermediate BFV (for modulus switching) key to the FHEW key
    auto BFVtoFHEWSwk = switchingKeyGenRLWEcc(privateKeyKS, privateKey, lwesk);

    return make_shared<schemeSwitchKeys>(FHEWtoBFVKey, BFVtoFHEWSwk);
}

std::vector<Plaintext> EvalMatMultColPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                const std::vector<std::vector<int64_t>>& A, uint32_t L) {
    uint32_t rows = A.size();
    uint32_t cols = A[0].size();
    std::vector<Plaintext> Apre(cols);

    TimeVar tVar;
    TIC(tVar);
#pragma omp parallel for
    for (size_t j = 0; j < cols; ++j) {
        std::vector<int64_t> temp_vec(rows);
        for (size_t i = 0; i < rows; ++i) {
            temp_vec[i] = A[i][j];
        }
        Apre[j] = cc.MakePackedPlaintext(temp_vec);
    }
    timePackedPrePtxt += TOC_NS(tVar);
    cntPackedPrePtxt += cols;

    return Apre;
}

std::vector<ConstPlaintext> EvalLTNPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                              const std::vector<std::vector<int64_t>>& A, uint32_t dim1, uint32_t L,
                                              double scale) {
    TimeVar tVar;

    if (A[0].size() != A.size()) {
        OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecomputeSwitch is not square");
    }

    uint32_t size = A.size();
    uint32_t N    = cc.GetRingDimension();  // When this method is used for homomorphic decoding in BFV, N = size

    uint32_t bStep = (dim1 == 0) ? getRatioBSGSPow2(size / 2) : dim1;
    uint32_t gStep = ceil(static_cast<double>(size / 2) / bStep);

    // std::cout << "bStep = " << bStep << ", gStep = " << gStep << ", N = " << N << std::endl;

    TIC(tVar);
    // Encode plaintext at minimum number of levels
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc.GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        while (elementParams.GetParams().size() > 1) {
            elementParams.PopLastParam();
        }
    }
    auto elementParamsPtr = std::make_shared<DCRTPoly::Params>(elementParams);
    // std::cout << "elementParams size: " << elementParams.GetParams().size() << std::endl;
    std::cout << "Time to get element parameters: " << static_cast<double>(TOC_NS(tVar)) / 1000000000.0 << " s"
              << std::endl;

    TIC(tVar);
    std::vector<ConstPlaintext> result(size);
#pragma omp parallel for
    for (size_t i = 0; i < bStep; ++i) {
        for (size_t j = 0; j < 2 * gStep; j++) {
            if (bStep * j + i < size) {
                auto diag = ExtractShiftedDiagonalN(A, static_cast<int32_t>(i), static_cast<int32_t>(bStep * j));
                std::transform(diag.begin(), diag.end(), diag.begin(),
                               [&](const int64_t& elem) { return elem * scale; });
                // result[bStep * j + i] = cc.MakePackedPlaintext(Fill(diag, N));
                result[bStep * j + i] = cc.MakePackedPlaintextAux(Fill(diag, N), 1, 0, elementParamsPtr);
            }
        }
    }
    timePackedPrePtxt += TOC_NS(tVar);
    cntPackedPrePtxt += N;

    return result;
}

void EvalSlotsToCoeffsPrecompute(const CryptoContextImpl<DCRTPoly>& cc, double scale, bool precompute) {
    uint32_t N     = cc.GetRingDimension();
    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = N / 2;

    NativeInteger t = cc.GetCryptoParameters()->GetPlaintextModulus();

    NativeInteger initRoot = RootOfUnity<NativeInteger>(M, t);

    // Matrix for decoding
    std::vector<std::vector<std::int64_t>> UT(N, std::vector<int64_t>(N));

    // Computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows %= M;
    }

    // computes all powers of a primitive root of unity zeta^{2N} = 1 mod t
    std::vector<NativeInteger> zetaPows(N);
    for (uint32_t j = 0; j < N; ++j) {
        zetaPows[j] = initRoot.ModExp(rotGroup[j], t);
    }

    for (size_t i = 0; i < slots; i++) {
        for (size_t j = 0; j < N; j++) {
            UT[i][j]         = NativeInteger(zetaPows[i].ModExp(j, t)).ConvertToInt();
            UT[i + slots][j] = NativeInteger(UT[i][j]).ModInverse(t).ConvertToInt();
        }
    }

    m_UT = UT;
    if (precompute) {
        m_UTPre = EvalLTNPrecompute(cc, UT, m_dim1BF, 1, 1);
    }
}

//------------------------------------------------------------------------------
// LINEAR TRANSFORM FOR BFV
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> EvalFHEWtoBFV(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<LWECiphertext>& lweCtxt,
                                   const std::vector<Ciphertext<DCRTPoly>>& keyCtxt) {
    // Step 1. Form matrix A and vector b from the LWE ciphertexts
    auto numValues = lweCtxt.size();
    auto n         = lweCtxt[0]->GetLength();
    std::vector<std::vector<int64_t>> A(numValues);

    vector<int64_t> b(numValues);
    NativeVector a_v(n);
    for (size_t i = 0; i < numValues; ++i) {
        A[i].resize(n);
        a_v = lweCtxt[i]->GetA();
        for (size_t j = 0; j < n; ++j) {
            A[i][j] = a_v[j].ConvertToInt();
        }
        b[i] = lweCtxt[i]->GetB().ConvertToInt();
    }

    // Step 2. Compute the product between the ciphertext of the LWE key and the matrix of first components

    // Currently, by design, the # rows (# LWE ciphertexts to switch) is a power of two.
    // Ensure that # cols (LWE lattice parameter n) is padded up to a power of two
    std::vector<std::vector<int64_t>> Acopy(A);
    uint32_t cols_po2 = 1 << static_cast<uint32_t>(std::ceil(std::log2(A[0].size())));

    if (cols_po2 != A[0].size()) {
        std::vector<int64_t> padding(cols_po2 - A[0].size());
        for (size_t i = 0; i < A.size(); ++i) {
            Acopy[i].insert(Acopy[i].end(), padding.begin(), padding.end());
        }
    }

    // // If we have the diagonal method
    // auto Apre = EvalLTRectPrecomputeSwitch(Acopy, dim1, scale);
    // auto res  = EvalLTRectWithPrecomputeSwitch(cc, Apre, ct[0], (Acopy.size() < A[0].size()), dim1,
    //                                            L);  // The result is repeated every Acopy.size() slots

    // Currently, for computational speed, we implement the column method since it does not require rotations. However, it requires storing n ciphertexts at the highest level
    // The linear transform happens at the highest level
    // auto Apre  = EvalMatMultColPrecompute(cc, Acopy, 0);
    // auto AdotS = EvalMatMultCol(cc, Apre, keyCtxt);
    auto AdotS = EvalMatMultColWithoutPrecompute(cc, Acopy, keyCtxt);  // To not store the plaintexts here

    // Step 3. Get the ciphertext of B - A*s
    Plaintext BPlain = cc.MakePackedPlaintext(b);  //, AdotS->GetNoiseScaleDeg(), AdotS->GetLevel());

    TimeVar tVar;
    TIC(tVar);
    auto BminusAdotS = cc.EvalAdd(cc.EvalNegate(AdotS), BPlain);
    timeAddCtxt += TOC_NS(tVar);
    cntAddCtxt += 2;

    return BminusAdotS;
}

Ciphertext<DCRTPoly> EvalPartialHomDecryptionOrig(const CryptoContextImpl<DCRTPoly>& cc,
                                                  const std::vector<std::vector<int64_t>>& A,
                                                  const std::vector<Ciphertext<DCRTPoly>>& ct) {
    // Currently, by design, the # rows (# LWE ciphertexts to switch) is a power of two.
    // Ensure that # cols (LWE lattice parameter n) is padded up to a power of two
    std::vector<std::vector<int64_t>> Acopy(A);
    uint32_t cols_po2 = 1 << static_cast<uint32_t>(std::ceil(std::log2(A[0].size())));

    if (cols_po2 != A[0].size()) {
        std::vector<int64_t> padding(cols_po2 - A[0].size());
        for (size_t i = 0; i < A.size(); ++i) {
            Acopy[i].insert(Acopy[i].end(), padding.begin(), padding.end());
        }
    }

    // // If we have the diagonal method
    // auto Apre = EvalLTRectPrecomputeSwitch(Acopy, dim1, scale);
    // auto res  = EvalLTRectWithPrecomputeSwitch(cc, Apre, ct[0], (Acopy.size() < A[0].size()), dim1,
    //                                            L);  // The result is repeated every Acopy.size() slots

    // Currently, for simplicity, we implement the column method
    // The linear transform happens at the highest level
    auto Apre = EvalMatMultColPrecompute(cc, Acopy, 0);
    auto res  = EvalMatMultCol(cc, Apre, ct);

    return res;
}

Ciphertext<DCRTPoly> EvalMatMultCol(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<Plaintext>& A,
                                    const std::vector<Ciphertext<DCRTPoly>>& ct) {
    TimeVar tVar;
    Ciphertext<DCRTPoly> res;
    uint32_t n = ct.size();

    uint32_t log_n = lbcrypto::GetMSB(n) - 1;
    std::vector<Ciphertext<DCRTPoly>> layer((1 << (log_n - 1)));

    for (size_t i = 0; i < log_n; ++i) {
        for (size_t j = 0; j < static_cast<uint32_t>(1 << (log_n - i - 1)); ++j) {
            if (i == 0) {  // first layer, need to compute the multiplications
                TIC(tVar);
                layer[j] = cc.EvalAdd(cc.EvalMult(A[j * 2], ct[j * 2]), cc.EvalMult(A[j * 2 + 1], ct[j * 2 + 1]));
                timeMultPtxt += TOC_NS(tVar);
                cntMultPtxt += 2;
            }
            else {
                TIC(tVar);
                layer[j] = cc.EvalAdd(layer[j * 2], layer[j * 2 + 1]);
                timeAddCtxt += TOC_NS(tVar);
                cntAddCtxt++;
            }
        }
        if (i == log_n - 1) {
            res = layer[0];
        }
        else {
            layer.resize((1 << (log_n - i - 1)));
        }
    }

    // // Linear summation
    // res = cc.EvalMult(A[0], ct[0]);
    // for (size_t i = 1; i < n; ++i) {
    // res = cc.EvalAdd(res, cc.EvalMult(A[i], ct[i]));
    // }

    return res;
}

Ciphertext<DCRTPoly> EvalMatMultColWithoutPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                     const std::vector<std::vector<int64_t>>& A,
                                                     const std::vector<Ciphertext<DCRTPoly>>& ct) {
    TimeVar tVar;

    uint32_t rows = A.size();

    Ciphertext<DCRTPoly> res;
    uint32_t n = ct.size();

    uint32_t log_n = lbcrypto::GetMSB(n) - 1;
    std::vector<Ciphertext<DCRTPoly>> layer((1 << (log_n - 1)));

    for (size_t i = 0; i < log_n; ++i) {
        for (size_t j = 0; j < static_cast<uint32_t>(1 << (log_n - i - 1)); ++j) {
            if (i == 0) {  // first layer, need to compute the multiplications
                std::vector<int64_t> temp_vec1(rows), temp_vec2(rows);
                for (size_t k = 0; k < rows; ++k) {
                    temp_vec1[k] = A[k][j * 2];
                    temp_vec2[k] = A[k][j * 2 + 1];
                }
                TIC(tVar);
                layer[j] = cc.EvalAdd(cc.EvalMult(cc.MakePackedPlaintext(temp_vec1), ct[j * 2]),
                                      cc.EvalMult(cc.MakePackedPlaintext(temp_vec2), ct[j * 2 + 1]));
                timeMultPtxt += TOC_NS(tVar);
                cntMultPtxt += 2;
            }
            else {
                TIC(tVar);
                layer[j] = cc.EvalAdd(layer[j * 2], layer[j * 2 + 1]);
                timeAddCtxt += TOC_NS(tVar);
                cntAddCtxt++;
            }
        }
        if (i == log_n - 1) {
            res = layer[0];
        }
        else {
            layer.resize((1 << (log_n - i - 1)));
        }
    }

    // // Linear summation
    // res = cc.EvalMult(A[0], ct[0]);
    // for (size_t i = 1; i < n; ++i) {
    // res = cc.EvalAdd(res, cc.EvalMult(A[i], ct[i]));
    // }

    return res;
}

// Encrypted matrix-vector multiplication of size N implemented as two sized N/2 matrix-vector multiplications
Ciphertext<DCRTPoly> EvalLTNWithPrecompute(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                           const std::vector<ConstPlaintext>& A, uint32_t dim1) {
    TimeVar tVar;
    uint32_t N = A.size();
    uint32_t M = cc.GetCyclotomicOrder();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSPow2(N / 2) : dim1;
    uint32_t gStep = ceil(static_cast<double>(N / 2) / bStep);

    // std::cout << "bStep = " << bStep << ", gStep = " << gStep << ", N = " << N << std::endl;

    // Swap ciphertext halves
    TIC(tVar);
    // Swap ciphertext halves
    Ciphertext<DCRTPoly> ctxt_swapped = cc.EvalAtIndex(ctxt, N / 2);
    std::cout << "EvalAtIndex time: " << static_cast<double>(TOC_NS(tVar)) / 1000000000.0 << " s" << std::endl;

    TIC(tVar);
    ctxt         = cc.Compress(ctxt, 1);
    ctxt_swapped = cc.Compress(ctxt_swapped, 1);
    std::cout << "Compress time: " << static_cast<double>(TOC_NS(tVar)) / 1000000000.0 << " s" << std::endl;

    TIC(tVar);
    std::vector<Ciphertext<DCRTPoly>> fastRotation(2 * gStep - 2);
    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits  = cc.EvalFastRotationPrecompute(ctxt);
    auto digits2 = cc.EvalFastRotationPrecompute(ctxt_swapped);
    timeRotationPrec += TOC_NS(tVar);
    cntRotationPrec += 2;

    TIC(tVar);
    // Hoisted automorphisms
#pragma omp parallel for
    for (size_t j = 1; j < gStep; j++) {
        fastRotation[j - 1]             = cc.EvalFastRotation(ctxt, j * bStep, M, digits);
        fastRotation[j - 1 + gStep - 1] = cc.EvalFastRotation(ctxt_swapped, j * bStep, M, digits2);
    }
    timeRotations += TOC_NS(tVar);
    cntRotations += 2 * gStep - 2;

    Ciphertext<DCRTPoly> result;

    for (size_t i = 0; i < bStep; ++i) {
        Ciphertext<DCRTPoly> inner;
        for (size_t j = 0; j < gStep; ++j) {
            if (j == 0) {
                TIC(tVar);
                inner = cc.EvalMult(ctxt, A[i]);
                timeMultPtxt += TOC_NS(tVar);
                cntMultPtxt++;
            }
            else {
                TIC(tVar);
                cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j - 1], A[bStep * j + i]));
                timeMultPtxt += TOC_NS(tVar);
                cntMultPtxt++;
            }
        }
        for (size_t j = gStep; j < 2 * gStep; ++j) {
            if (j == gStep) {
                TIC(tVar);
                cc.EvalAddInPlace(inner, cc.EvalMult(ctxt_swapped, A[bStep * j + i]));
                timeMultPtxt += TOC_NS(tVar);
                cntMultPtxt++;
            }
            else {
                TIC(tVar);
                cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j - 2], A[bStep * j + i]));
                timeMultPtxt += TOC_NS(tVar);
                cntMultPtxt++;
            }
        }

        if (i == 0) {
            result = inner;
        }
        else {
            TIC(tVar);
            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            timeRotationPrec += TOC_NS(tVar);
            cntRotationPrec++;
            TIC(tVar);
            cc.EvalAddInPlace(result, cc.EvalFastRotation(inner, i, M, innerDigits));
            timeRotations += TOC_NS(tVar);
            cntRotations++;
        }
    }

    return result;
}

// Encrypted matrix-vector multiplication of size N implemented as two sized N/2 matrix-vector multiplications, single-hoisted computation
Ciphertext<DCRTPoly> EvalLTNWithoutPrecompute(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                              std::vector<std::vector<int64_t>>& A, uint32_t dim1) {
    if (A[0].size() != A.size()) {
        OPENFHE_THROW(math_error, "The matrix passed to EvalLTNWithoutPrecompute is not square");
    }

    TimeVar tVar, tVarAll, tVarIn, tVarOutLoop, tVarInLoop;
    TIC(tVarAll);

    // uint32_t size = A.size();
    uint32_t N = cc.GetRingDimension();  // When this method is used for homomorphic decoding in BFV, N = size
    uint32_t M = cc.GetCyclotomicOrder();

    uint32_t bStep = (dim1 == 0) ? getRatioBSGSPow2(N / 2) : dim1;
    uint32_t gStep = ceil(static_cast<double>(N / 2) / bStep);

    // std::cout << "bStep = " << bStep << ", gStep = " << gStep << ", N = " << N << std::endl;

    TIC(tVar);
    // Swap ciphertext halves
    Ciphertext<DCRTPoly> ctxt_swapped = cc.EvalAtIndex(ctxt, N / 2);
    std::cout << "EvalAtIndex time: " << static_cast<double>(TOC_NS(tVar)) / 1000000000.0 << " s" << std::endl;

    TIC(tVar);
    ctxt         = cc.Compress(ctxt, 1);
    ctxt_swapped = cc.Compress(ctxt_swapped, 1);
    std::cout << "Compress time: " << static_cast<double>(TOC_NS(tVar)) / 1000000000.0 << " s" << std::endl;

    // std::cout << "-----ctxt depth, level, GetElements().size(), and GetElements()[0].GetNumOfElements(): "
    //           << ctxt->GetNoiseScaleDeg() << ", " << ctxt->GetLevel() << ", " << ctxt->GetElements().size() << ", "
    //           << ctxt->GetElements()[0].GetNumOfElements() << std::endl;

    TIC(tVar);
    std::vector<Ciphertext<DCRTPoly>> fastRotation(2 * gStep - 2);

    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits  = cc.EvalFastRotationPrecompute(ctxt);
    auto digits2 = cc.EvalFastRotationPrecompute(ctxt_swapped);
    timeRotationPrec += TOC_NS(tVar);
    cntRotationPrec += 2;

    TIC(tVar);
    // Hoisted automorphisms
    // #pragma omp parallel for
    for (size_t j = 1; j < gStep; j++) {
        fastRotation[j - 1]             = cc.EvalFastRotation(ctxt, j * bStep, M, digits);
        fastRotation[j - 1 + gStep - 1] = cc.EvalFastRotation(ctxt_swapped, j * bStep, M, digits2);
    }
    timeRotations += TOC_NS(tVar);
    cntRotations += 2 * gStep - 2;

    TIC(tVar);
    // Encode plaintext at minimum number of levels
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(fastRotation[0]->GetCryptoParameters());
    // ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto elementParams = *((*digits)[0].GetParams());
    if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        auto paramsP = cryptoParams->GetParamsP();
        if (cryptoParams->GetKeySwitchTechnique() == HYBRID) {
            for (uint32_t i = 0; i < paramsP->GetParams().size(); i++) {
                elementParams.PopLastParam();
            }
        }
    }
    auto elementParamsPtr = std::make_shared<DCRTPoly::Params>(elementParams);
    std::cout << "elementParams size: " << elementParams.GetParams().size() << std::endl;
    std::cout << "Time to get element parameters: " << static_cast<double>(TOC_NS(tVar)) / 1000000000.0 << " s"
              << std::endl;

    Ciphertext<DCRTPoly> result;

    std::cout << "Time until the loop: " << static_cast<double>(TOC_NS(tVarAll)) / 1000000000.0 << " s" << std::endl;

    double tInner1(0), tInner2(0), tInner3(0), tIn(0);
    double tOuter1(0), tOuter2(0), tOuter3(0);

    TIC(tVarAll);
    for (size_t i = 0; i < bStep; ++i) {
        TIC(tVarIn);
        Ciphertext<DCRTPoly> inner;
        TIC(tVarOutLoop);
        for (size_t j = 0; j < gStep; ++j) {
            TIC(tVarInLoop);
            TIC(tVar);
            auto diag        = ExtractShiftedDiagonalN(A, static_cast<int32_t>(i), static_cast<int32_t>(bStep * j));
            Plaintext A_ptxt = cc.MakePackedPlaintextAux(diag, 1, 0, elementParamsPtr);
            timePackedPtxt += TOC_NS(tVar);
            cntPackedPtxt++;
            TIC(tVar);
            if (j == 0) {
                inner = cc.EvalMult(ctxt, A_ptxt);
            }
            else {
                cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j - 1], A_ptxt));
            }
            timeMultPtxt += TOC_NS(tVar);
            cntMultPtxt++;
            tInner1 += static_cast<double>(TOC_NS(tVarInLoop));
        }
        tOuter1 += static_cast<double>(TOC_NS(tVarOutLoop));

        TIC(tVarOutLoop);
        for (size_t j = gStep; j < 2 * gStep; ++j) {
            TIC(tVarInLoop);
            TIC(tVar);
            auto diag        = ExtractShiftedDiagonalN(A, static_cast<int32_t>(i), static_cast<int32_t>(bStep * j));
            Plaintext A_ptxt = cc.MakePackedPlaintextAux(diag, 1, 0, elementParamsPtr);
            timePackedPtxt += TOC_NS(tVar);
            cntPackedPtxt++;
            TIC(tVar);
            if (j == gStep) {
                cc.EvalAddInPlace(inner, cc.EvalMult(ctxt_swapped, A_ptxt));
            }
            else {
                cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j - 2], A_ptxt));
            }
            timeMultPtxt += TOC_NS(tVar);
            cntMultPtxt++;
            tInner2 += static_cast<double>(TOC_NS(tVarInLoop));
        }
        tOuter2 += static_cast<double>(TOC_NS(tVarOutLoop));

        TIC(tVarOutLoop);
        if (i == 0) {
            result = inner;
        }
        else {
            TIC(tVarInLoop);
            TIC(tVar);
            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            timeRotationPrec += TOC_NS(tVar);
            cntRotationPrec++;
            TIC(tVar);
            cc.EvalAddInPlace(result, cc.EvalFastRotation(inner, i, M, innerDigits));
            timeRotations += TOC_NS(tVar);
            cntRotations++;
            tInner3 += static_cast<double>(TOC_NS(tVarInLoop));
        }
        tOuter3 += static_cast<double>(TOC_NS(tVarOutLoop));
        tIn += static_cast<double>(TOC_NS(tVarIn));
    }
    std::cout << "Time for the loop: " << static_cast<double>(TOC_NS(tVarAll)) / 1000000000.0 << " s" << std::endl;
    std::cout << "Time for i inner loops: " << tIn / 1000000000.0 << " s" << std::endl;

    std::cout << "Time for i * j loops interior: " << tInner1 / 1000000000.0 << " s" << std::endl;
    std::cout << "Time for i * j loops: " << tOuter1 / 1000000000.0 << " s" << std::endl;
    std::cout << "Time for second i * j loops interior: " << tInner2 / 1000000000.0 << " s" << std::endl;
    std::cout << "Time for second i * j loops: " << tOuter2 / 1000000000.0 << " s" << std::endl;
    std::cout << "Time for i updates interior: " << tInner3 / 1000000000.0 << " s" << std::endl;
    std::cout << "Time for i updates: " << tOuter3 / 1000000000.0 << " s" << std::endl;

    return result;
}

Ciphertext<DCRTPoly> EvalSlotsToCoeffs(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                       bool precompute) {
    // TimeVar tVar;
    // TIC(tVar);
    auto ctxtToDecode = ctxt;  // ->Clone();
    // timeClone += TOC_NS(tVar);
    // cntClone++;

    // auto dim1BF = (dim1 == 0) ? getRatioBSGSPow2(cc.GetRingDimension() / 2) : dim1;

    // Currently, this is only implemented for all slots (= ring dimension)
    if (precompute) {
        return EvalLTNWithPrecompute(cc, ctxtToDecode, m_UTPre, m_dim1BF);
    }
    else {
        return EvalLTNWithoutPrecompute(cc, ctxtToDecode, m_UT, m_dim1BF);
    }
}

//------------------------------------------------------------------------------
// EXTRACTION, MODULUS SWITCH AND KEY SWITCH
//------------------------------------------------------------------------------

std::vector<LWECiphertext> EvalBFVtoFHEW(const CryptoContextImpl<DCRTPoly>& cc, const CryptoContextImpl<DCRTPoly>& ccKS,
                                         ConstCiphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly> ctxtKS,
                                         lbcrypto::EvalKey<lbcrypto::DCRTPoly> BFVtoFHEWSwk,
                                         NativeInteger modulus_BFV_to, NativeInteger modulus_FHEW, uint32_t n) {
    // Step 1. Compress and switch to a secure BFV modulus
    // auto decoded = cc.Compress(ctxt, 1); // This is now done before
    auto decoded = ctxt;  // ->Clone();
    ModSwitchDown(decoded, ctxtKS, modulus_BFV_to);

    // Key switch from the BFV key with the new modulus Q' to the RLWE version of the FHEW key with the new modulus Q'
    auto ctSwitched = ccKS.KeySwitch(ctxtKS, BFVtoFHEWSwk);

    // Extract LWE ciphertexts with the modulus Q'
    return ExtractAndScaleLWE(ccKS, ctSwitched, n, modulus_BFV_to, modulus_FHEW);
}

void ModSwitchDown(ConstCiphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly>& ctxtKS, NativeInteger modulus_to) {
    if (ctxt->GetElements()[0].GetRingDimension() != ctxtKS->GetElements()[0].GetRingDimension()) {
        OPENFHE_THROW(not_implemented_error, "ModSwitch is implemented only for the same ring dimension.");
    }

    const std::vector<DCRTPoly> cv = ctxt->GetElements();

    if (cv[0].GetNumOfElements() != 1 || ctxtKS->GetElements()[0].GetNumOfElements() != 1) {
        OPENFHE_THROW(not_implemented_error, "ModSwitch is implemented only for ciphertext with one tower.");
    }

    const auto& paramsQlP = ctxtKS->GetElements()[0].GetParams();
    std::vector<DCRTPoly> resultElements(cv.size());

    for (uint32_t i = 0; i < cv.size(); i++) {
        resultElements[i] = DCRTPoly(paramsQlP, Format::COEFFICIENT, true);
        resultElements[i].SetValuesModSwitch(cv[i], modulus_to);
        resultElements[i].SetFormat(Format::EVALUATION);
    }

    ctxtKS->SetElements(resultElements);
}

std::vector<std::vector<NativeInteger>> ExtractLWEpacked(ConstCiphertext<DCRTPoly> ct) {
    auto originalA{(ct->GetElements()[1]).GetElementAtIndex(0)};
    auto originalB{(ct->GetElements()[0]).GetElementAtIndex(0)};
    originalA.SetFormat(Format::COEFFICIENT);
    originalB.SetFormat(Format::COEFFICIENT);
    auto N = originalB.GetLength();

    std::vector<std::vector<NativeInteger>> extracted(2);
    extracted[0].reserve(N);
    extracted[1].reserve(N);

    auto& originalAVals = originalA.GetValues();
    auto& originalBVals = originalB.GetValues();

    extracted[1].insert(extracted[1].end(), &originalAVals[0], &originalAVals[N]);
    extracted[0].insert(extracted[0].end(), &originalBVals[0], &originalBVals[N]);

    return extracted;
}

std::vector<std::shared_ptr<LWECiphertextImpl>> ExtractAndScaleLWE(const CryptoContextImpl<DCRTPoly>& cc,
                                                                   ConstCiphertext<DCRTPoly> ctxt, uint32_t n,
                                                                   NativeInteger modulus_from,
                                                                   NativeInteger modulus_to) {
    std::vector<std::shared_ptr<LWECiphertextImpl>> LWECiphertexts;
    auto AandB = ExtractLWEpacked(ctxt);
    auto N     = cc.GetRingDimension();
    auto size  = AandB[0].size();

    // std::cout << "AandB size = " << size << ", N = " << N << std::endl;

    for (uint32_t i = 0, idx = 0; i < N; ++i, ++idx) {
        NativeVector a(n, modulus_from);
        NativeInteger b;

        for (size_t j = 0; j < n && j <= idx; ++j) {
            a[j] = modulus_from - AandB[1][idx - j];
        }
        if (n > idx) {
            for (size_t k = idx + 1; k < n; ++k) {
                a[k] = AandB[1][size + idx - k];
            }
        }

        b         = AandB[0][idx];
        auto temp = std::make_shared<LWECiphertextImpl>(std::move(a), std::move(b));
        LWECiphertexts.emplace_back(temp);
    }

    // Modulus switch from modulus_from to modulus_to
#pragma omp parallel for
    for (uint32_t i = 0; i < size; ++i) {
        auto original_a = LWECiphertexts[i]->GetA();
        auto original_b = LWECiphertexts[i]->GetB();
        // multiply by Q_LWE/Q' and round to Q_LWE
        NativeVector a_round(n, modulus_to);
        for (uint32_t j = 0; j < n; ++j) {
            a_round[j] = RoundqQAlter(original_a[j], modulus_to, modulus_from);
        }
        NativeInteger b_round = RoundqQAlter(original_b, modulus_to, modulus_from);
        LWECiphertexts[i]     = std::make_shared<LWECiphertextImpl>(std::move(a_round), std::move(b_round));
    }

    return LWECiphertexts;
}

std::shared_ptr<LWECiphertextImpl> ExtractLWECiphertextShort(const std::vector<std::vector<NativeInteger>>& aANDb,
                                                             NativeInteger modulus, uint32_t n, uint32_t index) {
    auto N = aANDb[0].size();
    NativeVector a(n, modulus);
    NativeInteger b;

    for (size_t i = 0; i < n && i <= index; ++i) {
        a[i] = modulus - aANDb[1][index - i];
    }
    if (n > index) {
        for (size_t i = index + 1; i < n; ++i) {
            a[i] = aANDb[1][N + index - i];
        }
    }

    b           = aANDb[0][index];
    auto result = std::make_shared<LWECiphertextImpl>(std::move(a), std::move(b));
    return result;
}

NativeInteger RoundqQAlter(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) {
    return NativeInteger(
               (BasicInteger)std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble()))
        .Mod(q);
}

EvalKey<DCRTPoly> switchingKeyGenRLWEcc(const PrivateKey<DCRTPoly>& bfvSKto, const PrivateKey<DCRTPoly>& bfvSKfrom,
                                        ConstLWEPrivateKey& LWEsk) {
    auto skElements = bfvSKto->GetPrivateElement();
    skElements.SetFormat(Format::COEFFICIENT);
    auto skElementsFrom = bfvSKfrom->GetPrivateElement();
    skElementsFrom.SetFormat(Format::COEFFICIENT);
    auto skElements2 = bfvSKto->GetPrivateElement();
    skElements2.SetFormat(Format::COEFFICIENT);
    auto lweskElements = LWEsk->GetElement();

    for (size_t i = 0; i < skElements.GetNumOfElements(); i++) {
        auto skElementsPlain     = skElements.GetElementAtIndex(i);
        auto skElementsFromPlain = skElementsFrom.GetElementAtIndex(i);
        auto skElementsPlainLWE  = skElements2.GetElementAtIndex(i);
        for (size_t j = 0; j < skElementsPlain.GetLength(); j++) {
            if (skElementsFromPlain[j] == 0) {
                skElementsPlain[j] = 0;
            }
            else if (skElementsFromPlain[j] == 1) {
                skElementsPlain[j] = 1;
            }
            else
                skElementsPlain[j] = skElementsPlain.GetModulus() - 1;

            if (j >= lweskElements.GetLength()) {
                skElementsPlainLWE[j] = 0;
            }
            else {
                if (lweskElements[j] == 0) {
                    skElementsPlainLWE[j] = 0;
                }
                else if (lweskElements[j].ConvertToInt() == 1) {
                    skElementsPlainLWE[j] = 1;
                }
                else
                    skElementsPlainLWE[j] = skElementsPlain.GetModulus() - 1;
            }
        }
        skElements.SetElementAtIndex(i, skElementsPlain);
        skElements2.SetElementAtIndex(i, skElementsPlainLWE);
    }

    skElements.SetFormat(Format::EVALUATION);
    skElements2.SetFormat(Format::EVALUATION);

    auto cc              = bfvSKto->GetCryptoContext();
    auto oldTranformedSK = cc->KeyGen().secretKey;
    oldTranformedSK->SetPrivateElement(std::move(skElements));
    auto RLWELWEsk = cc->KeyGen().secretKey;
    RLWELWEsk->SetPrivateElement(std::move(skElements2));

    return cc->KeySwitchGen(oldTranformedSK, RLWELWEsk);
}

//------------------------------------------------------------------------------
// GATES AND LOOKUP TABLES
//------------------------------------------------------------------------------

// NAND: add the LWE ciphertexts (and ensure output is in desired range)
// Andreea: Is it worth it to pack first to RLWE and then do the additions?
std::vector<LWECiphertext> EvalNANDAmortized(std::vector<LWECiphertext> ctxtsLWE1, std::vector<LWECiphertext> ctxtsLWE2,
                                             NativeInteger q, bool opt) {
    std::vector<LWECiphertext> preBootCtxt(ctxtsLWE1.size());
    NativeInteger align =
        (opt) ? q / 3 :
                q / 6;  // for DRaMgate_opt use q/3, for DRaMgate_opt_reverse use 5q/6, for non-optimized use q/6
    for (size_t i = 0; i < ctxtsLWE1.size(); ++i) {
        preBootCtxt[i] = std::make_shared<LWECiphertextImpl>(
            ctxtsLWE1[i]->GetA().ModAdd(ctxtsLWE2[i]->GetA()),
            align.ModAddFast(ctxtsLWE1[i]->GetB().ModAddFast(ctxtsLWE2[i]->GetB(), q), q));
    }
    // Andreea: ctxtsLWE1[i]->GetB() has ModAddFast, but ctxtsLWE1[i]->GetA() does not? Both are NativeIntgers
    return preBootCtxt;
}

//------------------------------------------------------------------------------
// DEBUG
//------------------------------------------------------------------------------

NativePoly DecryptWithoutDecoding(ConstCiphertext<DCRTPoly> ctxt, const PrivateKey<DCRTPoly> privateKey) {
    const std::vector<DCRTPoly>& cv = ctxt->GetElements();
    const DCRTPoly& s               = privateKey->GetPrivateElement();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());

    size_t sizeQ  = s.GetParams()->GetParams().size();
    size_t sizeQl = cv[0].GetParams()->GetParams().size();

    size_t diffQl = sizeQ - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    DCRTPoly sPower(scopy);

    DCRTPoly b(cv[0]);
    b.SetFormat(Format::EVALUATION);

    DCRTPoly ci;
    for (size_t i = 1; i < cv.size(); i++) {
        ci = cv[i];
        ci.SetFormat(Format::EVALUATION);

        b += sPower * ci;
        sPower *= scopy;
    }

    b.SetFormat(Format::COEFFICIENT);

    NativePoly element;

    // use RNS procedures only if the number of RNS limbs is larger than 1
    if (sizeQl > 1) {
        element =
            b.ScaleAndRound(cryptoParams->GetPlaintextModulus(), cryptoParams->GettQHatInvModqDivqModt(),
                            cryptoParams->GettQHatInvModqDivqModtPrecon(), cryptoParams->GettQHatInvModqBDivqModt(),
                            cryptoParams->GettQHatInvModqBDivqModtPrecon(), cryptoParams->GettQHatInvModqDivqFrac(),
                            cryptoParams->GettQHatInvModqBDivqFrac());
    }
    else {
        const NativeInteger tt = cryptoParams->GetPlaintextModulus();
        element                = b.GetElementAtIndex(0);
        const NativeInteger qq = element.GetModulus();
        element                = element.MultiplyAndRound(tt, qq);

        // Setting the root of unity to ONE as the calculation is expensive
        // It is assumed that no polynomial multiplications in evaluation
        // representation are performed after this
        element.SwitchModulus(tt, 1, 0, 0);
    }

    return element;
}

// Inefficient way to evaluate a polynomial since it is done in cleartext
std::vector<int64_t> EvalPolyCleartextMod(std::vector<int64_t> input, std::vector<int64_t> coeff, const int64_t t,
                                          bool symmetric) {
    size_t n = coeff.size();

    std::vector<int64_t> output(input.size(), ModDownConst(coeff[0], t));

    if (symmetric) {  // odd coeffiecients are zero
        std::transform(input.begin(), input.end(), input.begin(),
                       [&](const int64_t& elem) { return (elem * elem) % t; });
    }

    std::vector<int64_t> powers(input);

    for (size_t i = 1; i < n; i++) {
        std::vector<int64_t> interm(input.size(), 0);
        std::transform(powers.begin(), powers.end(), interm.begin(),
                       [&](const int64_t& elem) { return (elem * ModDownConst(coeff[i], t)) % t; });
        std::transform(interm.begin(), interm.end(), output.begin(), output.begin(),
                       [&](const auto& elem1, const auto& elem2) { return (elem1 + elem2) % t; });
        std::transform(input.begin(), input.end(), powers.begin(), powers.begin(),
                       [&](const auto& elem1, const auto& elem2) { return (elem1 * elem2) % t; });
    }

    std::transform(output.begin(), output.end(), output.begin(),
                   [&](const auto& elem) { return ModDownHalfConst(elem, t); });

    return output;
}

uint32_t FindLevelsToDrop(usint multiplicativeDepth, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                          uint32_t dcrtBits, bool keySwitch) {
    const auto cryptoParamsBFVrns    = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cryptoParams);
    double sigma                     = cryptoParamsBFVrns->GetDistributionParameter();
    double alpha                     = cryptoParamsBFVrns->GetAssuranceMeasure();
    double p                         = static_cast<double>(cryptoParamsBFVrns->GetPlaintextModulus());
    uint32_t n                       = cryptoParamsBFVrns->GetElementParams()->GetRingDimension();
    uint32_t relinWindow             = cryptoParamsBFVrns->GetDigitSize();
    KeySwitchTechnique scalTechnique = cryptoParamsBFVrns->GetKeySwitchTechnique();
    EncryptionTechnique encTech      = cryptoParamsBFVrns->GetEncryptionTechnique();

    uint32_t k                = cryptoParamsBFVrns->GetNumPerPartQ();
    uint32_t numPartQ         = cryptoParamsBFVrns->GetNumPartQ();
    uint32_t thresholdParties = cryptoParamsBFVrns->GetThresholdNumOfParties();
    // Bkey set to thresholdParties * 1 for ternary distribution
    const double Bkey = (cryptoParamsBFVrns->GetSecretKeyDist() == GAUSSIAN) ?
                            sqrt(thresholdParties) * sigma * sqrt(alpha) :
                            thresholdParties;

    double w = relinWindow == 0 ? pow(2, dcrtBits) : pow(2, relinWindow);

    // Bound of the Gaussian error polynomial
    double Berr = sigma * sqrt(alpha);

    // expansion factor delta
    auto delta = [](uint32_t n) -> double {
        return (2. * sqrt(n));
    };

    // norm of fresh ciphertext polynomial (for EXTENDED the noise is reduced to modulus switching noise)
    auto Vnorm = [&](uint32_t n) -> double {
        if (encTech == EXTENDED)
            return (1. + delta(n) * Bkey) / 2.;
        else
            return Berr * (1. + 2. * delta(n) * Bkey);
    };

    auto noiseKS = [&](uint32_t n, double logqPrev, double w) -> double {
        if (scalTechnique == HYBRID)
            return k * (numPartQ * delta(n) * Berr + delta(n) * Bkey + 1.0) / 2;
        else
            return delta(n) * (floor(logqPrev / (log(2) * dcrtBits)) + 1) * w * Berr;
    };

    // function used in the EvalMult constraint
    auto C1 = [&](uint32_t n) -> double {
        return delta(n) * delta(n) * p * Bkey;
    };

    // function used in the EvalMult constraint
    auto C2 = [&](uint32_t n, double logqPrev) -> double {
        return delta(n) * delta(n) * Bkey * Bkey / 2.0 + noiseKS(n, logqPrev, w);
    };

    // main correctness constraint
    auto logqBFV = [&](uint32_t n, double logqPrev) -> double {
        if (multiplicativeDepth > 0) {
            return log(4 * p) + (multiplicativeDepth - 1) * log(C1(n)) +
                   log(C1(n) * Vnorm(n) + multiplicativeDepth * C2(n, logqPrev));
        }
        return log(p * (4 * (Vnorm(n))));
    };

    // initial values
    double logqPrev = 6. * log(10);
    double logq     = logqBFV(n, logqPrev);

    while (fabs(logq - logqPrev) > log(1.001)) {
        logqPrev = logq;
        logq     = logqBFV(n, logqPrev);
    }

    // get an estimate of the error q / (4t)
    double loge = logq / log(2) - 2 - log2(p);

    double logExtra = keySwitch ? log2(noiseKS(n, logq, w)) : log2(delta(n));

    // adding the cushon to the error (see Appendix D of https://eprint.iacr.org/2021/204.pdf for details)
    // adjusted empirical parameter to 16 from 4 for threshold scenarios to work correctly, this might need to
    // be further refined
    int32_t levels = std::floor((loge - 2 * multiplicativeDepth - 16 - logExtra) / dcrtBits);
    size_t sizeQ   = cryptoParamsBFVrns->GetElementParams()->GetParams().size();

    if (levels < 0)
        levels = 0;
    else if (levels > static_cast<int32_t>(sizeQ) - 1)
        levels = sizeQ - 1;

    return levels;
};
