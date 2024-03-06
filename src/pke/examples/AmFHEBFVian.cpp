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

#define ITERATIVE
#define TESTALT0

#include "openfhe.h"
#include "binfhecontext.h"
#include "fhew_bt_coeff.h"

#include <algorithm>
#include <queue>

using namespace lbcrypto;
using namespace std;

// GLOBAL VARIABLES
std::vector<std::vector<int64_t>> m_UT;
std::vector<ConstPlaintext> m_UTPre;
uint32_t m_dim1BF;
uint32_t m_LBF;
int64_t PTXT_MOD          = 65537;

// FUNCTIONS
void NANDthroughBFV();
void cLUTthroughBFV();

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
                                              double scale = 1.0);
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

uint32_t Degree(const std::vector<int64_t>& coefficients, uint32_t limit = 0);
uint32_t FindFirstNonZero(const std::vector<int64_t>& coefficients);
uint32_t CountNonZero(const std::vector<int64_t>& coefficients);
std::vector<int64_t> Rotate(const std::vector<int64_t>& a, int32_t index);
std::vector<int64_t> Fill(const std::vector<int64_t>& a, int32_t slots);
std::vector<int64_t> ExtractShiftedDiagonalN(const std::vector<std::vector<int64_t>>& A, uint32_t idx_in, uint32_t idx_out);
std::vector<int32_t> FindLTNRotationIndices(uint32_t dim1, uint32_t N);
uint32_t getRatioBSGSPow2(uint32_t slots);

struct schemeSwitchKeys {
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>
        FHEWtoBFVKey;  // Only for column method, otherwise it is a single ciphertext
    lbcrypto::EvalKey<lbcrypto::DCRTPoly> BFVtoFHEWSwk;
    schemeSwitchKeys(std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>&& key1,
                     lbcrypto::EvalKey<lbcrypto::DCRTPoly>&& key2) noexcept
        : FHEWtoBFVKey(std::move(key1)), BFVtoFHEWSwk(std::move(key2)) {}
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

    cLUTthroughBFV();

    return 0;
}

void NANDthroughBFV() {
    std::cout << "\n*****AMORTIZED NAND with RECURSIVE P-S*****\n" << std::endl;

    TimeVar tVar, tOnline;
    TIC(tVar);

    // Step 0. Meta-parameter
    bool opt = true;  // false;

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
    parameters.SetScalingModSize(60);
    parameters.SetKeySwitchTechnique(HYBRID);  // BV doesn't work for Compress then KeySwitch
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);
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
    parameters_KS.SetScalingModSize(27);
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

    double timePS = TOC_NS(tVar);
    std::cout << "---Time to evaluate the polynomial of degree " << coeff.size() - 1 << " for opt = " << opt << ": "
              << timePS / 1000000000.0 << " s\n"
              << std::endl;

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

}

//------------------------------------------------------------------------------
// BFV OPERATIONS
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> EvalLinearWSumBFV(const std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                       const std::vector<int64_t>& constants) {
    uint32_t size = std::min(ciphertexts.size(), constants.size());

    std::vector<Ciphertext<DCRTPoly>> cts;
    cts.reserve(size);
    std::vector<int64_t> constantsNZ;
    constantsNZ.reserve(size);

    TimeVar tVar;
    TIC(tVar);
    for (uint32_t i = 0; i < size; i++) {
        if (constants[i] != 0) {
            cts.push_back(ciphertexts[i]->Clone());
            constantsNZ.push_back(constants[i]);
        }
    }

    return EvalLinearWSumMutableBFV(cts, constantsNZ);
}
// This does not actually modify ciphertexts, and it would be incorrect if it would
Ciphertext<DCRTPoly> EvalLinearWSumMutableBFV(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                              const std::vector<int64_t>& constants) {
    uint32_t pos = FindFirstNonZero(constants);

    if (pos < ciphertexts.size()) {
        auto cc = ciphertexts[0]->GetCryptoContext();
        Ciphertext<DCRTPoly> weightedSum(EvalMultConstBFV(ciphertexts[pos], constants[pos]));
        for (uint32_t i = pos + 1; i < ciphertexts.size(); i++) {
            if (constants[i] != 0) {
                cc->EvalAddInPlace(weightedSum, EvalMultConstBFV(ciphertexts[i], constants[i]));
            }
        }
        return weightedSum;
    }
    return ciphertexts[0]->CloneZero();
}

Ciphertext<DCRTPoly> EvalMultConstBFV(ConstCiphertext<DCRTPoly> ciphertext, const int64_t constant) {
    Ciphertext<DCRTPoly> ciphertext_res = ciphertext->Clone();
    EvalMultCoreInPlaceBFV(ciphertext_res, constant);
    return ciphertext_res;
}

Ciphertext<DCRTPoly> EvalAddConstBFV(ConstCiphertext<DCRTPoly> ciphertext, const int64_t constant) {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    EvalAddInPlaceConstBFV(result, constant);
    return result;
}

uint64_t ModDownConst(const int64_t constant, const NativeInteger t) {
    auto t_int        = t.ConvertToInt<int64_t>();
    auto mod_constant = constant % t_int;
    if (mod_constant < 0)
        mod_constant += t_int;
    return mod_constant;
}

int64_t ModDownHalfConst(const int64_t constant, const NativeInteger t) {
    auto t_int        = t.ConvertToInt<int64_t>();
    auto mod_constant = constant % t_int;
    if (mod_constant < -static_cast<int32_t>(t_int / 2)) {  // <--- why int32_t?
        mod_constant += t_int;
    }
    else if (mod_constant >= t_int / 2) {
        mod_constant -= t_int;
    }
    return mod_constant;
}

void EvalMultCoreInPlaceBFV(Ciphertext<DCRTPoly>& ciphertext, const int64_t constant) {
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

    // ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + 1); // If this is set, it might lead to more moduli being dropped
}

void EvalAddInPlaceConstBFV(Ciphertext<DCRTPoly>& ciphertext, const int64_t constant) {
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
}

//------------------------------------------------------------------------------
// UTILS + FUNCTIONS THAT SHOULD BE USED WITH TEMPLATES IN ckksrns-utils
//------------------------------------------------------------------------------
std::vector<int64_t> Rotate(const std::vector<int64_t>& a, int32_t index) {
    int32_t slots = a.size();
    if (index < 0 || index > slots)
        index = ReduceRotation(index, slots);
    if (index == 0)
        return a;

    std::vector<int64_t> result;
    result.reserve(slots);
    result.insert(result.end(), a.begin() + index, a.end());
    result.insert(result.end(), a.begin(), a.begin() + index);
    return result;
}

std::vector<int64_t> Fill(const std::vector<int64_t>& a, int32_t slots) {
    int32_t usedSlots = a.size();
    std::vector<int64_t> result(slots);
    int32_t j = 0;
    for (int32_t i = 0; i < slots; ++i) {
        result[i] = a[j];
        if (++j == usedSlots)
            j = 0;
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
std::vector<int64_t> ExtractShiftedDiagonalN(const std::vector<std::vector<int64_t>>& A, uint32_t idx_out, uint32_t idx_in) {
    uint32_t N = A.size();
    if (N != A[0].size())
        OPENFHE_THROW(config_error, "ExtractShiftedDiagonalN is implemented only for square matrices.");
    uint32_t Nby2 = N >> 1;
    uint32_t mask = Nby2 - 1;

    std::vector<int64_t> result(N);
    if (idx_in < Nby2) {
        for (uint32_t j = 0; j < Nby2; ++j) {
            auto row_idx = (j - idx_out) & mask;
            auto col_idx = (j + idx_in) & mask;
            result[j] = A[row_idx][col_idx];
        }
        for (uint32_t j = Nby2; j < N; ++j) {
            auto row_idx = Nby2 + ((j - idx_out) & mask);
            auto col_idx = Nby2 + ((j + idx_in) & mask);
            result[j] = A[row_idx][col_idx];
        }
    }
    else {
        for (uint32_t j = 0; j < Nby2; ++j) {
            auto row_idx = (j - idx_out) & mask;
            auto col_idx = Nby2 + ((j + idx_in) & mask);
            result[j] = A[row_idx][col_idx];
        }
        for (uint32_t j = Nby2; j < N; ++j) {
            auto row_idx = Nby2 + ((j - idx_out) & mask);
            auto col_idx = (j + idx_in) & mask;
            result[j] = A[row_idx][col_idx];
        }
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

    if (int32_t(n - k) < 0)
        return std::make_shared<longDivMod>(std::vector<int64_t>(1), f);

    auto res = std::make_shared<longDivMod>();

    auto& q = res->q;
    q.resize(n - k + 1);

    auto& r = res->r;
    r = f;

    std::vector<int64_t> d;
    d.reserve(g.size() + n);

    while (int32_t(n - k) >= 0) {
        // d is g padded with zeros before up to n
        d.clear();
        d.resize(n - k);
        d.insert(d.end(), g.begin(), g.end());

        q[n - k] = r.back();
        if (g[k] != 1)
            q[n - k] = (q[n - k] / g.back()) % t;

        std::transform(d.begin(), d.end(), d.begin(), [&](const int64_t& elem) { return (elem * q[n - k]) % t; });
        // f-=d
        std::transform(r.begin(), r.end(), d.begin(), r.begin(), [&](const auto& elem1, const auto& elem2) { return (elem1 - elem2) % t; });

        if (r.size() > 1) {
            n = Degree(r);
            r.resize(n + 1);
        }
    }
    return res;
}

/*Return the degree of the polynomial described by coefficients,
which is the index of the last non-zero element in the coefficients - 1.
Don't throw an error if all the coefficients are zero, but return 0. */
uint32_t Degree(const std::vector<int64_t>& coefficients, uint32_t limit) {
    if (limit == 0)
        limit = coefficients.size();

    uint32_t deg = 1;
    for (int32_t i = limit - 1; i > 0; --i, ++deg) {
        if (coefficients[i] != 0)
            break;
    }

    return limit - deg;
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
                cu = EvalMultConstBFV(powers.front(), divcs->q[1]);
            }
            else {
                cu         = powers.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);
            for (size_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }
            cu = EvalLinearWSumMutableBFV(ctxs, weights);
        }

        // adds the free term (at x^0)
        EvalAddInPlaceConstBFV(cu, divcs->q.front());
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
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (size_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }

            qu = EvalLinearWSumMutableBFV(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            cc->EvalAddInPlace(qu, powers[k - 1]);
        }
        else {
            qu         = powers[k - 1]->Clone();
        }
        // adds the free term (at x^0)
        EvalAddInPlaceConstBFV(qu, divqr->q.front());
    }

    uint64_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        su         = qu->Clone();
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
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (size_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }
                su = EvalLinearWSumMutableBFV(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                cc->EvalAddInPlace(su, powers[k - 1]);
            }
            else {
                su         = powers[k - 1]->Clone();
            }
            // adds the free term (at x^0)
            EvalAddInPlaceConstBFV(su, s2.front());
        }
    }

    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
    }
    else {
        result = EvalAddConstBFV(powers2[m - 1], divcs->q.front());
    }

    result     = cc->EvalMult(result, qu);
    cc->EvalAddInPlace(result, su);

    // std::cout << "---Out of inner poly---" << std::endl;

    return result;
}

Ciphertext<DCRTPoly> EvalPolyPSBFV(ConstCiphertext<DCRTPoly> x, const std::vector<int64_t>& coefficients,
                                   bool symmetric) {
    TimeVar tIn, tVar, tVar2;

    auto xClone = x;  // ->Clone()
    auto cc = x->GetCryptoContext();

    if (symmetric) {
        xClone     = cc->EvalSquare(xClone);
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
    powers[0] = xClone->Clone();

    // computes all powers up to k for x
    for (size_t i = 2; i <= k; i++) {
        if (!(i & (i - 1))) {
            // if i is a power of two
            powers[i - 1] = cc->EvalSquare(powers[i / 2 - 1]);
        }
        else {
            if (indices[i - 1] == 1) {
                // non-power of 2
                int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
                int64_t rem      = i % powerOf2;
                powers[i - 1] = cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]);
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers2(m);

    // computes powers of form k*2^i for x
    powers2.front() = powers.back()->Clone();
    for (uint32_t i = 1; i < m; i++) {
        powers2[i] = cc->EvalSquare(powers2[i - 1]);
    }

    // computes the product of the powers in power2, that yield x^{k(2*m - 1)}
    auto power2km1 = powers2.front()->Clone();
    for (uint32_t i = 1; i < m; i++) {
        power2km1 = cc->EvalMult(power2km1, powers2[i]);
    }

    double timePowers = TOC_NS(tIn);
    std::cout << "-----Time to compute the powers for poly eval: " << timePowers / 1000000000.0 << " s" << std::endl;

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
                cu = EvalMultConstBFV(powers.front(), static_cast<int64_t>(divcs->q[1]));
            }
            else {
                cu = powers.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);

            for (uint32_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }
            cu = EvalLinearWSumMutableBFV(ctxs, weights);
        }

        // adds the free term (at x^0)
        EvalAddInPlaceConstBFV(cu, static_cast<int64_t>(divcs->q.front()));
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
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }

            TIC(tVar);
            qu = EvalLinearWSumMutableBFV(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            cc->EvalAddInPlace(qu, powers[k - 1]);
        }
        else {
            qu         = powers[k - 1]->Clone();
        }
        // adds the free term (at x^0)
        EvalAddInPlaceConstBFV(qu, divqr->q.front());
    }

    uint32_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        su         = qu->Clone();
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
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (uint32_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }

                su = EvalLinearWSumMutableBFV(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                cc->EvalAddInPlace(su, powers[k - 1]);
            }
            else {
                su         = powers[k - 1]->Clone();
            }
            // adds the free term (at x^0)
            EvalAddInPlaceConstBFV(su, s2.front());
        }
    }

    /*Ciphertext<DCRTPoly> result;
    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
    }
    else {
        result = EvalAddConstBFV(powers2[m - 1], divcs->q.front());
    }

    result = cc->EvalMult(result, qu);

    cc->EvalAddInPlace(result, su);
    cc->EvalSubInPlace(result, power2km1);

    return result;
    */

    // Save some cloning since powers2[m-1] is not used again
    if (flag_c) {
        cc->EvalAddInPlace(powers2[m - 1], cu);
    }
    else {
        EvalAddInPlaceConstBFV(powers2[m - 1], divcs->q.front());
    }
    powers2[m - 1] = cc->EvalMult(powers2[m - 1], qu);
    cc->EvalAddInPlace(powers2[m - 1], su);
    cc->EvalSubInPlace(powers2[m - 1], power2km1);

    return powers2[m - 1];
}

Ciphertext<DCRTPoly> InnerEvalPolyPSBFVWithPrecompute(ConstCiphertext<DCRTPoly> x, uint32_t k, uint32_t m,
                                                      std::vector<Ciphertext<DCRTPoly>>& powers,
                                                      std::vector<Ciphertext<DCRTPoly>>& powers2) {
    // std::cout << "---Inner poly---" << std::endl;
    auto cc = x->GetCryptoContext();

    // Compute k*2^m because we use it often
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    auto divqr = qr[m].front();
    qr[m].pop();

    auto divcs = cs[m].front();
    cs[m].pop();

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
                cu = EvalMultConstBFV(powers.front(), divcs->q[1]);
            }
            else {
                cu         = powers.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);
            for (size_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }
            cu = EvalLinearWSumMutableBFV(ctxs, weights);
        }

        // adds the free term (at x^0)
        EvalAddInPlaceConstBFV(cu, divcs->q.front());
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
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (size_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }

            qu = EvalLinearWSumMutableBFV(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            cc->EvalAddInPlace(qu, powers[k - 1]);
        }
        else {
            qu         = powers[k - 1]->Clone();
        }
        // adds the free term (at x^0)
        EvalAddInPlaceConstBFV(qu, divqr->q.front());
    }

    uint64_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        su         = qu->Clone();
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
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (size_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }
                su = EvalLinearWSumMutableBFV(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                cc->EvalAddInPlace(su, powers[k - 1]);
            }
            else {
                su         = powers[k - 1]->Clone();
            }
            // adds the free term (at x^0)
            EvalAddInPlaceConstBFV(su, s2.front());
        }
    }

    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
    }
    else {
        result = EvalAddConstBFV(powers2[m - 1], divcs->q.front());
    }
    result     = cc->EvalMult(result, qu);

    cc->EvalAddInPlace(result, su);

    return result;
}

Ciphertext<DCRTPoly> EvalPolyPSBFVWithPrecompute(ConstCiphertext<DCRTPoly> x, bool symmetric) {
    TimeVar tIn;

    auto xClone = x; 

    auto cc = x->GetCryptoContext();

    if (symmetric) {
        xClone     = cc->EvalSquare(xClone);
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
    powers[0] = xClone->Clone();

    // computes all powers up to k for x
    for (size_t i = 2; i <= k; i++) {
        if (!(i & (i - 1))) {
            // if i is a power of two
            powers[i - 1] = cc->EvalSquare(powers[i / 2 - 1]);
        }
        else {
            if (indices[i - 1] == 1) {
                // non-power of 2
                int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
                int64_t rem      = i % powerOf2;
                powers[i - 1] = cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]);
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers2(m);

    // computes powers of form k*2^i for x
    powers2.front() = powers.back()->Clone();
    for (uint32_t i = 1; i < m; i++) {
        powers2[i] = cc->EvalSquare(powers2[i - 1]);
    }

    // computes the product of the powers in power2, that yield x^{k(2*m - 1)}
    auto power2km1 = powers2.front()->Clone();
    for (uint32_t i = 1; i < m; i++) {
        power2km1 = cc->EvalMult(power2km1, powers2[i]);
    }

    double timePowers = TOC_NS(tIn);
    std::cout << "-----Time to compute the powers for poly eval: " << timePowers / 1000000000.0 << " s" << std::endl;

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    auto divqr = qr[m].front();
    qr[m].pop();

    auto divcs = cs[m].front();
    cs[m].pop();

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
                cu = EvalMultConstBFV(powers.front(), static_cast<int64_t>(divcs->q[1]));
            }
            else {
                cu = powers.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);

            for (uint32_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }
            cu = EvalLinearWSumMutableBFV(ctxs, weights);
        }

        // adds the free term (at x^0)
        EvalAddInPlaceConstBFV(cu, static_cast<int64_t>(divcs->q.front()));
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
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }

            qu = EvalLinearWSumMutableBFV(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            cc->EvalAddInPlace(qu, powers[k - 1]);
        }
        else {
            qu         = powers[k - 1]->Clone();
        }
        // adds the free term (at x^0)
        EvalAddInPlaceConstBFV(qu, divqr->q.front());
    }

    uint32_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        su         = qu->Clone();
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
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (uint32_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }

                su = EvalLinearWSumMutableBFV(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                cc->EvalAddInPlace(su, powers[k - 1]);
            }
            else {
                su         = powers[k - 1]->Clone();
            }
            // adds the free term (at x^0)
            EvalAddInPlaceConstBFV(su, s2.front());
        }
    }

    // Save some cloning since powers2[m-1] is not used again
    if (flag_c) {
        cc->EvalAddInPlace(powers2[m - 1], cu);
    }
    else {
        EvalAddInPlaceConstBFV(powers2[m - 1], divcs->q.front());
    }

    powers2[m - 1] = cc->EvalMult(powers2[m - 1], qu);

    cc->EvalAddInPlace(powers2[m - 1], su);
    cc->EvalSubInPlace(powers2[m - 1], power2km1);

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

    return make_shared<schemeSwitchKeys>(std::move(FHEWtoBFVKey), std::move(BFVtoFHEWSwk));
}

std::vector<Plaintext> EvalMatMultColPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                const std::vector<std::vector<int64_t>>& A, uint32_t L) {
    uint32_t rows = A.size();
    uint32_t cols = A[0].size();
    std::vector<Plaintext> Apre(cols);

#pragma omp parallel for
    for (size_t j = 0; j < cols; ++j) {
        std::vector<int64_t> temp_vec(rows);
        for (size_t i = 0; i < rows; ++i) {
            temp_vec[i] = A[i][j];
        }
        Apre[j] = cc.MakePackedPlaintext(temp_vec);
    }

    return Apre;
}

std::vector<ConstPlaintext> EvalLTNPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                              const std::vector<std::vector<int64_t>>& A, uint32_t dim1, uint32_t L,
                                              double scale) {
    if (A[0].size() != A.size()) {
        OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecomputeSwitch is not square");
    }

    uint32_t N    = cc.GetRingDimension();  // When this method is used for homomorphic decoding in BFV, N = size
    uint32_t size  = A.size();
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSPow2(size / 2) : dim1;

    // Encode plaintext at minimum number of levels
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc.GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        while (elementParams.GetParams().size() > 1) {
            elementParams.PopLastParam();
        }
    }
    auto elementParamsPtr = std::make_shared<DCRTPoly::Params>(elementParams);

    std::vector<ConstPlaintext> result(size);
    for (uint32_t i = 0, j = 0, k = 0; k < size; ++k) {
        auto diag = ExtractShiftedDiagonalN(A, i, j);
        if (scale != 1.0)
            std::transform(diag.begin(), diag.end(), diag.begin(), [&](const int64_t& elem) { return elem * scale; });
        result[k] = cc.MakePackedPlaintextAux(Fill(diag, N), 1, 0, elementParamsPtr);
        if (++i == bStep) {
            i = 0;
            j += bStep;
        }
    }

    return result;
}

void EvalSlotsToCoeffsPrecompute(const CryptoContextImpl<DCRTPoly>& cc, double scale, bool precompute) {
    uint32_t N     = cc.GetRingDimension();
    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = N / 2;

    NativeInteger t = cc.GetCryptoParameters()->GetPlaintextModulus();

    NativeInteger initRoot = RootOfUnity<NativeInteger>(M, t);

    // Matrix for decoding
    std::vector<std::vector<int64_t>> UT(N, std::vector<int64_t>(N));

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
            UT[i][j]         = NativeInteger(zetaPows[i].ModExp(j, t)).ConvertToInt<int64_t>();
            UT[i + slots][j] = NativeInteger(UT[i][j]).ModInverse(t).ConvertToInt<int64_t>();
        }
    }

    if (precompute) {
        m_UTPre = EvalLTNPrecompute(cc, UT, m_dim1BF, 1);
    }
    m_UT = std::move(UT);
}

//------------------------------------------------------------------------------
// LINEAR TRANSFORM FOR BFV
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> EvalFHEWtoBFV(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<LWECiphertext>& lweCtxt,
                                   const std::vector<Ciphertext<DCRTPoly>>& keyCtxt) {
    uint32_t numValues = lweCtxt.size();
    uint32_t n         = lweCtxt[0]->GetLength();
    uint32_t cols_po2  = 1 << static_cast<uint32_t>(std::ceil(std::log2(n)));

    std::vector<std::vector<int64_t>> A(numValues, std::vector<int64_t>(cols_po2));
    std::vector<int64_t> b(numValues);

    for (uint32_t i = 0; i < numValues; ++i) {
        const auto& a_v = lweCtxt[i]->GetA();
        for (uint32_t j = 0; j < n; ++j) {
            A[i][j] = a_v[j].ConvertToInt<int64_t>();
        }
        b[i] = lweCtxt[i]->GetB().ConvertToInt<int64_t>();
    }

    return cc.EvalAdd(cc.EvalNegate(EvalMatMultColWithoutPrecompute(cc, A, keyCtxt)), cc.MakePackedPlaintext(b));
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
    Ciphertext<DCRTPoly> res;
    uint32_t n = ct.size();

    uint32_t log_n = lbcrypto::GetMSB(n) - 1;
    std::vector<Ciphertext<DCRTPoly>> layer((1 << (log_n - 1)));

    for (size_t i = 0; i < log_n; ++i) {
        for (size_t j = 0; j < static_cast<uint32_t>(1 << (log_n - i - 1)); ++j) {
            if (i == 0) {  // first layer, need to compute the multiplications
                layer[j] = cc.EvalAdd(cc.EvalMult(A[j * 2], ct[j * 2]), cc.EvalMult(A[j * 2 + 1], ct[j * 2 + 1]));
            }
            else {
                layer[j] = cc.EvalAdd(layer[j * 2], layer[j * 2 + 1]);
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
    uint32_t rows = A.size();
    std::vector<int64_t> temp_vec1(rows), temp_vec2(rows);

    uint32_t log_n = lbcrypto::GetMSB(ct.size()) - 1;
    uint32_t jj    = 1 << (log_n - 1);
    std::vector<Ciphertext<DCRTPoly>> layer;
    layer.reserve(jj);

    for (uint32_t j = 0; j < jj; ++j) {
        for (uint32_t k = 0; k < rows; ++k) {
            temp_vec1[k] = A[k][j * 2];
            temp_vec2[k] = A[k][j * 2 + 1];
        }
        layer.push_back(cc.EvalAdd(cc.EvalMult(cc.MakePackedPlaintext(temp_vec1), ct[j * 2]),
                                   cc.EvalMult(cc.MakePackedPlaintext(temp_vec2), ct[j * 2 + 1])));
    }

    jj >>= 1;
    for (uint32_t i = 0; i < log_n; ++i, jj >>= 1) {
        for (uint32_t j = 0; j < jj; ++j) {
            layer[j] = cc.EvalAdd(layer[j * 2], layer[j * 2 + 1]);
        }
    }

    return layer[0];
}

// Encrypted matrix-vector multiplication of size N implemented as two sized N/2 matrix-vector multiplications
Ciphertext<DCRTPoly> EvalLTNWithPrecompute(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                           const std::vector<ConstPlaintext>& A, uint32_t dim1) {
    uint32_t N = A.size();
    uint32_t M = cc.GetCyclotomicOrder();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSPow2(N / 2) : dim1;
    uint32_t gStep = ceil(static_cast<double>(N / 2) / bStep);

    // std::cout << "bStep = " << bStep << ", gStep = " << gStep << ", N = " << N << std::endl;

    // Swap ciphertext halves
    // Swap ciphertext halves
    Ciphertext<DCRTPoly> ctxt_swapped = cc.EvalAtIndex(ctxt, N / 2);

    ctxt         = cc.Compress(ctxt, 1);
    ctxt_swapped = cc.Compress(ctxt_swapped, 1);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(2 * gStep - 2);
    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits  = cc.EvalFastRotationPrecompute(ctxt);
    auto digits2 = cc.EvalFastRotationPrecompute(ctxt_swapped);

    // Hoisted automorphisms
#pragma omp parallel for
    for (size_t j = 1; j < gStep; j++) {
        fastRotation[j - 1]             = cc.EvalFastRotation(ctxt, j * bStep, M, digits);
        fastRotation[j - 1 + gStep - 1] = cc.EvalFastRotation(ctxt_swapped, j * bStep, M, digits2);
    }

    Ciphertext<DCRTPoly> result;

    for (size_t i = 0; i < bStep; ++i) {
        Ciphertext<DCRTPoly> inner;
        for (size_t j = 0; j < gStep; ++j) {
            if (j == 0) {
                inner = cc.EvalMult(ctxt, A[i]);
            }
            else {
                cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j - 1], A[bStep * j + i]));
            }
        }
        for (size_t j = gStep; j < 2 * gStep; ++j) {
            if (j == gStep) {
                cc.EvalAddInPlace(inner, cc.EvalMult(ctxt_swapped, A[bStep * j + i]));
            }
            else {
                cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j - 2], A[bStep * j + i]));
            }
        }

        if (i == 0) {
            result = inner;
        }
        else {
            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            cc.EvalAddInPlace(result, cc.EvalFastRotation(inner, i, M, innerDigits));
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

    // Swap ciphertext halves
    Ciphertext<DCRTPoly> ctxt_swapped = cc.EvalAtIndex(ctxt, N / 2);

    ctxt         = cc.Compress(ctxt, 1);
    ctxt_swapped = cc.Compress(ctxt_swapped, 1);

    // std::cout << "-----ctxt depth, level, GetElements().size(), and GetElements()[0].GetNumOfElements(): "
    //           << ctxt->GetNoiseScaleDeg() << ", " << ctxt->GetLevel() << ", " << ctxt->GetElements().size() << ", "
    //           << ctxt->GetElements()[0].GetNumOfElements() << std::endl;

    std::vector<Ciphertext<DCRTPoly>> fastRotation(2 * gStep - 2);

    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits  = cc.EvalFastRotationPrecompute(ctxt);
    auto digits2 = cc.EvalFastRotationPrecompute(ctxt_swapped);

    // Hoisted automorphisms
    // #pragma omp parallel for
    for (size_t j = 1; j < gStep; j++) {
        fastRotation[j - 1]             = cc.EvalFastRotation(ctxt, j * bStep, M, digits);
        fastRotation[j - 1 + gStep - 1] = cc.EvalFastRotation(ctxt_swapped, j * bStep, M, digits2);
    }

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

    Ciphertext<DCRTPoly> result;
    for (size_t i = 0; i < bStep; ++i) {
        Ciphertext<DCRTPoly> inner;
        for (size_t j = 0; j < gStep; ++j) {
            auto diag        = ExtractShiftedDiagonalN(A, static_cast<int32_t>(i), static_cast<int32_t>(bStep * j));
            Plaintext A_ptxt = cc.MakePackedPlaintextAux(diag, 1, 0, elementParamsPtr);
            if (j == 0) {
                inner = cc.EvalMult(ctxt, A_ptxt);
            }
            else {
                cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j - 1], A_ptxt));
            }
        }

        for (size_t j = gStep; j < 2 * gStep; ++j) {
            auto diag        = ExtractShiftedDiagonalN(A, static_cast<int32_t>(i), static_cast<int32_t>(bStep * j));
            Plaintext A_ptxt = cc.MakePackedPlaintextAux(diag, 1, 0, elementParamsPtr);
            if (j == gStep) {
                cc.EvalAddInPlace(inner, cc.EvalMult(ctxt_swapped, A_ptxt));
            }
            else {
                cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j - 2], A_ptxt));
            }
        }

        if (i == 0) {
            result = inner;
        }
        else {
            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            cc.EvalAddInPlace(result, cc.EvalFastRotation(inner, i, M, innerDigits));
        }
    }

    return result;
}

Ciphertext<DCRTPoly> EvalSlotsToCoeffs(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                       bool precompute) {
    auto ctxtToDecode = ctxt; 
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
    if (ctxt->GetElements()[0].GetRingDimension() != ctxtKS->GetElements()[0].GetRingDimension())
        OPENFHE_THROW(not_implemented_error, "ModSwitch is implemented only for the same ring dimension.");

    const auto& cv = ctxt->GetElements();
    if (cv[0].GetNumOfElements() != 1 || ctxtKS->GetElements()[0].GetNumOfElements() != 1)
        OPENFHE_THROW(not_implemented_error, "ModSwitch is implemented only for ciphertext with one tower.");

    const auto& paramsQlP = ctxtKS->GetElements()[0].GetParams();
    std::vector<DCRTPoly> resultElements;
    resultElements.reserve(cv.size());

    for (const auto& v : cv) {
        resultElements.emplace_back(paramsQlP, Format::COEFFICIENT, true);
        resultElements.back().SetValuesModSwitch(v, modulus_to);
        resultElements.back().SetFormat(Format::EVALUATION);
    }

    ctxtKS->SetElements(std::move(resultElements));
}

std::vector<std::vector<NativeInteger>> ExtractLWEpacked(ConstCiphertext<DCRTPoly> ct) {
    auto originalA{(ct->GetElements()[1]).GetElementAtIndex(0)};
    originalA.SetFormat(Format::COEFFICIENT);
    const auto itA = std::vector<NativeInteger>::const_iterator(&originalA.GetValues()[0]);

    auto originalB{(ct->GetElements()[0]).GetElementAtIndex(0)};
    originalB.SetFormat(Format::COEFFICIENT);
    const auto itB = std::vector<NativeInteger>::const_iterator(&originalB.GetValues()[0]);

    // create 2 "begin" iterators to work with element values
    size_t N = originalA.GetLength();
    return std::vector<std::vector<NativeInteger>>{std::vector<NativeInteger>(itB, itB + N),
                                                   std::vector<NativeInteger>(itA, itA + N)};
}

std::vector<std::shared_ptr<LWECiphertextImpl>> ExtractAndScaleLWE(const CryptoContextImpl<DCRTPoly>& cc,
                                                                   ConstCiphertext<DCRTPoly> ctxt, uint32_t n,
                                                                   NativeInteger modulus_from,
                                                                   NativeInteger modulus_to) {
    auto BandA    = ExtractLWEpacked(ctxt);
    uint32_t size = BandA[0].size();

    std::vector<std::shared_ptr<LWECiphertextImpl>> LWECiphertexts;
    auto N = cc.GetRingDimension();
    LWECiphertexts.reserve(N);

    // std::cout << "BandA size = " << size << ", N = " << N << std::endl;

    for (uint32_t i = 0, idx = 0; i < N; ++i, ++idx) {
        NativeVector a(n, modulus_from);
        for (uint32_t j = 0; j < n && j <= idx; ++j)
            a[j] = modulus_from - BandA[1][idx - j];

        if (n > idx) {
            for (uint32_t k = idx + 1; k < n; ++k) {
                a[k] = BandA[1][size + idx - k];
            }
        }
        LWECiphertexts.emplace_back(std::make_shared<LWECiphertextImpl>(std::move(a), NativeInteger(BandA[0][idx])));
    }

    // Modulus switch from modulus_from to modulus_to
#pragma omp parallel for
    for (uint32_t i = 0; i < size; ++i) {
        auto& original_a = LWECiphertexts[i]->GetA();
        auto& original_b = LWECiphertexts[i]->GetB();
        // multiply by Q_LWE/Q' and round to Q_LWE
        NativeVector a_round(n, modulus_to);
        for (uint32_t j = 0; j < n; ++j)
            a_round[j] = RoundqQAlter(original_a[j], modulus_to, modulus_from);
        NativeInteger b_round = RoundqQAlter(original_b, modulus_to, modulus_from);
        LWECiphertexts[i]     = std::make_shared<LWECiphertextImpl>(std::move(a_round), std::move(b_round));
    }
    return LWECiphertexts;
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
    const auto& lweskElements = LWEsk->GetElement();

    uint32_t ii = skElements.GetNumOfElements();

    for (uint32_t i = 0; i < ii; ++i) {
        auto& skElementsPlain            = skElements.GetAllElements()[i];
        auto& skElementsPlainLWE         = skElements2.GetAllElements()[i];
        const auto& skElementsFromPlain = skElementsFrom.GetElementAtIndex(i);

        uint32_t jj = skElementsPlain.GetLength();
        auto tmp    = skElementsPlain.GetModulus() - 1;
        for (uint32_t j = 0; j < jj; ++j) {
            if (skElementsFromPlain[j] == 0) {
                skElementsPlain[j] = 0;
            }
            else if (skElementsFromPlain[j] == 1) {
                skElementsPlain[j] = 1;
            }
            else
                skElementsPlain[j] = tmp;

            if (j >= lweskElements.GetLength()) {
                skElementsPlainLWE[j] = 0;
            }
            else {
                if (lweskElements[j] == 0) {
                    skElementsPlainLWE[j] = 0;
                }
                else if (lweskElements[j] == 1) {
                    skElementsPlainLWE[j] = 1;
                }
                else
                    skElementsPlainLWE[j] = tmp;
            }
        }
    }

    auto cc              = bfvSKto->GetCryptoContext();
    auto oldTranformedSK = cc->KeyGen().secretKey;
    skElements.SetFormat(Format::EVALUATION);
    oldTranformedSK->SetPrivateElement(std::move(skElements));

    auto RLWELWEsk = cc->KeyGen().secretKey;
    skElements2.SetFormat(Format::EVALUATION);
    RLWELWEsk->SetPrivateElement(std::move(skElements2));

    return cc->KeySwitchGen(std::move(oldTranformedSK), std::move(RLWELWEsk));
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



// ####################################################################################################################################################

std::shared_ptr<schemeSwitchKeys> cEvalAmortizedFHEWBootKeyGen(CryptoContextImpl<DCRTPoly>& cc,
                                                              const KeyPair<DCRTPoly>& keyPair,
                                                              ConstLWEPrivateKey& lwesk,
                                                              const PrivateKey<DCRTPoly> privateKeyKS, uint32_t dim1,
                                                              uint32_t L) {
    const auto& privateKey = keyPair.secretKey;
    const auto& publicKey  = keyPair.publicKey;

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
    uint32_t n    = lwesk->GetElement().GetLength();
    auto& temp_sk = lwesk->GetElement();  // re-encode to binary

    std::vector<int64_t> LWE_sk;
    LWE_sk.reserve(n);
    std::vector<int64_t> vec_LWE_sk(N);
    std::vector<Ciphertext<DCRTPoly>> FHEWtoBFVKey;
    FHEWtoBFVKey.reserve(n);

    // This encoding is for the column method: obtain n ciphertext each containing one repeated element of the vector of LWE sk
    for (uint32_t i = 0; i < n; i++) {
        auto temp = temp_sk[i].ConvertToInt<int64_t>();
        LWE_sk.push_back(temp > 1 ? -1 : temp);
        std::fill(vec_LWE_sk.begin(), vec_LWE_sk.end(), LWE_sk.back());
        FHEWtoBFVKey.push_back(cc.Encrypt(publicKey, cc.MakePackedPlaintext(vec_LWE_sk)));
    }

    // Compute switching key hint between main BFV secret key to the intermediate BFV (for modulus switching) key to the FHEW key
    auto BFVtoFHEWSwk = switchingKeyGenRLWEcc(privateKeyKS, privateKey, lwesk);

    return make_shared<schemeSwitchKeys>(std::move(FHEWtoBFVKey), std::move(BFVtoFHEWSwk));
}

Ciphertext<DCRTPoly> cEvalMultConstBFV(const ConstCiphertext<DCRTPoly>& ciphertext, const int64_t constant) {
    const auto& t = ciphertext->GetCryptoParameters()->GetPlaintextModulus();
    auto res      = ciphertext->Clone();

    NativeInteger mod_constant = ModDownConst(constant, t);
    for (auto& c : res->GetElements())
        c *= mod_constant;

    return res;
}

void cEvalAddInPlaceConstBFV(Ciphertext<DCRTPoly>& ciphertext, const int64_t constant) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoParameters());

    const std::vector<NativeInteger>& tInvModq = cryptoParams->GettInvModq();
    const NativeInteger& t                     = cryptoParams->GetPlaintextModulus();
    const NativeInteger& NegQModt              = cryptoParams->GetNegQModt();
    const NativeInteger& NegQModtPrecon        = cryptoParams->GetNegQModtPrecon();

    DCRTPoly tmp(ciphertext->GetElements()[0].GetParams(), Format::COEFFICIENT, true);
    tmp = {ModDownConst(constant, t)};
    tmp.TimesQovert(cryptoParams->GetElementParams(), tInvModq, t, NegQModt, NegQModtPrecon);
    tmp.SetFormat(Format::EVALUATION);
    ciphertext->GetElements()[0] += tmp;
}

Ciphertext<DCRTPoly> cEvalLinearWSumBFV(const std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                        const std::vector<int64_t>& constants, const uint32_t limit) {
#if 1
    uint32_t i = 1;
    for (; i <= limit; ++i) {
        if (constants[i] != 0)
            break;
    }

    if (i <= limit) {
        auto cc = ciphertexts[i - 1]->GetCryptoContext();
        Ciphertext<DCRTPoly> weightedSum = cEvalMultConstBFV(ciphertexts[i - 1], constants[i]);
        for (++i; i <= limit; ++i) { // Andreea: what does that mean?
            if (constants[i] != 0)
                cc->EvalAddInPlace(weightedSum, cEvalMultConstBFV(ciphertexts[i - 1], constants[i]));
        }
        return weightedSum;
    }
    return ciphertexts[0]->CloneZero();
#else
    auto cc          = ciphertexts[0]->GetCryptoContext();
    auto weightedSum = cEvalMultConstBFV(ciphertexts[0], constants[1]);

    for (uint32_t i = 2; i <= limit; ++i) {
        if (constants[i] != 0)
            cc->EvalAddInPlace(weightedSum, cEvalMultConstBFV(ciphertexts[i - 1], constants[i]));
    }
    return weightedSum;
#endif
}

inline Ciphertext<DCRTPoly> evalqu(const ConstCiphertext<DCRTPoly>& x, uint32_t k,
                            const std::vector<int64_t>& qrq,
                            const std::vector<Ciphertext<DCRTPoly>>& p) {
//    Ciphertext<DCRTPoly> result = p[k - 1]->Clone();
//    cEvalAddInPlaceConstBFV(result, qrq.front());
//    x->GetCryptoContext()->EvalAddInPlace(result, cEvalLinearWSumBFV(p, qrq, Degree(qrq, k)));
//    return result;

    Ciphertext<DCRTPoly> result = p[k - 1]->Clone();
    if (auto d = Degree(qrq, k); d > 0) {
        if (d == 0)
            x->GetCryptoContext()->EvalAddInPlace(result, cEvalMultConstBFV(p.front(), qrq[1]));
        else
            x->GetCryptoContext()->EvalAddInPlace(result, cEvalLinearWSumBFV(p, qrq, d));
    }
    cEvalAddInPlaceConstBFV(result, qrq.front());
    return result;
}

inline Ciphertext<DCRTPoly> evalcu(const ConstCiphertext<DCRTPoly>& x, uint32_t m,
                            const std::vector<int64_t>& csq,
                            const std::vector<Ciphertext<DCRTPoly>>& p,
                            const std::vector<Ciphertext<DCRTPoly>>& p2) {
//    Ciphertext<DCRTPoly> result = p2[m - 1]->Clone();
//    cEvalAddInPlaceConstBFV(result, csq.front());
//    x->GetCryptoContext()->EvalAddInPlace(result, cEvalLinearWSumBFV(p, csq, Degree(csq)));
//    return result;

    Ciphertext<DCRTPoly> result = p2[m - 1]->Clone();
    if (auto d = Degree(csq); d > 0) {
        if (d == 0)
            x->GetCryptoContext()->EvalAddInPlace(result, cEvalMultConstBFV(p.front(), csq[1]));
        else
            x->GetCryptoContext()->EvalAddInPlace(result, cEvalLinearWSumBFV(p, csq, d));
    }
    cEvalAddInPlaceConstBFV(result, csq.front());
    return result;
}


#ifdef ITERATIVE

struct TreeNode {
    uint32_t m;
    std::vector<int64_t> qrq, csq, csr;
    Ciphertext<DCRTPoly> res;
    TreeNode* left{nullptr};
    TreeNode* right{nullptr};
    TreeNode(uint32_t m, const std::vector<int64_t>& qrq) : m(m), qrq(qrq) {}
};
std::vector<TreeNode> schedule;

#else

void cInnerEvalPolyPSBFVPrecompute(const std::vector<int64_t>& f2, uint32_t k, uint32_t m) {
    // Compute k*2^m because we use it often
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Divide f2 by x^{k*2^{m-1}}
    std::vector<int64_t> xkm(k2m2k + k + 1);
    xkm.back() = 1;

    auto divqr = LongDivisionPolyMod(f2, xkm);
    qr[m].push(divqr);

    // Subtract x^{k(2^{m-1} - 1)} from r
    auto& r2 = divqr->r;
    if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
        r2[k2m2k] -= 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(k2m2k + 1);
        r2.back() = -1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionPolyMod(r2, divqr->q);
    cs[m].push(divcs);

    // Add x^{k(2^{m-1} - 1)} to s
    auto& s2 = divcs->r;
    s2.resize(k2m2k + 1);
    s2.back() = 1;

    if (Degree(divqr->q) > k)
        cInnerEvalPolyPSBFVPrecompute(divqr->q, k, m - 1);

    if (!std::equal(s2.begin(), s2.end(), divqr->q.begin()) && (Degree(s2) > k))
        cInnerEvalPolyPSBFVPrecompute(s2, k, m - 1);
}

Ciphertext<DCRTPoly> cInnerEvalPolyPSBFVWithPrecompute(const ConstCiphertext<DCRTPoly>& x, uint32_t k, uint32_t m,
                                                       const std::vector<Ciphertext<DCRTPoly>>& powers,
                                                       const std::vector<Ciphertext<DCRTPoly>>& powers2) {
    auto qrq = std::move(qr[m].front()->q);
    qr[m].pop();

    auto csq = std::move(cs[m].front()->q);
    auto csr = std::move(cs[m].front()->r);
    cs[m].pop();

#ifdef TESTALT0
    Ciphertext<DCRTPoly> qu = (Degree(qrq) > k)
                                ? cInnerEvalPolyPSBFVWithPrecompute(x, k, m - 1, powers, powers2)
                                : evalqu(x, k, qrq, powers);

    const auto& cc = x->GetCryptoContext();
    if (std::equal(csr.begin(), csr.end(), qrq.begin()))
        return cc->EvalAdd(cc->EvalMult(evalcu(x, m, csq, powers, powers2), qu), qu);

    Ciphertext<DCRTPoly> su = (Degree(csr) > k)
                                ? cInnerEvalPolyPSBFVWithPrecompute(x, k, m - 1, powers, powers2)
                                : evalqu(x, k, csr, powers);

    return cc->EvalAdd(cc->EvalMult(evalcu(x, m, csq, powers, powers2), qu), su);
#else
    const auto& cc = x->GetCryptoContext();
    Ciphertext<DCRTPoly> qu;
    if (Degree(qrq) > k) {
        qu = cInnerEvalPolyPSBFVWithPrecompute(x, k, m - 1, powers, powers2);
    }
    else {
        qu = powers[k - 1]->Clone();
        cEvalAddInPlaceConstBFV(qu, qrq.front());
        cc->EvalAddInPlace(qu, cEvalLinearWSumBFV(powers, qrq, Degree(qrq, k)));
    }

    Ciphertext<DCRTPoly> cu(powers2[m - 1]->Clone());
    cEvalAddInPlaceConstBFV(cu, csq.front());
    cc->EvalAddInPlace(cu, cEvalLinearWSumBFV(powers, csq, Degree(csq)));

    if (std::equal(csr.begin(), csr.end(), qrq.begin()))
        return cc->EvalAdd(cc->EvalMult(cu, qu), qu);

    Ciphertext<DCRTPoly> su;
    if (Degree(csr) > k) {
        su = cInnerEvalPolyPSBFVWithPrecompute(x, k, m - 1, powers, powers2);
    }
    else {
        su = powers[k - 1]->Clone();
        cEvalAddInPlaceConstBFV(su, csr.front());
        cc->EvalAddInPlace(su, cEvalLinearWSumBFV(powers, csr, Degree(csr, k)));
    }

    return cc->EvalAdd(cc->EvalMult(cu, qu), su);
#endif
}
#endif


void cEvalPolyPSBFVPrecompute(const std::vector<int64_t>& coefficients) {
    uint32_t n = Degree(coefficients);
    auto degs  = ComputeDegreesPS(n);
    uint32_t k = degs[0];
    uint32_t m = degs[1];
    m_nPS      = n;
    m_kPS      = k;
    m_mPS      = m;

    uint32_t k2m2k = k * (1 << (m - 1)) - k;
    cout << "\nDegree: n = " << n << ", k = " << k << ", m = " << m << ", k2m2k = " << k2m2k << endl;

#ifdef ITERATIVE
    schedule.reserve(1 << m);
    schedule.emplace_back(m, coefficients);

    schedule[0].qrq.resize(2 * k2m2k + k + 1);
    schedule[0].qrq.back() = 1;

    std::vector<int64_t> xkm(k2m2k + k + 1);

    uint32_t i = 0;
    while (i < schedule.size()) {
        auto& node = schedule[i];
        ++i;

        k2m2k = k * (1 << (node.m - 1)) - k;
        xkm.resize(k2m2k + k + 1);
        xkm.back() = 1;

        auto divqr = LongDivisionPolyMod(node.qrq, xkm);
        node.qrq   = std::move(divqr->q);

        // Subtract x^{k(2^{m-1} - 1)} from r
        auto& r2 = divqr->r;
        if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
            r2[k2m2k] -= 1;
            r2.resize(Degree(r2) + 1);
        }
        else {
            r2.resize(k2m2k + 1);
            r2.back() = -1;
        }

        auto divcs = LongDivisionPolyMod(r2, node.qrq);
        node.csq   = std::move(divcs->q);
        node.csr   = std::move(divcs->r);
        node.csr.resize(k2m2k + 1);
        node.csr.back() = 1;

        if (Degree(node.qrq) > k) {
            schedule.emplace_back(node.m - 1, node.qrq);
            node.left = &schedule.back();
        }

#ifdef TESTALT0
        if (Degree(node.csr) > k) {
#else
        if (!std::equal(node.csr.begin(), node.csr.end(), node.qrq.begin()) && (Degree(node.csr) > k)) {
#endif
            schedule.emplace_back(node.m - 1, node.csr);
            node.right = &schedule.back();
        }
    }
#else
    qr.resize(m + 1);
    cs.resize(m + 1);

    std::vector<int64_t> f2(coefficients);
    f2.resize(2 * k2m2k + k + 1);
    f2.back() = 1;

    cInnerEvalPolyPSBFVPrecompute(f2, k, m);
#endif
}

Ciphertext<DCRTPoly> cEvalPolyPSBFVWithPrecompute(const ConstCiphertext<DCRTPoly>& x, bool symmetric) {

    uint32_t n = m_nPS;
    uint32_t k = m_kPS;
    uint32_t m = m_mPS;

    std::cerr << "\nDegree: n = " << n << ", k = " << k << ", m = " << m << endl;

    TimeVar tIn;
    TIC(tIn);

    const auto& cc = x->GetCryptoContext();
    std::vector<Ciphertext<DCRTPoly>> powers;
    powers.reserve(k);
    powers.push_back((symmetric ? cc->EvalSquare(x) : x->Clone()));

    // computes all powers up to k for x
    uint32_t powerOf2 = 2;
    uint32_t rem      = 0;
    for (uint32_t i = 2; i <= k; i++) {
        powers.push_back((rem == 0) ? cc->EvalSquare(powers[(powerOf2 >> 1) - 1])
                                    : cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]));
        if (++rem == powerOf2) {
            powerOf2 <<= 1;
            rem = 0;
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers2;
    powers2.reserve(m);
    powers2.push_back(powers.back()->Clone());
    auto power2km1 = powers.back()->Clone();
    for (uint32_t i = 1; i < m; i++) {
        powers2.push_back(cc->EvalSquare(powers2[i - 1]));
        power2km1 = cc->EvalMult(power2km1, powers2.back());
    }

    std::cout << "-----Time to compute the powers for poly eval: " << TOC_NS(tIn) / 1000000000.0 << " s" << std::endl;

#ifdef ITERATIVE
    for (auto node = schedule.rbegin(); node != schedule.rend(); ++node) {
        Ciphertext<DCRTPoly> qu = node->left
                                ? node->left->res
                                : evalqu(x, k, node->qrq, powers);
#ifndef TESTALT0
        if (std::equal(node->csr.begin(), node->csr.end(), node->qrq.begin()))
            node->res = cc->EvalAdd(cc->EvalMult(evalcu(x, node->m, node->csq, powers, powers2), qu), qu);
#endif
        Ciphertext<DCRTPoly> su = node->right
                                ? node->right->res
                                : evalqu(x, k, node->csr, powers);
        node->res = cc->EvalAdd(cc->EvalMult(evalcu(x, node->m, node->csq, powers, powers2), qu), su);
    }
    return cc->EvalSub(schedule.front().res, power2km1);
#else
    return cc->EvalSub(cInnerEvalPolyPSBFVWithPrecompute(x, k, m, powers, powers2), power2km1);
#endif
}

Ciphertext<DCRTPoly> cEvalLTNWithPrecompute(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                           const std::vector<ConstPlaintext>& A, uint32_t dim1) {

    uint32_t N     = A.size();
    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSPow2(N / 2) : dim1;
    uint32_t gStep = ceil(static_cast<double>(N / 2) / bStep);

    auto ctxt_swapped = cc.Compress(cc.EvalAtIndex(ctxt, N / 2), 1);
    ctxt = cc.Compress(ctxt, 1);

    std::vector<Ciphertext<DCRTPoly>> fastRotation;
    fastRotation.reserve(gStep);
    auto digits  = cc.EvalFastRotationPrecompute(ctxt);

    std::vector<Ciphertext<DCRTPoly>> fastRotation2;
    fastRotation2.reserve(gStep);
    auto digits2 = cc.EvalFastRotationPrecompute(ctxt_swapped);

    for (uint32_t j = 1; j < gStep; j++) {
        fastRotation.push_back(cc.EvalFastRotation(ctxt, j * bStep, M, digits));
        fastRotation2.push_back(cc.EvalFastRotation(ctxt_swapped, j * bStep, M, digits2));
    }

    Ciphertext<DCRTPoly> result = cc.EvalMult(ctxt, A[0]);
    cc.EvalAddInPlace(result, cc.EvalMult(ctxt_swapped, A[bStep * gStep]));
    for (uint32_t j = 1, j2 = gStep + 1; j < gStep; ++j, ++j2) {
        cc.EvalAddInPlace(result, cc.EvalMult(fastRotation[j - 1], A[bStep * j]));
        cc.EvalAddInPlace(result, cc.EvalMult(fastRotation2[j - 1], A[bStep * j2]));
    }

    Ciphertext<DCRTPoly> inner;
    for (uint32_t i = 1; i < bStep; ++i) {
        inner = cc.EvalMult(ctxt, A[i]);
        cc.EvalAddInPlace(inner, cc.EvalMult(ctxt_swapped, A[bStep * gStep + i]));
        for (uint32_t j = 1, j2 = gStep + 1; j < gStep; ++j, ++j2) {
            cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j - 1], A[bStep * j + i]));
            cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation2[j - 1], A[bStep * j2 + i]));
        }
        cc.EvalAddInPlace(result, cc.EvalFastRotation(inner, i, M, cc.EvalFastRotationPrecompute(inner)));
    }

    return result;
}

Ciphertext<DCRTPoly> cEvalSlotsToCoeffs(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                       bool precompute) {
    auto ctxtToDecode = ctxt;  // ->Clone();
    if (precompute)
        return cEvalLTNWithPrecompute(cc, ctxtToDecode, m_UTPre, m_dim1BF);
    return EvalLTNWithoutPrecompute(cc, ctxtToDecode, m_UT, m_dim1BF);
}


void cLUTthroughBFV() {
    std::cout << "\n*****AMORTIZED LUT*****\n" << std::endl;

    TimeVar tVar, tOnline;

    // Step 1. FHEW cryptocontext generation
    TIC(tVar);
    auto ccLWE            = BinFHEContext();
    const uint32_t n      = 1024;
    const uint32_t NN     = 1024;  // RSGW ring dim. Not used
    const uint32_t p      = 512;
    const NativeInteger q = 65537;
    const NativeInteger Q = 18014398509404161;

    ccLWE.BinFHEContext::GenerateBinFHEContext(n, NN, q, Q, 3.19, 32, 32, 32, UNIFORM_TERNARY, GINX, 10);
    auto params = ccLWE.GetParams();
    auto QFHEW  = ccLWE.GetParams()->GetLWEParams()->Getq();

    LWEPrivateKey lwesk = ccLWE.KeyGen();

    std::cout << "\n--- Time for Step1 = FHEW param generation: " << TOC_NS(tVar) / 1000000000.0 << " s\n";
    std::cout << "    FHEW params: p = " << p << ", n = " << n << ", q = " << q << std::endl;


    // Step 2. Main BFV cryptocontext generation
    uint32_t numDigits = 3;
    uint32_t maxRelin  = 2;
    uint32_t numValues = 8;

    CCParams<CryptoContextBFVRNS> parameters;
    // The BFV plaintext modulus needs to be the same as the FHEW ciphertext modulus
    parameters.SetPlaintextModulus(q.ConvertToInt());
    parameters.SetMultiplicativeDepth(18);
    parameters.SetMaxRelinSkDeg(maxRelin);
    parameters.SetNumLargeDigits(numDigits);
    parameters.SetScalingModSize(60);
    parameters.SetKeySwitchTechnique(HYBRID);  // BV doesn't work for Compress then KeySwitch
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);

    CryptoContext<DCRTPoly> ccBFV = GenCryptoContext(parameters);
    ccBFV->Enable(PKE);
    ccBFV->Enable(KEYSWITCH);
    ccBFV->Enable(LEVELEDSHE);
    ccBFV->Enable(ADVANCEDSHE);

    auto keys = ccBFV->KeyGen();

    std::cout << "\n--- Time for Step2 = FHEW param generation : " << TOC_NS(tVar) / 1000000000.0 << " s\n";

    uint32_t ringDim = ccBFV->GetRingDimension();

    std::cout << "    BFV params: t = " << ccBFV->GetCryptoParameters()->GetPlaintextModulus() << ", N = " << ringDim
              << ", log2 q = " << log2(ccBFV->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    std::cout << "    Number of digits for keyswitch: " << numDigits << std::endl;
    std::cout << "    MaxRelinSkDeg: " << maxRelin << std::endl;

    // Step 3. Intermediate BFV cruptocontext generation
    TIC(tVar);
    CCParams<CryptoContextBFVRNS> parameters_KS;
    // The BFV plaintext modulus needs to be the same as the FHEW ciphertext modulus
    parameters_KS.SetPlaintextModulus(q.ConvertToInt());
    parameters_KS.SetMultiplicativeDepth(0);
    parameters_KS.SetMaxRelinSkDeg(2);
    parameters_KS.SetRingDim(ringDim);
    parameters_KS.SetScalingModSize(27);
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
    auto ptxtZeroKS = ccBFV_KS->MakePackedPlaintext(std::vector<int64_t>{0});
    auto ctxtKS     = ccBFV_KS->Compress(ccBFV_KS->Encrypt(keys_KS.publicKey, ptxtZeroKS), 1);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ccBFV->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_BFV_from                         = paramsQ[0]->GetModulus();

    const auto cryptoParams2 = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ccBFV_KS->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams2 = *(cryptoParams2->GetElementParams());
    auto paramsQ2                                  = elementParams2.GetParams();
    auto modulus_BFV_to                            = paramsQ2[0]->GetModulus();


    std::cout << "\n--- Time for Step3 = inner BFV param generation: " << TOC_NS(tVar) / 1000000000.0 << " s\n";
    std::cout << "    modulus_BFV_from: " << modulus_BFV_from << ", modulus_BFV_to: " << modulus_BFV_to << std::endl;


    // Step 4. Key generation for switching and precomputations
    TIC(tVar);
    // Automorphism keys for homomorphic decoding, FHEW to BFV key and BFV to FHEW key
    auto keyStruct       = cEvalAmortizedFHEWBootKeyGen(*ccBFV, keys, lwesk, keys_KS.secretKey, 128, 0);
    auto& ctxt_vec_LWE_sk = keyStruct->FHEWtoBFVKey;
    auto& BFVtoFHEWSwk    = keyStruct->BFVtoFHEWSwk;

    EvalSlotsToCoeffsPrecompute(*ccBFV, 1, true);
    cEvalPolyPSBFVPrecompute(DRaMLUT_coeff_sqrt_9);

    std::cout << "\n--- Time for Step4 = key generation & precomputations: " << TOC_NS(tVar) / 1000000000.0 << " s\n";


    // Step 5. Inputs and encryption
    TIC(tOnline);
    TIC(tVar);

    vector<int32_t> x1 = {-4, 0, 1, 4, 9, 16, 121, 144};
    if (x1.size() < numValues)
        x1.resize(numValues);

    std::vector<LWECiphertext> ctxtsLWE1;
    ctxtsLWE1.reserve(numValues);
    for (uint32_t i = 0; i < numValues; i++)
        ctxtsLWE1.push_back(ccLWE.Encrypt(lwesk, x1[i], FRESH, p));

    std::vector<LWEPlaintext> LWEptxt(numValues);
    for (uint32_t i = 0; i < numValues; i++)
        ccLWE.Decrypt(lwesk, ctxtsLWE1[i], &LWEptxt[i], p);

    std::cout << "Encrypted LWE message" << std::endl;
    std::cout << LWEptxt << std::endl;

    std::cout << "\n--- Time for Step5 = inputs and encryption: " << TOC_NS(tVar) / 1000000000.0 << " s\n";
    std::cout << "---Online time so far: " << TOC_NS(tOnline) / 1000000000.0 << " s\n";


    // Step 6. Conversion from LWE to RLWE
    TIC(tVar);
    auto BminusAdotS = EvalFHEWtoBFV(*ccBFV, ctxtsLWE1, ctxt_vec_LWE_sk);

    // Plaintext ptxt;
    // ccBFV->Decrypt(keys.secretKey, BminusAdotS, &ptxt);
    // ptxt->SetLength(numValues);
    // std::cout << "B - A*s: " << ptxt << std::endl;

    std::cout << "\n--- Time for Step6 = FHEWtoBFV: " << TOC_NS(tVar) / 1000000000.0 << " s\n";
    std::cout << "---Online time so far: " << TOC_NS(tOnline) / 1000000000.0 << " s\n";

    /* // Test the matrix-vector multiplication
    std::vector<int64_t> LWE_sk(n);
    for (size_t i = 0; i < n; ++i) {
        Plaintext LWE_sk_ptxt;
        ccBFV->Decrypt(keys.secretKey, ctxt_vec_LWE_sk[i], &LWE_sk_ptxt);
        LWE_sk_ptxt->SetLength(1);
        LWE_sk[i] = LWE_sk_ptxt->GetPackedValue()[0];
    }

    std::vector<std::vector<int64_t>> A(numValues);
    vector<int64_t> b(numValues);
    NativeVector a_v(n);
    for(size_t i = 0; i < numValues; ++i){
     A[i].resize(n);
     a_v = ctxtsLWE1[i]->GetA();
     for(size_t j = 0; j < n; ++j){
         A[i][j] = a_v[j].ConvertToInt();
     }
     b[i] = ctxtsLWE1[i]->GetB().ConvertToInt();
    }

    std::vector<int64_t> res(A.size(), 0);
    for (size_t i = 0; i < A.size(); ++i) {
     for (size_t j = 0; j < A[0].size(); ++j) {
         res[i] += A[i][j] * LWE_sk[j];
     }
     res[i] = ModDownHalfConst(b[i] - res[i], q);
    }
    std::cout << "Cleartext B - A*s % q: " << res << std::endl;
    */

    // Step 7. Polynomial evaluation for rounding and modding down
    TIC(tVar);
    auto ctxt_poly = cEvalPolyPSBFVWithPrecompute(BminusAdotS, false);

    // Plaintext ptxt_res;
    // ccBFV->Decrypt(keys.secretKey, ctxt_poly, &ptxt_res);
    // ptxt_res->SetLength(numValues);
    // std::cout << "\nEvaluated polynomial: " << ptxt_res << std::endl;

    std::cout << "\n--- Time for Step7 = poly evaluation: " << TOC_NS(tVar) / 1000000000.0 << " s\n";
    std::cout << "---Online time so far: " << TOC_NS(tOnline) / 1000000000.0 << " s\n";

    // std::vector<int64_t> decoded_int(ringDim);
    // for(size_t i = 0; i < ringDim; ++i) {
    //     decoded_int[i] = ModDownConst(ptxt->GetPackedValue()[i], q.ConvertToInt());
    // }
    // auto clear_res = EvalPolyCleartextMod(decoded_int, coeff, q.ConvertToInt());
    // std::cout << "Cleartext evaluated polynomial: " << clear_res << std::endl;

    // Step 8. Decoding
    TIC(tVar);
    auto decoded = cEvalSlotsToCoeffs(*ccBFV, ctxt_poly, true);

    // Plaintext ptxt_dec;
    // ccBFV->Decrypt(keys.secretKey, decoded, &ptxt_dec);
    // ptxt_dec->SetLength(numValues);
    // std::cout << "Decoded: " << ptxt_dec << std::endl;

    std::cout << "\n--- Time for Step8 = decoding: " << TOC_NS(tVar) / 1000000000.0 << " s\n";
    std::cout << "---Online time so far: " << TOC_NS(tOnline) / 1000000000.0 << " s\n";

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

    // Step 9. Translating back to FHEW
    TIC(tVar);
    auto ctxtsFHEW = EvalBFVtoFHEW(*ccBFV, *ccBFV_KS, decoded, ctxtKS, BFVtoFHEWSwk, modulus_BFV_to, QFHEW, n);
    std::cout << "\nDecrypting switched ciphertexts" << std::endl;
    vector<LWEPlaintext> ptxtsFHEW(numValues);
    for (uint32_t i = 0; i < numValues; i++) {
        ccLWE.Decrypt(lwesk, ctxtsFHEW[i], &ptxtsFHEW[i], p);
    }
    std::cout << ptxtsFHEW << std::endl;
    std::cout << "\n--- Time for Step9 = BFVtoFHEW & decryption: " << TOC_NS(tVar) / 1000000000.0 << " s\n";
    std::cout << "---Online time so far: " << TOC_NS(tOnline) / 1000000000.0 << " s\n";
}