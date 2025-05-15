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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_FHE_H
#define LBCRYPTO_CRYPTO_CKKSRNS_FHE_H

#include "constants.h"
#include "encoding/plaintext-fwd.h"
#include "schemerns/rns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "utils/caller_info.h"
#include "math/hal/basicint.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class CKKSBootstrapPrecom {
public:
    CKKSBootstrapPrecom() {}

    CKKSBootstrapPrecom(const CKKSBootstrapPrecom& rhs) {
        m_dim1         = rhs.m_dim1;
        m_slots        = rhs.m_slots;
        m_paramsEnc    = rhs.m_paramsEnc;
        m_paramsDec    = rhs.m_paramsDec;
        m_U0Pre        = rhs.m_U0Pre;
        m_U0hatTPre    = rhs.m_U0hatTPre;
        m_U0PreFFT     = rhs.m_U0PreFFT;
        m_U0hatTPreFFT = rhs.m_U0hatTPreFFT;
    }

    CKKSBootstrapPrecom(CKKSBootstrapPrecom&& rhs) {
        m_dim1         = rhs.m_dim1;
        m_slots        = rhs.m_slots;
        m_paramsEnc    = std::move(rhs.m_paramsEnc);
        m_paramsDec    = std::move(rhs.m_paramsDec);
        m_U0Pre        = std::move(rhs.m_U0Pre);
        m_U0hatTPre    = std::move(rhs.m_U0hatTPre);
        m_U0PreFFT     = std::move(rhs.m_U0PreFFT);
        m_U0hatTPreFFT = std::move(rhs.m_U0hatTPreFFT);
    }

    virtual ~CKKSBootstrapPrecom() {}
    // the inner dimension in the baby-step giant-step strategy
    uint32_t m_dim1 = 0;

    // number of slots for which the bootstrapping is performed
    uint32_t m_slots = 0;

    // level budget for homomorphic encoding, number of layers to collapse in one level,
    // number of layers remaining to be collapsed in one level to have exactly the number
    // of levels specified in the level budget, the number of rotations in one level,
    // the baby step and giant step in the baby-step giant-step strategy, the number of
    // rotations in the remaining level, the baby step and giant step in the baby-step
    // giant-step strategy for the remaining level
    std::vector<int32_t> m_paramsEnc = std::vector<int32_t>(CKKS_BOOT_PARAMS::TOTAL_ELEMENTS, 0);

    // level budget for homomorphic decoding, number of layers to collapse in one level,
    // number of layers remaining to be collapsed in one level to have exactly the number
    // of levels specified in the level budget, the number of rotations in one level,
    // the baby step and giant step in the baby-step giant-step strategy, the number of
    // rotations in the remaining level, the baby step and giant step in the baby-step
    // giant-step strategy for the remaining level
    std::vector<int32_t> m_paramsDec = std::vector<int32_t>(CKKS_BOOT_PARAMS::TOTAL_ELEMENTS, 0);

    // Linear map U0; used in decoding
    std::vector<ReadOnlyPlaintext> m_U0Pre;

    // Conj(U0^T); used in encoding
    std::vector<ReadOnlyPlaintext> m_U0hatTPre;

    // coefficients corresponding to U0; used in decoding
    std::vector<std::vector<ReadOnlyPlaintext>> m_U0PreFFT;

    // coefficients corresponding to conj(U0^T); used in encoding
    std::vector<std::vector<ReadOnlyPlaintext>> m_U0hatTPreFFT;

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::make_nvp("dim1_Enc", m_dim1));
        ar(cereal::make_nvp("dim1_Dec", m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP]));
        ar(cereal::make_nvp("slots", m_slots));
        ar(cereal::make_nvp("lEnc", m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET]));
        ar(cereal::make_nvp("lDec", m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET]));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::make_nvp("dim1_Enc", m_dim1));
        ar(cereal::make_nvp("dim1_Dec", m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP]));
        ar(cereal::make_nvp("slots", m_slots));
        ar(cereal::make_nvp("lEnc", m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET]));
        ar(cereal::make_nvp("lDec", m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET]));
    }
};

class FHECKKSRNS : public FHERNS {
    using ParmType = typename DCRTPoly::Params;

public:
    virtual ~FHECKKSRNS() {}

    //------------------------------------------------------------------------------
    // Bootstrap Wrapper
    //------------------------------------------------------------------------------

    void EvalBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc, std::vector<uint32_t> levelBudget,
                            std::vector<uint32_t> dim1, uint32_t slots, uint32_t correctionFactor,
                            bool precompute) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalBootstrapKeyGen(const PrivateKey<DCRTPoly> privateKey,
                                                                            uint32_t slots) override;

    void EvalBootstrapPrecompute(const CryptoContextImpl<DCRTPoly>& cc, uint32_t slots) override;

    Ciphertext<DCRTPoly> EvalBootstrap(ConstCiphertext<DCRTPoly> ciphertext, uint32_t numIterations,
                                       uint32_t precision) const override;

    //------------------------------------------------------------------------------
    // Precomputations for CoeffsToSlots and SlotsToCoeffs
    //------------------------------------------------------------------------------

    std::vector<ReadOnlyPlaintext> EvalLinearTransformPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                              const std::vector<std::vector<std::complex<double>>>& A,
                                                              double scale = 1, uint32_t L = 0) const;

    std::vector<ReadOnlyPlaintext> EvalLinearTransformPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                              const std::vector<std::vector<std::complex<double>>>& A,
                                                              const std::vector<std::vector<std::complex<double>>>& B,
                                                              uint32_t orientation = 0, double scale = 1,
                                                              uint32_t L = 0) const;

    std::vector<std::vector<ReadOnlyPlaintext>> EvalCoeffsToSlotsPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                                         const std::vector<std::complex<double>>& A,
                                                                         const std::vector<uint32_t>& rotGroup,
                                                                         bool flag_i, double scale = 1,
                                                                         uint32_t L = 0) const;

    std::vector<std::vector<ReadOnlyPlaintext>> EvalSlotsToCoeffsPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                                         const std::vector<std::complex<double>>& A,
                                                                         const std::vector<uint32_t>& rotGroup,
                                                                         bool flag_i, double scale = 1,
                                                                         uint32_t L = 0) const;

    //------------------------------------------------------------------------------
    // EVALUATION: CoeffsToSlots and SlotsToCoeffs
    //------------------------------------------------------------------------------

    Ciphertext<DCRTPoly> EvalLinearTransform(const std::vector<ReadOnlyPlaintext>& A, ConstCiphertext<DCRTPoly> ct) const;

    Ciphertext<DCRTPoly> EvalCoeffsToSlots(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                           ConstCiphertext<DCRTPoly> ctxt) const;

    Ciphertext<DCRTPoly> EvalSlotsToCoeffs(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                           ConstCiphertext<DCRTPoly> ctxt) const;

    //------------------------------------------------------------------------------
    // SERIALIZATION
    //------------------------------------------------------------------------------

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<FHERNS>(this));
        ar(cereal::make_nvp("paramMap", m_bootPrecomMap));
        ar(cereal::make_nvp("corFactor", m_correctionFactor));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<FHERNS>(this));
        ar(cereal::make_nvp("paramMap", m_bootPrecomMap));
        ar(cereal::make_nvp("corFactor", m_correctionFactor));
    }

    // To be deprecated; left for backwards compatibility
    static uint32_t GetBootstrapDepth(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                      SecretKeyDist secretKeyDist);

    static uint32_t GetBootstrapDepth(const std::vector<uint32_t>& levelBudget, SecretKeyDist secretKeyDist);

    std::string SerializedObjectName() const {
        return "FHECKKSRNS";
    }

private:
    //------------------------------------------------------------------------------
    // Find Rotation Indices
    //------------------------------------------------------------------------------
    std::vector<int32_t> FindBootstrapRotationIndices(uint32_t slots, uint32_t M);

    // ATTN: The following 3 functions are helper methods to be called in FindBootstrapRotationIndices() only.
    // so they DO NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
    // These methods completely depend on FindBootstrapRotationIndices() to do that.
    std::vector<uint32_t> FindLinearTransformRotationIndices(uint32_t slots, uint32_t M);
    std::vector<uint32_t> FindCoeffsToSlotsRotationIndices(uint32_t slots, uint32_t M);
    std::vector<uint32_t> FindSlotsToCoeffsRotationIndices(uint32_t slots, uint32_t M);

    //------------------------------------------------------------------------------
    // Auxiliary Bootstrap Functions
    //------------------------------------------------------------------------------
    uint32_t GetBootstrapDepthInternal(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                       const CryptoContextImpl<DCRTPoly>& cc);
    static uint32_t GetModDepthInternal(SecretKeyDist secretKeyDist);

    void AdjustCiphertext(Ciphertext<DCRTPoly>& ciphertext, double correction) const;

    void ExtendCiphertext(std::vector<DCRTPoly>& ciphertext, const CryptoContextImpl<DCRTPoly>& cc,
                          const std::shared_ptr<DCRTPoly::Params> params) const;

    void ApplyDoubleAngleIterations(Ciphertext<DCRTPoly>& ciphertext, uint32_t numIt) const;

    Plaintext MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                               const std::vector<std::complex<double>>& value, size_t noiseScaleDeg, uint32_t level,
                               usint slots) const;

    Ciphertext<DCRTPoly> EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const;

    void EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const;

    Ciphertext<DCRTPoly> EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const;

    EvalKey<DCRTPoly> ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey) const;

    Ciphertext<DCRTPoly> Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                                   const std::map<usint, EvalKey<DCRTPoly>>& evalKeys) const;

    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    void FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
                           NativeVector* nativeVec) const;

#if NATIVEINT == 128
    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    void FitToNativeVector(uint32_t ringDim, const std::vector<int128_t>& vec, int128_t bigBound,
                           NativeVector* nativeVec) const;
#endif

    const uint32_t K_SPARSE  = 28;   // upper bound for the number of overflows in the sparse secret case
    const uint32_t K_UNIFORM = 512;  // upper bound for the number of overflows in the uniform secret case
    const uint32_t K_UNIFORMEXT =
        768;  // upper bound for the number of overflows in the uniform secret case for compositeDegreee > 2
    static const uint32_t R_UNIFORM =
        6;  // number of double-angle iterations in CKKS bootstrapping. Must be static because it is used in a static function.
    static const uint32_t R_SPARSE =
        3;  // number of double-angle iterations in CKKS bootstrapping. Must be static because it is used in a static function.
    uint32_t m_correctionFactor = 0;  // correction factor, which we scale the message by to improve precision

    // key tuple is dim1, levelBudgetEnc, levelBudgetDec
    std::map<uint32_t, std::shared_ptr<CKKSBootstrapPrecom>> m_bootPrecomMap;

    // Chebyshev series coefficients for the SPARSE case
    static const inline std::vector<double> g_coefficientsSparse{
        -0.18646470117093214,   0.036680543700430925,    -0.20323558926782626,     0.029327390306199311,
        -0.24346234149506416,   0.011710240188138248,    -0.27023281815251715,     -0.017621188001030602,
        -0.21383614034992021,   -0.048567932060728937,   -0.013982336571484519,    -0.051097367628344978,
        0.24300487324019346,    0.0016547743046161035,   0.23316923792642233,      0.060707936480887646,
        -0.18317928363421143,   0.0076878773048247966,   -0.24293447776635235,     -0.071417413140564698,
        0.37747441314067182,    0.065154496937795681,    -0.24810721693607704,     -0.033588418808958603,
        0.10510660697380972,    0.012045222815124426,    -0.032574751830745423,    -0.0032761730196023873,
        0.0078689491066424744,  0.00070965574480802061,  -0.0015405394287521192,   -0.00012640521062948649,
        0.00025108496615830787, 0.000018944629154033562, -0.000034753284216308228, -2.4309868106111825e-6,
        4.1486274737866247e-6,  2.7079833113674568e-7,   -4.3245388569898879e-7,   -2.6482744214856919e-8,
        3.9770028771436554e-8,  2.2951153557906580e-9,   -3.2556026220554990e-9,   -1.7691071323926939e-10,
        2.5459052150406730e-10};

    // Chebyshev series coefficients for the OPTIMIZED/uniform case
    static const inline std::vector<double> g_coefficientsUniform{
        0.15421426400235561,    -0.0037671538417132409,  0.16032011744533031,      -0.0034539657223742453,
        0.17711481926851286,    -0.0027619720033372291,  0.19949802549604084,      -0.0015928034845171929,
        0.21756948616367638,    0.00010729951647566607,  0.21600427371240055,      0.0022171399198851363,
        0.17647500259573556,    0.0042856217194480991,   0.086174491919472254,     0.0054640252312780444,
        -0.046667988130649173,  0.0047346914623733714,   -0.17712686172280406,     0.0016205080004247200,
        -0.22703114241338604,   -0.0028145845916205865,  -0.13123089730288540,     -0.0056345646688793190,
        0.078818395388692147,   -0.0037868875028868542,  0.23226434602675575,      0.0021116338645426574,
        0.13985510526186795,    0.0059365649669377071,   -0.13918475289368595,     0.0018580676740836374,
        -0.23254376365752788,   -0.0054103844866927788,  0.056840618403875359,     -0.0035227192748552472,
        0.25667909012207590,    0.0055029673963982112,   -0.073334392714092062,    0.0027810273357488265,
        -0.24912792167850559,   -0.0069524866497120566,  0.21288810409948347,      0.0017810057298691725,
        0.088760951809475269,   0.0055957188940032095,   -0.31937177676259115,     -0.0087539416335935556,
        0.34748800245527145,    0.0075378299617709235,   -0.25116537379803394,     -0.0047285674679876204,
        0.13970502851683486,    0.0023672533925155220,   -0.063649401080083698,    -0.00098993213448982727,
        0.024597838934816905,   0.00035553235917057483,  -0.0082485030307578155,   -0.00011176184313622549,
        0.0024390574829093264,  0.000031180384864488629, -0.00064373524734389861,  -7.8036008952377965e-6,
        0.00015310015145922058, 1.7670804180220134e-6,   -0.000033066844379476900, -3.6460909134279425e-7,
        6.5276969021754105e-6,  6.8957843666189918e-8,   -1.1842811187642386e-6,   -1.2015133285307312e-8,
        1.9839339947648331e-7,  1.9372045971100854e-9,   -3.0815418032523593e-8,   -2.9013806338735810e-10,
        4.4540904298173700e-9,  4.0505136697916078e-11,  -6.0104912807134771e-10,  -5.2873323696828491e-12,
        7.5943206779351725e-11, 6.4679566322060472e-13,  -9.0081200925539902e-12,  -7.4396949275292252e-14,
        1.0057423059167244e-12, 8.1701187638005194e-15,  -1.0611736208855373e-13,  -8.9597492970451533e-16,
        1.1421575296031385e-14};

    // Chebyshev series coefficients for the COMPOSITESCALING case where d > 2
    const std::vector<double> g_coefficientsUniformExt{
        // New Coefficients (K_UNIFORM = 768)
        0.12602195635248634,    -0.0030834928649740388,  0.1293538007310393,      -0.0029150296085609707,
        0.13880323885842225,    -0.0025534902415420128,  0.15259900956315636,     -0.0019572806381606537,
        0.16740348080390202,    -0.0010852123927167594,  0.17795704156012629,     7.3594791671716396e-05,
        0.17708229644467954,    0.0014573280941530976,   0.15661113656175465,     0.0028850600459592078,
        0.10984969661272398,    0.0040295575406054489,   0.035829873357113948,    0.004449523200499763,
        -0.055520186697616318,  0.0037264589074560098,   -0.14007871037019429,    0.001719720247528076,
        -0.18281801001428047,   -0.0011373848818829857,  -0.15209319897288492,    -0.0037123962122311092,
        -0.043785371196750272,  -0.0045107273507656552,  0.09756154430583093,     -0.002604845726688627,
        0.18481556762187912,    0.0012462519210521535,   0.1403768476069214,      0.0043541760219966428,
        -0.024293645826662724,  0.0037846793397644275,   -0.17560536795332429,    -0.0005605968506360667,
        -0.1519811728143392,    -0.0045192348096649545,  0.048231020943727741,    -0.0032001529516056853,
        0.19692074387699257,    0.0024419388214462485,   0.078182928643403107,    0.0047838249172446005,
        -0.16476594792427054,   -0.00036614509861925492, -0.14537982038722122,    -0.0050995116137312257,
        0.13564231010825495,    -0.00050653194386865278, 0.16465075644913021,     0.0052831338103145531,
        -0.1493249604350485,    -0.00016209880585104635, -0.13934114757550983,    -0.0054247353644288178,
        0.20649654831497111,    0.0026431561325639561,   0.032277990808412343,    0.0039463054621702767,
        -0.23636345040634044,   -0.0059041496654351176,  0.17831596275657194,     0.0017594032442182191,
        0.05094162125752931,    0.0040150842221901416,   -0.24841268578463685,    -0.0073080801617375155,
        0.3122522704364516,     0.0073316847629231194,   -0.26606798599442621,    -0.0054892692910619113,
        0.17878607636323862,    0.0033586935001791839,   -0.10066311654486482,    -0.001754132071278842,
        0.049074577561330504,   0.00080234886593034873,  -0.021150143470356698,   -0.0003269871328764949,
        0.0081757002802533667,  0.00012021127618051574,  -0.0028652357611661534,  -4.0244300629116574e-05,
        0.00091801734966694636, 1.2361006806444711e-05,  -0.0002707191913116332,  -3.504631720275642e-06,
        7.3888955616723944e-05, 9.2189772261859728e-07,  -1.8752943907614565e-05, -2.2597387576370175e-07,
        4.4436168671606267e-06, 5.1807959456553769e-08,  -9.8651004908533913e-07, -1.1146078152883018e-08,
        2.0582706963882007e-07, 2.2568126993711184e-09,  -4.0469622058265335e-08, -4.31163542777443e-10,
        7.517057515198321e-09,  7.7904840375183328e-11,  -1.3219720621636946e-09, -1.3342979848924908e-11,
        2.2055962238660182e-10, 2.1724065123826773e-12,  -3.4974624736954921e-11, -3.3609296485004418e-13,
        5.2789108285402917e-12, 4.9471164793087018e-14,  -7.5998777765849013e-13, -4.2492853307002972e-15,
        1.0768090434260388e-13, -2.1478500584069139e-15, -1.3891315735425435e-14};
};

}  // namespace lbcrypto

#endif
