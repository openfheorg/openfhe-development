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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_SCHEMESWITCH_H
#define LBCRYPTO_CRYPTO_CKKSRNS_SCHEMESWITCH_H

#include "constants.h"
#include "schemerns/rns-fhe.h"

#include "binfhecontext.h"
#include "lwe-pke.h"
#include "lwe-ciphertext.h"

#include <memory>
#include <string>
#include <utility>
#include <map>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class SWITCHCKKSRNS : public FHERNS {
    using ParmType = typename DCRTPoly::Params;

public:
    virtual ~SWITCHCKKSRNS() {}

    //------------------------------------------------------------------------------
    // Scheme Switching Wrappers
    //------------------------------------------------------------------------------

    std::pair<BinFHEContext, LWEPrivateKey> EvalCKKStoFHEWSetup(const CryptoContextImpl<DCRTPoly>& cc, SecurityLevel sl,
                                                                BINFHE_PARAMSET slBin, bool arbFunc, uint32_t logQ,
                                                                bool dynamic, uint32_t numSlotsCKKS,
                                                                uint32_t logQswitch) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalCKKStoFHEWKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                             ConstLWEPrivateKey& lwesk, uint32_t dim1,
                                                                             uint32_t L) override;

    void EvalCKKStoFHEWPrecompute(const CryptoContextImpl<DCRTPoly>& cc, double scale) override;

    std::vector<ConstPlaintext> EvalLTPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                       const std::vector<std::vector<std::complex<double>>>& A,
                                                       uint32_t dim1, uint32_t L, double scale) const;

    std::vector<ConstPlaintext> EvalLTPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                       const std::vector<std::vector<std::complex<double>>>& A,
                                                       const std::vector<std::vector<std::complex<double>>>& B,
                                                       uint32_t dim1, uint32_t L, double scale) const;

    Ciphertext<DCRTPoly> EvalLTWithPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                    ConstCiphertext<DCRTPoly> ctxt,
                                                    const std::vector<ConstPlaintext>& A, uint32_t dim1) const;

    Ciphertext<DCRTPoly> EvalLTRectWithPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                        const std::vector<std::vector<std::complex<double>>>& A,
                                                        ConstCiphertext<DCRTPoly> ct, uint32_t dim1, uint32_t L) const;

    Ciphertext<DCRTPoly> EvalSlotsToCoeffsSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                 ConstCiphertext<DCRTPoly> ciphertext) const;

    Ciphertext<DCRTPoly> EvalPartialHomDecryption(const CryptoContextImpl<DCRTPoly>& cc,
                                                  const std::vector<std::vector<std::complex<double>>>& A,
                                                  ConstCiphertext<DCRTPoly> ct, uint32_t dim1, double scale,
                                                  uint32_t L) const;

    std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<DCRTPoly> ciphertext,
                                                                   uint32_t numCtxts) override;

    void EvalFHEWtoCKKSSetup(const CryptoContextImpl<DCRTPoly>& ccCKKS, const BinFHEContext& ccLWE,
                             uint32_t numSlotsCKKS, uint32_t logQ) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalFHEWtoCKKSKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                             ConstLWEPrivateKey& lwesk,
                                                                             uint32_t numSlots, uint32_t dim1,
                                                                             uint32_t L) override;

    Ciphertext<DCRTPoly> EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                        uint32_t numCtxts, uint32_t numSlots, uint32_t p, double pmin,
                                        double pmax) const override;

    std::pair<BinFHEContext, LWEPrivateKey> EvalSchemeSwitchingSetup(const CryptoContextImpl<DCRTPoly>& cc,
                                                                     SecurityLevel sl, BINFHE_PARAMSET slBin,
                                                                     bool arbFunc, uint32_t logQ, bool dynamic,
                                                                     uint32_t numSlotsCKKS,
                                                                     uint32_t logQswitch) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalSchemeSwitchingKeyGen(
        const KeyPair<DCRTPoly>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numValues, bool oneHot, bool alt,
        uint32_t dim1CF, uint32_t dim1FC, uint32_t LCF, uint32_t LFC) override;

    void EvalCompareSwitchPrecompute(const CryptoContextImpl<DCRTPoly>& ccCKKS, uint32_t pLWE, uint32_t init_level,
                                     double scaleSign, bool unit) override;

    Ciphertext<DCRTPoly> EvalCompareSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext1,
                                                    ConstCiphertext<DCRTPoly> ciphertext2, uint32_t numCtxts,
                                                    uint32_t numSlots, uint32_t pLWE, double scaleSign,
                                                    bool unit) override;

    std::vector<Ciphertext<DCRTPoly>> EvalMinSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                             PublicKey<DCRTPoly> publicKey, uint32_t numValues,
                                                             uint32_t numSlots, bool oneHot, uint32_t pLWE,
                                                             double scaleSign) override;

    std::vector<Ciphertext<DCRTPoly>> EvalMinSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                PublicKey<DCRTPoly> publicKey, uint32_t numValues,
                                                                uint32_t numSlots, bool oneHot, uint32_t pLWE,
                                                                double scaleSign) override;

    std::vector<Ciphertext<DCRTPoly>> EvalMaxSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                             PublicKey<DCRTPoly> publicKey, uint32_t numValues,
                                                             uint32_t numSlots, bool oneHot, uint32_t pLWE,
                                                             double scaleSign) override;

    std::vector<Ciphertext<DCRTPoly>> EvalMaxSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                PublicKey<DCRTPoly> publicKey, uint32_t numValues,
                                                                uint32_t numSlots, bool oneHot, uint32_t pLWE,
                                                                double scaleSign) override;

    //------------------------------------------------------------------------------
    // SERIALIZATION
    //------------------------------------------------------------------------------

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<FHERNS>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<FHERNS>(this));
    }

    std::string SerializedObjectName() const {
        return "SWITCHCKKSRNS";
    }

private:
    //------------------------------------------------------------------------------
    // Complex Plaintext Functions, copied from ckksrns-fhe. TODO: fix this
    //------------------------------------------------------------------------------

    Plaintext MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                               const std::vector<std::complex<double>>& value, size_t noiseScaleDeg, uint32_t level,
                               usint slots) const;

    Ciphertext<DCRTPoly> EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const;

    void EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const;

    Ciphertext<DCRTPoly> EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const;

    EvalKey<DCRTPoly> ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey) const;

    Ciphertext<DCRTPoly> Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                                   const std::map<usint, EvalKey<DCRTPoly>>& evalKeys) const;

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    void FitToNativeVector(uint32_t ringDim, const std::vector<__int128>& vec, __int128 bigBound,
                           NativeVector* nativeVec) const;

#else  // NATIVEINT == 64
    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    void FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
                           NativeVector* nativeVec) const;
#endif

    //------------------------------------------------------------------------------
    // Private members
    //------------------------------------------------------------------------------

    // Precomputed matrix for CKKS to FHEW switching
    std::vector<ConstPlaintext> m_U0Pre;
    // the LWE cryptocontext to generate when scheme switching from CKKS
    BinFHEContext m_ccLWE;
    // the CKKS cryptocontext for the intermediate modulus switching in CKKS to FHEW
    CryptoContext<DCRTPoly> m_ccKS;
    // the associated ciphertext modulus Q for the LWE cryptocontext
    NativeInteger m_modulus_LWE;
    // the target ciphertext modulus Q for the CKKS cryptocontext. We assume the switching goes to the same initial cryptocontext
    NativeInteger m_modulus_CKKS_initial;
    // the ciphertext modulus Q' for the CKKS cryptocontext that is secure for the LWE ring dimension
    NativeInteger m_modulus_CKKS_from;
    // switching key from CKKS to FHEW
    EvalKey<DCRTPoly> m_CKKStoFHEWswk;
    // switching key from FHEW to CKKS
    Ciphertext<DCRTPoly> m_FHEWtoCKKSswk;
    // a ciphertext under the intermediate cryptocontext
    Ciphertext<DCRTPoly> m_ctxtKS;
    // number of slots encoded in the CKKS ciphertext
    uint32_t m_numSlotsCKKS;
    // baby-step dimensions for linear transform for CKKS->FHEW, FHEW->CKKS
    uint32_t m_dim1CF;
    uint32_t m_dim1FC;
    // starting levels for linear transforms
    uint32_t m_LCF;
    uint32_t m_LFC;

    // target FHEW plaintext modulus
    uint64_t m_plaintextFHEW;
    // scaling factor of CKKS "outer" ciphertext
    double m_scFactorOuter;

#define Pi 3.14159265358979323846

    // K = 16
    enum { LEN_16 = 118 };
    static constexpr std::array<double, LEN_16> g_coefficientsFHEW16{
        0.2455457340168511,     -0.04791906488334782,   0.2838870204084082,     -0.02994453873551349,
        0.3557652261903648,     0.01510656188507299,    0.2953294667450001,     0.07120360233373937,
        -0.1034734733966807,    0.04499759051255525,    -0.4275071243192574,    -0.09034212972909554,
        0.367628762693249,      0.04931806603933471,    -0.14535986272412,      -0.01510693848306369,
        0.03595193549924024,    0.003103658218868759,   -0.006264460660707066,  -0.0004660943047712052,
        0.0008212879885240095,  5.391053389217882e-05,  -8.455154976914221e-05, -4.977380178602518e-06,
        7.04666204400644e-06,   3.765980757166835e-07,  -4.864851013612591e-07, -2.383026746930811e-08,
        2.832970640938316e-08,  1.28177429687131e-09,   -1.412145521045378e-09, -5.939145408994641e-11,
        6.099273252183116e-11,  2.397381728164642e-12,  -2.307402856353623e-12, -8.500921247536622e-14,
        7.704571444110577e-14,  2.704051671841271e-15,  -2.154585361348821e-15, -7.263493008564584e-16,
        -1.260761739828568e-16, 1.637108527837095e-16,  1.185492382226862e-16,  6.379078056744543e-16,
        -1.411300455031979e-16, 3.123678340470779e-16,  5.946279250534737e-16,  2.954322285866942e-16,
        -8.279629336187608e-17, 5.024229619913844e-16,  -3.293034395074617e-16, -1.189255850106947e-15,
        1.674743206637948e-16,  -1.524204491434537e-16, -7.90328254817908e-17,  3.95164127408954e-16,
        -1.317213758029847e-17, 8.016186584581639e-16,  -3.650563843682718e-16, 3.763467880085276e-16,
        -2.709696873661399e-16, -1.524204491434537e-16, -4.83605622590958e-16,  7.376397044967142e-16,
        1.234417464667971e-15,  -2.672062194860546e-16, -4.892508244110859e-17, -7.122362963061386e-16,
        3.763467880085276e-17,  -2.944913616166729e-16, -2.897870267665663e-16, 9.794425157921932e-16,
        -3.198947698072485e-17, 6.614294799249873e-16,  -5.7769231959309e-16,   6.586068790149234e-16,
        -4.629065492504889e-16, -5.127724986616189e-16, -3.236582376873337e-16, -1.64745806450733e-15,
        -9.408669700213192e-16, -4.986594941112991e-16, -1.209954923447416e-15, -1.373665776231126e-16,
        -2.314532746252445e-16, 3.217765037472911e-16,  3.481207789078881e-16,  8.223177317986329e-16,
        -9.766199148821293e-16, 6.19090466274028e-16,   1.209014056477395e-15,  -3.30244306477483e-16,
        5.974505259635377e-16,  5.993322599035803e-16,  1.829986256691466e-16,  -2.690879534260973e-16,
        8.618341445395283e-16,  -1.002023323072705e-16, 6.374373721894436e-16,  6.270878355192092e-16,
        1.199605386777182e-15,  -8.712428142397415e-16, -2.507410475106815e-16, -1.086230916889613e-15,
        1.072588345824304e-15,  -4.534978795502758e-16, 2.119067633230516e-15,  -1.842923177529259e-15,
        -1.814697168428619e-15, 4.243310034796149e-16,  4.224492695395723e-16,  1.531966643937213e-15,
        -2.850826919164597e-16, -8.958229638315484e-16, -5.02893395476395e-16,  1.096110020074837e-16,
        -6.975352498995555e-16, -8.743006318923108e-16};

    // K = 128
    enum { LEN_128_9 = 160 };
    static constexpr std::array<double, LEN_128_9> g_coefficientsFHEW128_9{
        0.08761193238226354,    -0.01738402917379392,   0.08935060894767313,    -0.01667686631436392,
        0.09435445639097996,    -0.01518333497826596,   0.1019473189108075,     -0.01276275748916528,
        0.110882655474149,      -0.009252446966171999,  0.1192111685574758,     -0.004534979909938953,
        0.1242004317120066,     0.001362904847617233,   0.1224283765086551,     0.008145596233693092,
        0.1102080588183085,     0.01512350467093644,    0.08449405378412403,    0.02114203679334985,
        0.04431786059830115,    0.02464956129638114,    -0.007454366487154669,  0.02400059020366966,
        -0.06266441339261235,   0.0180491215413637,     -0.1077943201829795,    0.00695836538813938,
        -0.1265848641500751,    -0.007067567033131986,  -0.1060856934163377,    -0.01966175019277508,
        -0.04512467324356773,   -0.02537595733026167,   0.03862916785371963,    -0.0201785566296389,
        0.1092652333753526,     -0.004612578019766411,  0.1263344585514989,     0.01438496124842956,
        0.07022427857484209,    0.02550072245548077,    -0.03434514153678107,   0.01979242584243335,
        -0.1194659697149694,    -0.001008794768691528,  -0.1149256786653964,    -0.02192904329965044,
        -0.01184295110147364,   -0.02417858011117596,   0.1066507410103885,     -0.003076473516323838,
        0.122343225763269,      0.02209885820126707,    0.005200840409852563,   0.02321022960558625,
        -0.1224755172356864,    -0.003930982569218595,  -0.1000653894904632,    -0.02689795846413602,
        0.05865754664309684,    -0.01297065380451242,   0.1377909895596227,     0.02083617539534925,
        0.006502421233003679,   0.02248299870285675,    -0.139660074659475,     -0.01399307934458518,
        -0.04589168496663835,   -0.0263421662574377,    0.1358978738303921,     0.01130242907664306,
        0.05563799538901031,    0.02715486116995984,    -0.1426236952996719,    -0.01461041285557406,
        -0.03302834981489188,   -0.02454368648125577,   0.1559877850928394,     0.02360418859443232,
        -0.03051465817859748,   0.01394389273916019,    -0.1434779685133351,    -0.0326137520114734,
        0.1272587840850199,     0.00968806150092634,    0.04489729856072615,    0.02496761251245225,
        -0.1723551233719199,    -0.03505277577503257,   0.1396636892583818,     0.01468861799711852,
        0.00597622458952793,    0.01686435635501478,    -0.1508869780062401,    -0.0392626068463298,
        0.2221665014327329,     0.04513725581939847,    -0.2157338005707834,    -0.03852627732394119,
        0.1657363840292956,     0.02705951812948022,    -0.1076077703571204,    -0.01637507278621027,
        0.06108202920758021,    0.00876339054415577,    -0.03094805600072437,   -0.004218297546715713,
        0.01419483272929196,    0.001848310901625205,   -0.005954927442783235,  -0.000743844834357433,
        0.002303049930851211,   0.000276890872388833,   -0.0008263094529170254, -9.587788269377866e-05,
        0.000276459761481133,   3.10280277328683e-05,   -8.662530848949058e-05, -9.421991495095434e-06,
        2.551403977799462e-05,  2.693817139509806e-06,  -7.08627853168575e-06,  -7.273160333789605e-07,
        1.861116908629967e-06,  1.859288982562724e-07,  -4.633601616493963e-07, -4.510790623761216e-08,
        1.096004151863654e-07,  1.040757606442787e-08,  -2.467843591423806e-08, -2.288015736340782e-09,
        5.299290810294302e-09,  4.800959747999802e-10,  -1.086991796689273e-09, -9.63033831430537e-11,
        2.133040952766737e-10,  1.849336626863696e-11,  -4.010173216641153e-11, -3.404204559101731e-12,
        7.232799297263385e-12,  6.027665442316686e-13,  -1.252868789531569e-12, -1.035300267428826e-13,
        2.072453780944445e-13,  1.81572061755555e-14,   -3.012503176280137e-14, -4.417490972407089e-16,
        3.698522891563647e-15,  -4.204154533937635e-16, -2.740777660720187e-15, -1.348919106364917e-15,
        -1.620799477984723e-15, 4.003965342611375e-16,  -5.245330582249314e-16, 1.754761547401069e-15,
        -5.0481471966847e-16,   -4.722624632690369e-16, 1.628901569091919e-16,  -1.219903204684612e-15};

    enum { LEN_128_8 = 119 };
    static constexpr std::array<double, LEN_128_8> g_coefficientsFHEW128_8{
        0.08761193238226343,   -0.01738402917379268,  0.08935060894767202,    -0.0166768663143651,
        0.09435445639098095,   -0.01518333497826714,  0.1019473189108076,     -0.01276275748916462,
        0.1108826554741475,    -0.009252446966171845, 0.1192111685574773,     -0.004534979909938402,
        0.1242004317120066,    0.001362904847616587,  0.1224283765086535,     0.008145596233693802,
        0.1102080588183083,    0.0151235046709367,    0.08449405378412395,    0.02114203679334948,
        0.04431786059830203,   0.02464956129638117,   -0.007454366487155707,  0.02400059020367158,
        -0.06266441339261287,  0.01804912154136392,   -0.107794320182978,     0.006958365388138488,
        -0.1265848641500738,   -0.007067567033133184, -0.1060856934163389,    -0.01966175019277399,
        -0.0451246732435682,   -0.02537595733026211,  0.0386291678537217,     -0.02017855662963969,
        0.1092652333753532,    -0.004612578019767425, 0.1263344585514991,     0.01438496124843117,
        0.07022427857484087,   0.02550072245548053,   -0.03434514153678073,   0.01979242584243296,
        -0.1194659697149702,   -0.00100879476868968,  -0.1149256786653952,    -0.02192904329965062,
        -0.01184295110147335,  -0.02417858011117619,  0.1066507410103884,     -0.003076473516322021,
        0.1223432257632692,    0.02209885820126752,   0.005200840409853516,   0.02321022960558683,
        -0.1224755172356849,   -0.003930982569218244, -0.1000653894904628,    -0.02689795846413568,
        0.05865754664309823,   -0.01297065380451253,  0.1377909895596233,     0.02083617539534807,
        0.006502421233004046,  0.02248299870285591,   -0.1396600746594754,    -0.01399307934458444,
        -0.04589168496663817,  -0.02634216625743798,  0.1358978738303917,     0.0113024290766429,
        0.05563799538901171,   0.02715486116995986,   -0.1426236952996744,    -0.01461041285557423,
        -0.03302834981489241,  -0.02454368648125667,  0.155987785092838,      0.02360418859443058,
        -0.03051465817859778,  0.01394389273915945,   -0.1434779685133346,    -0.03261375201147241,
        0.1272587840850196,    0.009688061500927738,  0.04489729856072736,    0.02496761251245433,
        -0.1723551233719191,   -0.03505277577503064,  0.1396636892583768,     0.01468861799712161,
        0.005976224589562133,  0.01686435635499993,   -0.1508869780064481,    -0.03926260684622985,
        0.2221665014339838,    0.04513725581879824,   -0.2157338005780147,    -0.03852627732053739,
        0.1657363840693943,    0.02705951811098469,   -0.1076077705704247,    -0.0163750726899083,
        0.06108203029457551,   0.008763390064061401,  -0.03094806130001855,   -0.00421829525869962,
        0.01419485740772663,   0.001848300494047458,  -0.005955037043195616,  -0.000743799726455706,
        0.002303513291010024,  0.0002767049434914361, -0.0008281705698254814, -9.515056665793518e-05,
        0.0002835460400168608, 2.833421059257267e-05, -0.0001121393482639905};
};

}  // namespace lbcrypto

#endif
