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
#include "encoding/plaintext-fwd.h"
#include "schemerns/rns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "utils/caller_info.h"

#include "../../binfhe/include/binfhecontext.h"
#include "../../binfhe/include/lwe-pke.h"
#include "../../binfhe/include/lwe-ciphertext.h"

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

class FHECKKSRNSSS : public FHERNS {
    using ParmType = typename DCRTPoly::Params;

public:
    virtual ~FHECKKSRNSSS() {}

    // Precomputed matrix for CKKS to FHEW switching
    std::vector<ConstPlaintext> m_U0Pre;

    //------------------------------------------------------------------------------
    // Scheme Switching Wrappers
    //------------------------------------------------------------------------------

    std::pair<BinFHEContext, LWEPrivateKey> EvalCKKStoFHEWSetup(const CryptoContextImpl<DCRTPoly>& cc, SecurityLevel sl,
                                                                bool arbFunc, uint32_t logQ, bool dynamic,
                                                                uint32_t numSlotsCKKS) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalCKKStoFHEWKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                             ConstLWEPrivateKey& lwesk,
                                                                             uint32_t dim1) override;

    void EvalCKKStoFHEWPrecompute(const CryptoContextImpl<DCRTPoly>& cc, double scale, uint32_t dim1,
                                  uint32_t L) override;

    std::vector<ConstPlaintext> EvalLTPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
                                                   const std::vector<std::vector<std::complex<double>>>& A,
                                                   uint32_t dim1, double scale, uint32_t L) const;

    std::vector<ConstPlaintext> EvalLTPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
                                                   const std::vector<std::vector<std::complex<double>>>& A,
                                                   const std::vector<std::vector<std::complex<double>>>& B,
                                                   uint32_t dim1, double scale, uint32_t L) const;

    Ciphertext<DCRTPoly> EvalLTRectWithPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
                                                    const std::vector<std::vector<std::complex<double>>>& A,
                                                    ConstCiphertext<DCRTPoly> ct, uint32_t dim1, uint32_t L) const;

    Ciphertext<DCRTPoly> EvalSlotsToCoeffsSS(const CryptoContextImpl<DCRTPoly>& cc,
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
                                                                             uint32_t numSlots) override;

    Ciphertext<DCRTPoly> EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                        double prescale, uint32_t numCtxts, uint32_t numSlots, uint32_t p, double pmin,
                                        double pmax) const override;

    std::pair<BinFHEContext, LWEPrivateKey> EvalSchemeSwitchingSetup(const CryptoContextImpl<DCRTPoly>& cc,
                                                                     SecurityLevel sl, bool arbFunc, uint32_t logQ,
                                                                     bool dynamic, uint32_t numSlotsCKKS) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalSchemeSwitchingKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                                  ConstLWEPrivateKey& lwesk,
                                                                                  uint32_t dim1CF, uint32_t dim1FC,
                                                                                  uint32_t numValues, bool oneHot,
                                                                                  bool alt) override;

    void EvalCompareSSPrecompute(const CryptoContextImpl<DCRTPoly>& ccCKKS, uint32_t pLWE, uint32_t init_level,
                                 double scaleSign, uint32_t dim1, uint32_t L) override;

    Ciphertext<DCRTPoly> EvalCompareSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext1,
                                                    ConstCiphertext<DCRTPoly> ciphertext2, uint32_t numCtxts,
                                                    uint32_t numSlots, uint32_t pLWE, double scaleSign) override;

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
        return "FHECKKSRNSSS";
    }

private:
    // the LWE cryptocontext to generate when scheme switching from CKKS
    BinFHEContext m_ccLWE;
    // the associated ciphertext modulus Q for the LWE cryptocontext
    uint64_t m_modulus_LWE;
    // the target ciphertext modulus Q for the CKKS cryptocontext (from FHEW to CKKS)
    uint64_t m_modulus_CKKS_to;
    // the ciphertext modulus Q' for the CKKS cryptocontext that is secure for the LWE ring dimension
    uint64_t m_modulus_CKKS_from;
    // switching key from CKKS to FHEW ("outer", i.e., not for an inner functionality)
    EvalKey<DCRTPoly> m_CKKStoFHEWswk;
    // switching key from FHEW to CKKS ("outer", i.e., not for an inner functionality)
    Ciphertext<DCRTPoly> m_FHEWtoCKKSswk;
    // number of slots encoded in the CKKS ciphertext
    uint32_t m_numSlotsCKKS;
    // Baby-step dimensions for linear transform for CKKS->FHEW, FHEW->CKKS
    uint32_t m_dim1CF;
    uint32_t m_dim1FC;

    // Andreea: temporary for debugging, remove later
    PrivateKey<DCRTPoly> m_CKKSsk;
    PrivateKey<DCRTPoly> m_RLWELWEsk;
    std::vector<std::complex<double>> m_FHEWtoCKKSswkDouble;

#define Pi 3.14159265358979323846

    // K = 16
    const std::vector<double> g_coefficientsFHEW16{
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

    // K = 64;
    const std::vector<double> g_coefficientsFHEW64{
        0.1237452059598565,     -0.02449355701825017,   0.1286446884866481,     -0.02245724754410056,
        0.1421211580570139,     -0.01795799205157859,   0.1600819769383666,     -0.01035620646412178,
        0.1745829482770354,     0.0006976478623535425,  0.1733269844502962,     0.01441556286972672,
        0.1416077538887186,     0.02786456947460996,    0.06914846898272799,    0.03552639981663498,
        -0.03744750746838193,   0.03078436405048089,    -0.1421308212097455,    0.01053633771666829,
        -0.1821752070665586,    -0.01830007243510788,   -0.1053028039922058,    -0.0366352256342817,
        0.06324576156360075,    -0.02462186278314502,   0.1863744545431488,     0.01372957586444736,
        0.1122230742864549,     0.03859879331185206,    -0.1116851675473931,    0.01208092061837111,
        -0.1865986659187467,    -0.03517763449108481,   0.04561026878269605,    -0.02290427443194653,
        0.2059654278949174,     0.03577959684066309,    -0.0588452669346322,    0.01808188740879842,
        -0.199906190117321,     -0.04520418738617502,   0.1708264955814432,     0.01157987362006509,
        0.0712239061277013,     0.03638265532740949,    -0.2562715358979272,    -0.05691701946510863,
        0.2788326664240982,     0.04901001544406153,    -0.2015410903244797,    -0.0307445466148373,
        0.1121026491244629,     0.01539158165089832,    -0.05107379850255724,   -0.006436413323990595,
        0.01973789302077544,    0.002311626356947763,   -0.006618795693152914,  -0.0007266613449669904,
        0.001957157935572253,   0.0002027309121464716,  -0.0005165485260485022, -5.073802438370248e-05,
        0.0001228512154654347,  1.148933300597038e-05,  -2.653362511390128e-05, -2.370642119797197e-06,
        5.237979787390324e-06,  4.483551635618111e-07,  -9.502954347082743e-07, -7.812087401923437e-08,
        1.591955981154347e-07,  1.259545821972524e-08,  -2.472702641324664e-08, -1.886442237824422e-09,
        3.574068055636053e-09,  2.633595752023516e-10,  -4.822971353740751e-10, -3.437660231804929e-11,
        6.09389506840908e-11,   4.20804351815884e-12,   -7.227927296230807e-12, -4.843743109054654e-13,
        8.0586290935993e-13,    5.203652951096909e-14,  -8.506284189265744e-14, -6.696150225641728e-15,
        7.90234168120906e-15,   3.612929164881866e-16,  -9.775607818521505e-16, -3.754059210385063e-16,
        4.986594941112991e-16,  -8.147907960384623e-16, 1.565602638115475e-15,  8.025595254281852e-16,
        1.329445028640124e-15,  -7.244675669164158e-16, -3.608224830031759e-16, 2.739804616702081e-15,
        -5.146542326016615e-16, 3.048408982869074e-16,  -1.837513192451636e-15, -1.543021830834963e-15,
        7.762152502675883e-17,  4.15863200749423e-16,   -7.228210497188784e-16, 1.806464582440933e-16,
        -4.210379690845403e-17, -5.043046959314271e-16, -1.592887780246093e-15, 1.125276896145498e-15,
        -3.09192408023256e-16,  9.922618282587337e-16,  3.424755770877601e-16,  2.091841295285524e-15,
        1.155913876856817e-15,  -1.628523116735651e-15};

    // K = 128
    const std::vector<double> g_coefficientsFHEW128{
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
};

}  // namespace lbcrypto

#endif
