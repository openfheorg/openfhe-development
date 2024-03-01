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
	CKKS to FHEW scheme switching implementation.
 */

#define PROFILE

#include "scheme/ckksrns/ckksrns-schemeswitching.h"

#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"

#include "math/dftransform.h"

#include <iterator>

// K = 16
static constexpr std::initializer_list<double> g_coefficientsFHEW16{
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
static constexpr std::initializer_list<double> g_coefficientsFHEW128_9{
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

static constexpr std::initializer_list<double> g_coefficientsFHEW128_8{
    0.08761193238226343,    -0.01738402917379268,  0.08935060894767202,   -0.0166768663143651,   0.09435445639098095,
    -0.01518333497826714,   0.1019473189108076,    -0.01276275748916462,  0.1108826554741475,    -0.009252446966171845,
    0.1192111685574773,     -0.004534979909938402, 0.1242004317120066,    0.001362904847616587,  0.1224283765086535,
    0.008145596233693802,   0.1102080588183083,    0.0151235046709367,    0.08449405378412395,   0.02114203679334948,
    0.04431786059830203,    0.02464956129638117,   -0.007454366487155707, 0.02400059020367158,   -0.06266441339261287,
    0.01804912154136392,    -0.107794320182978,    0.006958365388138488,  -0.1265848641500738,   -0.007067567033133184,
    -0.1060856934163389,    -0.01966175019277399,  -0.0451246732435682,   -0.02537595733026211,  0.0386291678537217,
    -0.02017855662963969,   0.1092652333753532,    -0.004612578019767425, 0.1263344585514991,    0.01438496124843117,
    0.07022427857484087,    0.02550072245548053,   -0.03434514153678073,  0.01979242584243296,   -0.1194659697149702,
    -0.00100879476868968,   -0.1149256786653952,   -0.02192904329965062,  -0.01184295110147335,  -0.02417858011117619,
    0.1066507410103884,     -0.003076473516322021, 0.1223432257632692,    0.02209885820126752,   0.005200840409853516,
    0.02321022960558683,    -0.1224755172356849,   -0.003930982569218244, -0.1000653894904628,   -0.02689795846413568,
    0.05865754664309823,    -0.01297065380451253,  0.1377909895596233,    0.02083617539534807,   0.006502421233004046,
    0.02248299870285591,    -0.1396600746594754,   -0.01399307934458444,  -0.04589168496663817,  -0.02634216625743798,
    0.1358978738303917,     0.0113024290766429,    0.05563799538901171,   0.02715486116995986,   -0.1426236952996744,
    -0.01461041285557423,   -0.03302834981489241,  -0.02454368648125667,  0.155987785092838,     0.02360418859443058,
    -0.03051465817859778,   0.01394389273915945,   -0.1434779685133346,   -0.03261375201147241,  0.1272587840850196,
    0.009688061500927738,   0.04489729856072736,   0.02496761251245433,   -0.1723551233719191,   -0.03505277577503064,
    0.1396636892583768,     0.01468861799712161,   0.005976224589562133,  0.01686435635499993,   -0.1508869780064481,
    -0.03926260684622985,   0.2221665014339838,    0.04513725581879824,   -0.2157338005780147,   -0.03852627732053739,
    0.1657363840693943,     0.02705951811098469,   -0.1076077705704247,   -0.0163750726899083,   0.06108203029457551,
    0.008763390064061401,   -0.03094806130001855,  -0.00421829525869962,  0.01419485740772663,   0.001848300494047458,
    -0.005955037043195616,  -0.000743799726455706, 0.002303513291010024,  0.0002767049434914361, -0.0008281705698254814,
    -9.515056665793518e-05, 0.0002835460400168608, 2.833421059257267e-05, -0.0001121393482639905};

namespace lbcrypto {

//------------------------------------------------------------------------------
// Complex Plaintext Functions, copied from ckksrns-fhe. TODO: fix this
//------------------------------------------------------------------------------

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
Plaintext SWITCHCKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                          const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                          uint32_t level, usint slots) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    usint N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    uint64_t pBits = cc.GetEncodingParams()->GetPlaintextModulus();

    double powP      = std::pow(2.0, MAX_DOUBLE_PRECISION);
    int32_t pCurrent = pBits - MAX_DOUBLE_PRECISION;

    std::vector<int128_t> temp(2 * slots);
    for (size_t i = 0; i < slots; ++i) {
        // extract the mantissa of real part and multiply it by 2^52
        int32_t n1 = 0;
        double dre = std::frexp(inverse[i].real(), &n1) * powP;
        // extract the mantissa of imaginary part and multiply it by 2^52
        int32_t n2 = 0;
        double dim = std::frexp(inverse[i].imag(), &n2) * powP;

        // Check for possible overflow
        if (is128BitOverflow(dre) || is128BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1, imagMax = -1;
            uint32_t realMaxIdx = -1, imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> expFactor = {cos((factor * idx) / invLen), sin((factor * idx) / invLen)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prodFactor = inverse[idx] * expFactor;

                double realVal = prodFactor.real();
                double imagVal = prodFactor.imag();

                if (realVal > realMax) {
                    realMax    = realVal;
                    realMaxIdx = idx;
                }
                if (imagVal > imagMax) {
                    imagMax    = imagVal;
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = ceil(log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << ceil(log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(buffer.str());
        }

        int64_t re64       = std::llround(dre);
        int32_t pRemaining = pCurrent + n1;
        __int128 re        = 0;
        if (pRemaining < 0) {
            re = re64 >> (-pRemaining);
        }
        else {
            __int128 pPowRemaining = ((__int128)1) << pRemaining;
            re                     = pPowRemaining * re64;
        }

        int64_t im64 = std::llround(dim);
        pRemaining   = pCurrent + n2;
        __int128 im  = 0;
        if (pRemaining < 0) {
            im = im64 >> (-pRemaining);
        }
        else {
            __int128 pPowRemaining = ((int64_t)1) << pRemaining;
            im                     = pPowRemaining * im64;
        }

        temp[i]         = (re < 0) ? Max128BitValue() + re : re;
        temp[i + slots] = (im < 0) ? Max128BitValue() + im : im;

        if (is128BitOverflow(temp[i]) || is128BitOverflow(temp[i + slots])) {
            OPENFHE_THROW("Overflow, try to decrease scaling factor");
        }
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams        = plainElement.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); i++) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, temp, Max128BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(nativeVec, Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, element);
    }

    usint numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (usint i = 0; i < numTowers; i++) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    DCRTPoly::Integer intPowP = NativeInteger(1) << pBits;
    std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

    auto currPowP = crtPowP;

    // We want to scale temp by 2^(pd), and the loop starts from j=2
    // because temp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; i++) {
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    }

    if (noiseScaleDeg > 1) {
        plainElement = plainElement.Times(currPowP);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(pow(p->GetScalingFactor(), noiseScaleDeg));

    return p;
}
#else
Plaintext SWITCHCKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                          const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                          uint32_t level, usint slots) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    usint N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    double powP = scFact;

    // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
    constexpr int32_t MAX_BITS_IN_WORD = 61;

    int32_t logc = 0;
    for (size_t i = 0; i < slots; ++i) {
        inverse[i] *= powP;
        if (inverse[i].real() != 0) {
            int32_t logci = static_cast<int32_t>(ceil(log2(std::abs(inverse[i].real()))));
            if (logc < logci)
                logc = logci;
        }
        if (inverse[i].imag() != 0) {
            int32_t logci = static_cast<int32_t>(ceil(log2(std::abs(inverse[i].imag()))));
            if (logc < logci)
                logc = logci;
        }
    }
    if (logc < 0) {
        OPENFHE_THROW("Too small scaling factor");
    }
    int32_t logValid    = (logc <= MAX_BITS_IN_WORD) ? logc : MAX_BITS_IN_WORD;
    int32_t logApprox   = logc - logValid;
    double approxFactor = pow(2, logApprox);

    std::vector<int64_t> temp(2 * slots);
    for (size_t i = 0; i < slots; ++i) {
        // Scale down by approxFactor in case the value exceeds a 64-bit integer.
        double dre = inverse[i].real() / approxFactor;
        double dim = inverse[i].imag() / approxFactor;

        // Check for possible overflow
        if (is64BitOverflow(dre) || is64BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1;
            double imagMax = -1;
            // TODO (dsuponit): is this correct - "uint32_t realMaxIdx = -1" and "uint32_t imagMaxIdx = -1"? if yes,
            // TODO (dsuponit): shouldn't it better be "uint32_t realMaxIdx = std::numeric_limits<uint32_t>::max()"?"
            uint32_t realMaxIdx = -1;
            uint32_t imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> expFactor = {cos((factor * idx) / invLen), sin((factor * idx) / invLen)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prodFactor = inverse[idx] * expFactor;

                double realVal = prodFactor.real();
                double imagVal = prodFactor.imag();

                if (realVal > realMax) {
                    realMax    = realVal;
                    realMaxIdx = idx;
                }
                if (imagVal > imagMax) {
                    imagMax    = imagVal;
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = ceil(log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << ceil(log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(buffer.str());
        }

        int64_t re = std::llround(dre);
        int64_t im = std::llround(dim);

        temp[i]         = (re < 0) ? Max64BitValue() + re : re;
        temp[i + slots] = (im < 0) ? Max64BitValue() + im : im;
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams        = plainElement.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); i++) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, temp, Max64BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(nativeVec, Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, element);
    }

    usint numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (usint i = 0; i < numTowers; i++) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    DCRTPoly::Integer intPowP = std::llround(powP);
    std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

    auto currPowP = crtPowP;

    // We want to scale temp by 2^(pd), and the loop starts from j=2
    // because temp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; i++) {
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    }

    if (noiseScaleDeg > 1) {
        plainElement = plainElement.Times(currPowP);
    }

    // Scale back up by the approxFactor to get the correct encoding.
    if (logApprox > 0) {
        int32_t logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
        auto intStep    = DCRTPoly::Integer(uint64_t(1) << logStep);
        std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
        logApprox -= logStep;

        while (logApprox > 0) {
            logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
            intStep = DCRTPoly::Integer(uint64_t(1) << logStep);
            std::vector<DCRTPoly::Integer> crtSF(numTowers, intStep);
            crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
            logApprox -= logStep;
        }
        plainElement = plainElement.Times(crtApprox);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(pow(p->GetScalingFactor(), noiseScaleDeg));

    return p;
}
#endif

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
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

void SWITCHCKKSRNS::EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const {
    std::vector<DCRTPoly>& cv1       = ciphertext1->GetElements();
    const std::vector<DCRTPoly>& cv2 = ciphertext2->GetElements();

    for (size_t i = 0; i < cv1.size(); ++i) {
        cv1[i] += cv2[i];
    }
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1,
                                               ConstCiphertext<DCRTPoly> ciphertext2) const {
    Ciphertext<DCRTPoly> result = ciphertext1->Clone();
    EvalAddExtInPlace(result, ciphertext2);
    return result;
}

EvalKey<DCRTPoly> SWITCHCKKSRNS::ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey) const {
    const auto cc = privateKey->GetCryptoContext();
    auto algo     = cc->GetScheme();

    const DCRTPoly& s = privateKey->GetPrivateElement();
    usint N           = s.GetRingDimension();

    PrivateKey<DCRTPoly> privateKeyPermuted = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);

    usint index = 2 * N - 1;
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, index, &vec);

    DCRTPoly sPermuted = s.AutomorphismTransform(index, vec);

    privateKeyPermuted->SetPrivateElement(sPermuted);
    privateKeyPermuted->SetKeyTag(privateKey->GetKeyTag());

    return algo->KeySwitchGen(privateKey, privateKeyPermuted);
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                                              const std::map<usint, EvalKey<DCRTPoly>>& evalKeyMap) const {
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    usint N                         = cv[0].GetRingDimension();

    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, 2 * N - 1, &vec);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    Ciphertext<DCRTPoly> result = ciphertext->Clone();

    algo->KeySwitchInPlace(result, evalKeyMap.at(2 * N - 1));

    std::vector<DCRTPoly>& rcv = result->GetElements();

    rcv[0] = rcv[0].AutomorphismTransform(2 * N - 1, vec);
    rcv[1] = rcv[1].AutomorphismTransform(2 * N - 1, vec);

    return result;
}

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
void SWITCHCKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<__int128>& vec, __int128 bigBound,
                                      NativeVector* nativeVec) const {
    if (nativeVec == nullptr)
        OPENFHE_THROW("The passed native vector is empty.");
    NativeInteger bigValueHf((unsigned __int128)bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = NativeInteger((unsigned __int128)bigBound) - modulus;
    uint32_t dslots    = vec.size();
    uint32_t gap       = ringDim / dslots;
    for (usint i = 0; i < vec.size(); i++) {
        NativeInteger n((unsigned __int128)vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        }
        else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}
#else  // NATIVEINT == 64
void SWITCHCKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
                                      NativeVector* nativeVec) const {
    if (nativeVec == nullptr)
        OPENFHE_THROW("The passed native vector is empty.");
    NativeInteger bigValueHf(bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = bigBound - modulus;
    uint32_t dslots    = vec.size();
    uint32_t gap       = ringDim / dslots;
    for (usint i = 0; i < vec.size(); i++) {
        NativeInteger n(vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        }
        else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}
#endif

//------------------------------------------------------------------------------
// Key and modulus switch and extraction methods
//------------------------------------------------------------------------------

NativeInteger RoundqQAlter(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) {
    return NativeInteger(
               (BasicInteger)std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble()))
        .Mod(q);
}

EvalKey<DCRTPoly> switchingKeyGenRLWE(
    const PrivateKey<DCRTPoly>& ckksSK,
    ConstLWEPrivateKey& LWEsk) {  // This function is without the intermediate ModSwitch
    // Extract CKKS params: method which populates the first n elements of a new RLWE key with the n elements of the target LWE key
    auto skelements = ckksSK->GetPrivateElement();
    skelements.SetFormat(Format::COEFFICIENT);
    auto lweskElements = LWEsk->GetElement();
    for (size_t i = 0; i < skelements.GetNumOfElements(); i++) {
        auto skelementsPlain = skelements.GetElementAtIndex(i);
        for (size_t j = 0; j < skelementsPlain.GetLength(); j++) {
            if (j >= lweskElements.GetLength()) {
                skelementsPlain[j] = 0;
            }
            else {
                if (lweskElements[j] == 0) {
                    skelementsPlain[j] = 0;
                }
                else if (lweskElements[j].ConvertToInt() == 1) {
                    skelementsPlain[j] = 1;
                }
                else
                    skelementsPlain[j] = skelementsPlain.GetModulus() - 1;
            }
        }
        skelements.SetElementAtIndex(i, skelementsPlain);
    }

    skelements.SetFormat(Format::EVALUATION);

    auto ccCKKS    = ckksSK->GetCryptoContext();
    auto RLWELWEsk = ccCKKS->KeyGen().secretKey;
    RLWELWEsk->SetPrivateElement(std::move(skelements));

    return ccCKKS->KeySwitchGen(ckksSK, RLWELWEsk);
}

void ModSwitch(ConstCiphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly>& ctxtKS, NativeInteger modulus_CKKS_to) {
    if (ctxt->GetElements()[0].GetRingDimension() != ctxtKS->GetElements()[0].GetRingDimension()) {
        OPENFHE_THROW("ModSwitch is implemented only for the same ring dimension.");
    }

    const std::vector<DCRTPoly>& cv = ctxt->GetElements();

    if (cv[0].GetNumOfElements() != 1 || ctxtKS->GetElements()[0].GetNumOfElements() != 1) {
        OPENFHE_THROW("ModSwitch is implemented only for ciphertext with one tower.");
    }

    const auto& paramsQlP = ctxtKS->GetElements()[0].GetParams();
    std::vector<DCRTPoly> resultElements;
    resultElements.reserve(cv.size());

    for (const auto& elem : cv) {
        auto& ref = resultElements.emplace_back(paramsQlP, Format::COEFFICIENT, true);
        ref.SetValuesModSwitch(elem, modulus_CKKS_to);
        ref.SetFormat(Format::EVALUATION);
    }

    ctxtKS->SetElements(resultElements);
}

EvalKey<DCRTPoly> switchingKeyGen(const PrivateKey<DCRTPoly>& ckksSKto, const PrivateKey<DCRTPoly>& ckksSKfrom) {
    auto skElements = ckksSKto->GetPrivateElement();
    skElements.SetFormat(Format::COEFFICIENT);
    auto skElementsFrom = ckksSKfrom->GetPrivateElement();
    skElementsFrom.SetFormat(Format::COEFFICIENT);

    for (size_t i = 0; i < skElements.GetNumOfElements(); i++) {
        auto skElementsPlain     = skElements.GetElementAtIndex(i);
        auto skElementsFromPlain = skElementsFrom.GetElementAtIndex(i);
        for (size_t j = 0; j < skElementsPlain.GetLength(); j++) {
            if (skElementsFromPlain[j] == 0) {
                skElementsPlain[j] = 0;
            }
            else if (skElementsFromPlain[j] == 1) {
                skElementsPlain[j] = 1;
            }
            else
                skElementsPlain[j] = skElementsPlain.GetModulus() - 1;
        }
        skElements.SetElementAtIndex(i, skElementsPlain);
    }

    skElements.SetFormat(Format::EVALUATION);

    auto ccCKKSto        = ckksSKto->GetCryptoContext();
    auto oldTranformedSK = ccCKKSto->KeyGen().secretKey;
    oldTranformedSK->SetPrivateElement(std::move(skElements));

    return ccCKKSto->KeySwitchGen(oldTranformedSK, ckksSKto);
}

EvalKey<DCRTPoly> switchingKeyGenRLWEcc(const PrivateKey<DCRTPoly>& ckksSKto, const PrivateKey<DCRTPoly>& ckksSKfrom,
                                        ConstLWEPrivateKey& LWEsk) {
    auto skElements = ckksSKto->GetPrivateElement();
    skElements.SetFormat(Format::COEFFICIENT);
    auto skElementsFrom = ckksSKfrom->GetPrivateElement();
    skElementsFrom.SetFormat(Format::COEFFICIENT);
    auto skElements2 = ckksSKto->GetPrivateElement();
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

    auto ccCKKSto        = ckksSKto->GetCryptoContext();
    auto oldTranformedSK = ccCKKSto->KeyGen().secretKey;
    oldTranformedSK->SetPrivateElement(std::move(skElements));
    auto RLWELWEsk = ccCKKSto->KeyGen().secretKey;
    RLWELWEsk->SetPrivateElement(std::move(skElements2));

    return ccCKKSto->KeySwitchGen(oldTranformedSK, RLWELWEsk);
}

std::vector<std::vector<NativeInteger>> ExtractLWEpacked(const Ciphertext<DCRTPoly>& ct) {
    auto originalA{(ct->GetElements()[1]).GetElementAtIndex(0)};
    originalA.SetFormat(Format::COEFFICIENT);
    auto* ptrA = &originalA.GetValues()[0];
    auto originalB{(ct->GetElements()[0]).GetElementAtIndex(0)};
    originalB.SetFormat(Format::COEFFICIENT);
    auto* ptrB = &originalB.GetValues()[0];
    size_t N = originalB.GetLength();
    std::vector<std::vector<NativeInteger>> extracted{std::vector<NativeInteger>(ptrB, ptrB + N),
                                                      std::vector<NativeInteger>(ptrA, ptrA + N)};
    return extracted;
}

std::shared_ptr<LWECiphertextImpl> ExtractLWECiphertext(const std::vector<std::vector<NativeInteger>>& aANDb,
                                                        NativeInteger modulus, uint32_t n, uint32_t index = 0) {
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

//------------------------------------------------------------------------------
// Linear transformation methods.
// Currently mostly copied from ckksrns-fhe, because there an internal bootstrapping global structure is used.
// TODO: fix this.
//------------------------------------------------------------------------------

std::vector<ConstPlaintext> SWITCHCKKSRNS::EvalLTPrecomputeSwitch(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
    const std::vector<std::vector<std::complex<double>>>& B, uint32_t dim1, uint32_t L, double scale = 1) const {
    uint32_t slots = A.size();
    uint32_t M     = cc.GetCyclotomicOrder();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(slots) : dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

    uint32_t towersToDrop = 0;
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - 1;
        for (uint32_t i = 0; i < towersToDrop; i++)
            elementParams.PopLastParam();
    }

    const auto& paramsQ = elementParams.GetParams();
    const auto& paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();

    size_t sizeQP = paramsQ.size() + paramsP.size();
    std::vector<NativeInteger> moduli;
    moduli.reserve(sizeQP);
    std::vector<NativeInteger> roots;
    roots.reserve(sizeQP);
    for (const auto& elem : paramsQ) {
        moduli.emplace_back(elem->GetModulus());
        roots.emplace_back(elem->GetRootOfUnity());
    }
    for (const auto& elem : paramsP) {
        moduli.emplace_back(elem->GetModulus());
        roots.emplace_back(elem->GetRootOfUnity());
    }

    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);

    std::vector<std::vector<std::complex<double>>> newA(slots);
    std::vector<ConstPlaintext> result(slots);

    //  A and B are concatenated horizontally
    for (uint32_t i = 0; i < A.size(); i++) {
        newA[i].reserve(A[i].size() + B[i].size());
        newA[i].insert(newA[i].end(), A[i].begin(), A[i].end());
        newA[i].insert(newA[i].end(), B[i].begin(), B[i].end());
    }

#pragma omp parallel for
    for (uint32_t j = 0; j < gStep; j++) {
        int32_t offset = -static_cast<int32_t>(bStep * j);
        for (uint32_t i = 0; i < bStep; i++) {
            if (bStep * j + i < slots) {
                // shifted diagonal is computed for rectangular map newA of dimension slots x 2*slots
                auto vec = ExtractShiftedDiagonal(newA, bStep * j + i);
                std::transform(vec.begin(), vec.end(), vec.begin(),
                               [&](const std::complex<double>& elem) { return elem * scale; });

                result[bStep * j + i] =
                    MakeAuxPlaintext(cc, elementParamsPtr, Rotate(Fill(vec, M / 4), offset), 1, towersToDrop, M / 4);
            }
        }
    }

    return result;
}

std::vector<ConstPlaintext> SWITCHCKKSRNS::EvalLTPrecomputeSwitch(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1,
    uint32_t L, double scale = 1) const {
    if (A[0].size() != A.size()) {
        OPENFHE_THROW("The matrix passed to EvalLTPrecomputeSwitch is not square");
    }

    uint32_t slots = A.size();

    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(slots) : dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    // Make sure the plaintext is created only with the necessary amount of moduli
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = 0;
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - 1;
        for (uint32_t i = 0; i < towersToDrop; i++)
            elementParams.PopLastParam();
    }

    const auto& paramsQ = elementParams.GetParams();
    const auto& paramsP = cryptoParams->GetParamsP()->GetParams();

    size_t sizeQP = paramsQ.size() + paramsP.size();
    std::vector<NativeInteger> moduli;
    moduli.reserve(sizeQP);
    std::vector<NativeInteger> roots;
    roots.reserve(sizeQP);
    for (const auto& elem : paramsQ) {
        moduli.emplace_back(elem->GetModulus());
        roots.emplace_back(elem->GetRootOfUnity());
    }
    for (const auto& elem : paramsP) {
        moduli.emplace_back(elem->GetModulus());
        roots.emplace_back(elem->GetRootOfUnity());
    }

    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);

    std::vector<ConstPlaintext> result(slots);
#pragma omp parallel for
    for (uint32_t j = 0; j < gStep; j++) {
        int32_t offset = -static_cast<int32_t>(bStep * j);
        for (uint32_t i = 0; i < bStep; i++) {
            if (bStep * j + i < slots) {
                auto diag = ExtractShiftedDiagonal(A, bStep * j + i);
                std::transform(diag.begin(), diag.end(), diag.begin(),
                               [&](const std::complex<double>& elem) { return elem * scale; });
                result[bStep * j + i] =
                    MakeAuxPlaintext(cc, elementParamsPtr, Rotate(Fill(diag, M / 4), offset), 1, towersToDrop, M / 4);
            }
        }
    }

    return result;
}

std::vector<std::vector<std::complex<double>>> EvalLTRectPrecomputeSwitch(
    const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1, double scale) {
    if (!IsPowerOfTwo(A.size()) || !IsPowerOfTwo(A[0].size())) {
        OPENFHE_THROW("The matrix passed to EvalLTPrecompute is not padded up to powers of two");
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
                    std::vector<std::complex<double>> diag;
                    diag.reserve(A.size() * num_slices);
                    for (uint32_t k = 0; k < num_slices; k++) {
                        auto tmp = ExtractShiftedDiagonal(A_slices[k], bStep * j + i);
                        diag.insert(diag.end(), std::make_move_iterator(tmp.begin()),
                                    std::make_move_iterator(tmp.end()));
                    }
                    std::transform(diag.begin(), diag.end(), diag.begin(),
                                   [&](const std::complex<double>& elem) { return elem * scale; });
                    diags[bStep * j + i] = std::move(diag);
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
                    diags[bStep * j + i] = std::move(diag);
                }
            }
        }
    }
    return diags;
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalLTWithPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                               ConstCiphertext<DCRTPoly> ctxt,
                                                               const std::vector<ConstPlaintext>& A,
                                                               uint32_t dim1) const {
    uint32_t slots = A.size();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t N = cc.GetRingDimension();

    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(ctxt);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);

    // Hoisted automorphisms
#pragma omp parallel for
    for (uint32_t j = 1; j < bStep; j++) {
        fastRotation[j - 1] = cc.EvalFastRotationExt(ctxt, j, digits, true);
    }

    Ciphertext<DCRTPoly> result;
    DCRTPoly first;

    for (uint32_t j = 0; j < gStep; j++) {
        Ciphertext<DCRTPoly> inner = EvalMultExt(cc.KeySwitchExt(ctxt, true), A[bStep * j]);

        for (uint32_t i = 1; i < bStep; i++) {
            if (bStep * j + i < slots) {
                EvalAddExtInPlace(inner, EvalMultExt(fastRotation[i - 1], A[bStep * j + i]));
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
            // Find the automorphism index that corresponds to the rotation index.
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

    return result;
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalLTRectWithPrecomputeSwitch(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
    ConstCiphertext<DCRTPoly> ct, bool wide, uint32_t dim1, uint32_t L) const {
    uint32_t n = std::min(A.size(), A[0].size());

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(n) : dim1;
    uint32_t gStep = ceil(static_cast<double>(n) / bStep);

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

    const auto& paramsQ = elementParams.GetParams();
    const auto& paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();

    size_t sizeQP = paramsQ.size() + paramsP.size();
    std::vector<NativeInteger> moduli;
    moduli.reserve(sizeQP);
    std::vector<NativeInteger> roots;
    roots.reserve(sizeQP);
    for (const auto& elem : paramsQ) {
        moduli.emplace_back(elem->GetModulus());
        roots.emplace_back(elem->GetRootOfUnity());
    }
    for (const auto& elem : paramsP) {
        moduli.emplace_back(elem->GetModulus());
        roots.emplace_back(elem->GetRootOfUnity());
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
        Ciphertext<DCRTPoly> inner = EvalMultExt(cc.KeySwitchExt(ct, true), temp);

        for (uint32_t i = 1; i < bStep; i++) {
            if (bStep * j + i < n) {
                auto tempi = cc.MakeCKKSPackedPlaintext(Rotate(Fill(A[bStep * j + i], N / 2), offset), 1, towersToDrop,
                                                        elementParamsPtr2, N / 2);
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

    // A represents the diagonals, which lose the information whether the initial matrix is tall or wide
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

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalSlotsToCoeffsSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                            ConstCiphertext<DCRTPoly> ctxt) const {
    uint32_t slots = m_numSlotsCKKS;
    uint32_t m     = 4 * slots;
    uint32_t M     = cc.GetCyclotomicOrder();
    bool isSparse  = (M != m) ? true : false;

    auto ctxtToDecode = ctxt->Clone();

    uint32_t numTowersToKeep = 2;
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() == ScalingTechnique::FLEXIBLEAUTO ||
        cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        ctxtToDecode = cc.Compress(ctxtToDecode, numTowersToKeep + 1);

        double targetSF =
            cryptoParams->GetScalingFactorReal(cryptoParams->GetElementParams()->GetParams().size() - numTowersToKeep);
        double sourceSF    = ctxtToDecode->GetScalingFactor();
        uint32_t numTowers = ctxtToDecode->GetElements()[0].GetNumOfElements();
        double modToDrop = cryptoParams->GetElementParams()->GetParams()[numTowers - 1]->GetModulus().ConvertToDouble();
        double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF);

        ctxtToDecode = cc.EvalMult(ctxtToDecode, adjustmentFactor);
        cc.GetScheme()->ModReduceInternalInPlace(ctxtToDecode, 1);
        ctxtToDecode->SetScalingFactor(targetSF);
    }
    else {
        ctxtToDecode = cc.Compress(ctxtToDecode, numTowersToKeep);
    }

    Ciphertext<DCRTPoly> ctxtDecoded;

    if (slots != m_numSlotsCKKS || m_U0Pre.size() == 0) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalCKKSToFHEWPrecompute to proceed"));
        OPENFHE_THROW(errorMsg);
    }

    if (!isSparse) {  // fully packed
        // ctxtToDecode = cc.EvalAdd(ctxtToDecode, cc.GetScheme()->MultByMonomial(ctxtToDecode, M / 4));
        ctxtDecoded = EvalLTWithPrecomputeSwitch(cc, ctxtToDecode, m_U0Pre, m_dim1CF);
    }
    else {  // sparsely packed
        ctxtDecoded = EvalLTWithPrecomputeSwitch(cc, ctxtToDecode, m_U0Pre, m_dim1CF);
        cc.EvalAddInPlace(ctxtDecoded, cc.EvalAtIndex(ctxtDecoded, slots));
    }

    return ctxtDecoded;
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalPartialHomDecryption(const CryptoContextImpl<DCRTPoly>& cc,
                                                             const std::vector<std::vector<std::complex<double>>>& A,
                                                             ConstCiphertext<DCRTPoly> ct, uint32_t dim1, double scale,
                                                             uint32_t L) const {
    // Currently, by design, the # rows (# LWE ciphertexts to switch) is a power of two.
    // Ensure that # cols (LWE lattice parameter n) is padded up to a power of two
    std::vector<std::vector<std::complex<double>>> Acopy(A);
    uint32_t cols_po2 = 1 << static_cast<uint32_t>(std::ceil(std::log2(A[0].size())));

    if (cols_po2 > A[0].size()) {
        for (size_t i = 0; i < A.size(); ++i) {
            Acopy[i].resize(cols_po2);
        }
    }

    auto Apre = EvalLTRectPrecomputeSwitch(Acopy, dim1, scale);
    auto res  = EvalLTRectWithPrecomputeSwitch(cc, Apre, ct, (Acopy.size() < A[0].size()), dim1,
                                               L);  // The result is repeated every Acopy.size() slots

    return res;
}

//------------------------------------------------------------------------------
// Scheme switching Wrapper
//------------------------------------------------------------------------------
LWEPrivateKey SWITCHCKKSRNS::EvalCKKStoFHEWSetup(const SchSwchParams& params) {
    if (params.GetSecurityLevelFHEW() != TOY && params.GetSecurityLevelFHEW() != STD128)
        OPENFHE_THROW("Only STD128 or TOY are currently supported.");

    uint32_t ringDim = params.GetRingDimension();
    if (params.GetNumSlotsCKKS() == 0 || params.GetNumSlotsCKKS() == (ringDim / 2))  // fully-packed
        m_numSlotsCKKS = ringDim / 2;
    else  // sparsely-packed
        m_numSlotsCKKS = params.GetNumSlotsCKKS();

    m_modulus_CKKS_initial = params.GetInitialCKKSModulus();
    // Modulus to switch to in order to have secure RLWE samples with ring dimension n.
    // We can select any Qswitch less than 27 bits corresponding to 128 bits of security for lattice parameter n=1024 < 1305
    // according to https://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
    // or any Qswitch for TOY security.
    // Ensure that Qswitch is larger than Q_FHEW and smaller than Q_CKKS.
    if (params.GetCtxtModSizeFHEWIntermedSwch() <= params.GetCtxtModSizeFHEWLargePrec() ||
        params.GetCtxtModSizeFHEWIntermedSwch() > GetMSB(m_modulus_CKKS_initial.ConvertToInt()) - 1) {
        OPENFHE_THROW("Qswitch should be larger than QFHEW and smaller than QCKKS.");
    }
    // Intermediate cryptocontext
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(0);
    parameters.SetFirstModSize(params.GetCtxtModSizeFHEWIntermedSwch());
    parameters.SetScalingModSize(params.GetScalingModSize());
    // This doesn't need this to be the same scaling technique as the outer cryptocontext, since we only do a key switch
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(params.GetSecurityLevelCKKS());
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(params.GetBatchSize());

    m_ccKS = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    m_ccKS->Enable(PKE);
    m_ccKS->Enable(KEYSWITCH);

    // Get the ciphertext modulus
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(m_ccKS->GetCryptoParameters());
    m_modulus_CKKS_from     = cryptoParams->GetElementParams()->GetParams()[0]->GetModulus();

    m_ccLWE = std::make_shared<BinFHEContext>();
    m_ccLWE->BinFHEContext::GenerateBinFHEContext(
        params.GetSecurityLevelFHEW(), params.GetArbitraryFunctionEvaluation(), params.GetCtxtModSizeFHEWLargePrec(), 0,
        GINX, params.GetUseDynamicModeFHEW());

    // For arbitrary functions, the LWE ciphertext needs to be at most the ring dimension in FHEW bootstrapping
    m_modulus_LWE = (!params.GetArbitraryFunctionEvaluation()) ?
                        1 << params.GetCtxtModSizeFHEWLargePrec() :
                        m_ccLWE->GetParams()->GetLWEParams()->Getq().ConvertToInt();

    // LWE private key
    LWEPrivateKey lwesk = m_ccLWE->KeyGen();

    // The baby-step and number of levels for the linear transformation associated to the homomorphic decoding
    m_dim1CF = (params.GetBStepLTrCKKStoFHEW() == 0) ? getRatioBSGSLT(params.GetNumSlotsCKKS()) :
                                                       params.GetBStepLTrCKKStoFHEW();
    m_LCF    = params.GetLevelLTrCKKStoFHEW();

    return lwesk;
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> SWITCHCKKSRNS::EvalCKKStoFHEWKeyGen(
    const KeyPair<DCRTPoly>& keyPair, ConstLWEPrivateKey& lwesk) {
    auto privateKey = keyPair.secretKey;
    auto publicKey  = keyPair.publicKey;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS to FHEW scheme switching is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS to FHEW scheme switching is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    auto ccCKKS = privateKey->GetCryptoContext();

    // Intermediate cryptocontext for CKKS to FHEW
    auto keys2 = m_ccKS->KeyGen();

    Plaintext ptxtZeroKS = m_ccKS->MakeCKKSPackedPlaintext(std::vector<double>{0.0});
    m_ctxtKS             = m_ccKS->Encrypt(keys2.publicKey, ptxtZeroKS);

    // Compute switching key between RLWE and LWE via the intermediate cryptocontext, keep it in RLWE form
    m_CKKStoFHEWswk = switchingKeyGenRLWEcc(keys2.secretKey, privateKey, lwesk);

    // Compute automorphism keys
    uint32_t M     = ccCKKS->GetCyclotomicOrder();
    uint32_t slots = m_numSlotsCKKS;

    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> indexRotationS2C = FindLTRotationIndicesSwitch(m_dim1CF, M, slots);
    indexRotationS2C.emplace_back(static_cast<int32_t>(slots));

    // Remove possible duplicates and zero
    sort(indexRotationS2C.begin(), indexRotationS2C.end());
    indexRotationS2C.erase(unique(indexRotationS2C.begin(), indexRotationS2C.end()), indexRotationS2C.end());
    indexRotationS2C.erase(std::remove(indexRotationS2C.begin(), indexRotationS2C.end(), 0), indexRotationS2C.end());

    auto algo = ccCKKS->GetScheme();

    // Compute multiplication key
    algo->EvalMultKeyGen(privateKey);

    auto evalKeys = algo->EvalAtIndexKeyGen(publicKey, privateKey, indexRotationS2C);

    // Compute conjugation key
    auto conjKey       = ConjugateKeyGen(privateKey);
    (*evalKeys)[M - 1] = conjKey;

    return evalKeys;
}

void SWITCHCKKSRNS::EvalCKKStoFHEWPrecompute(const CryptoContextImpl<DCRTPoly>& cc, double scale) {
    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = m_numSlotsCKKS;

    uint32_t m    = 4 * m_numSlotsCKKS;
    bool isSparse = (M != m) ? true : false;

    // Computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows %= m;
    }
    // Computes all powers of a primitive root of unity exp(2*M_PI/m)
    std::vector<std::complex<double>> ksiPows(m + 1);
    for (uint32_t j = 0; j < m; ++j) {
        double angle = 2.0 * M_PI * j / m;
        ksiPows[j].real(cos(angle));
        ksiPows[j].imag(sin(angle));
    }
    ksiPows[m] = ksiPows[0];

    // Matrices for decoding
    std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
    std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));

    for (size_t i = 0; i < slots; i++) {
        for (size_t j = 0; j < slots; j++) {
            U0[i][j] = ksiPows[(j * rotGroup[i]) % m];
            U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
        }
    }

    // Obtain the right scaling for encoded messages in FHEW coming from encoded messages in CKKS
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    double scFactor = cryptoParams->GetScalingFactorReal(cryptoParams->GetElementParams()->GetParams().size() - 1);
    scale *= m_modulus_CKKS_initial.ConvertToDouble() / scFactor;

    if (!isSparse) {  // fully packed
        m_U0Pre = EvalLTPrecomputeSwitch(cc, U0, m_dim1CF, m_LCF, scale);
    }
    else {  // sparsely packed
        m_U0Pre = EvalLTPrecomputeSwitch(cc, U0, U1, m_dim1CF, m_LCF, scale);
    }
}

std::vector<std::shared_ptr<LWECiphertextImpl>> SWITCHCKKSRNS::EvalCKKStoFHEW(ConstCiphertext<DCRTPoly> ciphertext,
                                                                              uint32_t numCtxts) {
    auto ccCKKS    = ciphertext->GetCryptoContext();
    uint32_t slots = m_numSlotsCKKS;

    // Step 1. Homomorphic decoding
    auto ctxtDecoded = EvalSlotsToCoeffsSwitch(*ccCKKS, ciphertext);
    ccCKKS->GetScheme()->ModReduceInternalInPlace(ctxtDecoded, 1);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS->GetCryptoParameters());

    // Step 2. Modulus switch to Q', such that CKKS is secure for (Q',n)
    auto ctxtKS = m_ctxtKS->Clone();
    ModSwitch(ctxtDecoded, ctxtKS, m_modulus_CKKS_from);

    // Step 3: Key switch from the CKKS key with the new modulus Q' to the RLWE version of the FHEW key with the new modulus Q'
    auto ccKS       = ctxtKS->GetCryptoContext();  // Use this instead of m_ccKS to work with serialization
    auto ctSwitched = ccKS->KeySwitch(ctxtKS, m_CKKStoFHEWswk);

    // Step 4. Extract LWE ciphertexts with the modulus Q'
    uint32_t n = m_ccLWE->GetParams()->GetLWEParams()->Getn();  // lattice parameter for additive LWE
    std::vector<std::shared_ptr<LWECiphertextImpl>> LWEciphertexts(numCtxts);
    auto AandB = ExtractLWEpacked(ctSwitched);

    if (numCtxts == 0 || numCtxts > slots) {
        numCtxts = slots;
    }

    uint32_t gap = ccKS->GetRingDimension() / (2 * slots);

    for (uint32_t i = 0, idx = 0; i < numCtxts; ++i, idx += gap) {
        LWEciphertexts[i] = ExtractLWECiphertext(AandB, m_modulus_CKKS_from, n, idx);
    }

    // Step 5. Modulus switch to q in FHEW

    // Compute the necessary factor to obtaine the message Q'/pLWE
    if (m_modulus_LWE != m_modulus_CKKS_from) {
#pragma omp parallel for
        for (uint32_t i = 0; i < numCtxts; i++) {
            auto original_a = LWEciphertexts[i]->GetA();
            auto original_b = LWEciphertexts[i]->GetB();
            // multiply by Q_LWE/Q' and round to Q_LWE
            NativeVector a_round(n, m_modulus_LWE);
            for (uint32_t j = 0; j < n; ++j) {
                a_round[j] = RoundqQAlter(original_a[j], m_modulus_LWE, m_modulus_CKKS_from);
            }
            NativeInteger b_round = RoundqQAlter(original_b, m_modulus_LWE, m_modulus_CKKS_from);
            LWEciphertexts[i]     = std::make_shared<LWECiphertextImpl>(std::move(a_round), std::move(b_round));
        }
    }

    return LWEciphertexts;
}

//------------------------------------------------------------------------------
// Scheme switching Wrapper
//------------------------------------------------------------------------------
void SWITCHCKKSRNS::EvalFHEWtoCKKSSetup(const CryptoContextImpl<DCRTPoly>& ccCKKS,
                                        const std::shared_ptr<BinFHEContext>& ccLWE, uint32_t numSlotsCKKS,
                                        uint32_t logQ) {
    m_ccLWE = ccLWE;

    if (m_ccLWE->GetParams()->GetLWEParams()->Getn() * 2 > ccCKKS.GetRingDimension())
        OPENFHE_THROW("The lattice parameter in LWE cannot be larger than half the RLWE ring dimension.");

    if (numSlotsCKKS == 0) {
        if (ccCKKS.GetEncodingParams()->GetBatchSize() != 0)
            m_numSlotsCKKS = ccCKKS.GetEncodingParams()->GetBatchSize();
        else
            m_numSlotsCKKS = ccCKKS.GetRingDimension() / 2;
    }
    else {
        m_numSlotsCKKS = numSlotsCKKS;
    }

    m_modulus_LWE = (logQ != 0) ? 1 << logQ : m_ccLWE->GetParams()->GetLWEParams()->Getq().ConvertToInt();
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> SWITCHCKKSRNS::EvalFHEWtoCKKSKeyGen(
    const KeyPair<DCRTPoly>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numSlots, uint32_t numCtxts, uint32_t dim1,
    uint32_t L) {
    auto privateKey = keyPair.secretKey;
    auto publicKey  = keyPair.publicKey;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());
    auto ccCKKS             = privateKey->GetCryptoContext();

    uint32_t n       = lwesk->GetElement().GetLength();
    uint32_t ringDim = ccCKKS->GetRingDimension();

    // Generate FHEW to CKKS switching key, i.e., CKKS encryption of FHEW secret key. Pad up to the closest power of two
    uint32_t n_po2     = 1 << static_cast<uint32_t>(std::ceil(std::log2(n)));
    auto skLWEElements = lwesk->GetElement();
    std::vector<std::complex<double>> skLWEDouble(n_po2);
    for (uint32_t i = 0; i < n; i++) {
        auto tmp = skLWEElements[i].ConvertToDouble();
        if (tmp == lwesk->GetModulus().ConvertToInt() - 1)
            tmp = -1;
        skLWEDouble[i] = std::complex<double>(tmp, 0);
    }

    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    Plaintext skLWEPlainswk;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, BASE_NUM_LEVELS_TO_DROP,
                                                        nullptr, ringDim / 2);
    else
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, 0, nullptr, ringDim / 2);

    m_FHEWtoCKKSswk = ccCKKS->Encrypt(publicKey, skLWEPlainswk);

    // Compute automorphism keys for CKKS for baby-step giant-step
    if (numCtxts == 0) {
        numCtxts = m_numSlotsCKKS;  // If no value is specified, default to the column size of the linear transformation
    }
    uint32_t M = ccCKKS->GetCyclotomicOrder();
    if (dim1 == 0)
        dim1 = getRatioBSGSLT(numCtxts);
    m_dim1FC = dim1;
    m_LFC    = L;

    // Compute indices for rotations for homomorphic decryption in CKKS
    std::vector<int32_t> indexRotationHomDec = FindLTRotationIndicesSwitch(dim1, M, numCtxts);

    // If the linear transform is wide instead of tall, we need extra rotations
    if (numCtxts < n_po2) {
        uint32_t logl = lbcrypto::GetMSB(n_po2 / numCtxts) - 1;  // These are powers of two, so log(l) is integer
        indexRotationHomDec.reserve(indexRotationHomDec.size() + logl);
        for (size_t j = 1; j <= logl; ++j) {
            indexRotationHomDec.emplace_back(numCtxts * (1 << (j - 1)));
        }
    }

    uint32_t slots = (numSlots == 0) ? m_numSlotsCKKS : numSlots;
    // Compute indices for rotations to bring back the final CKKS ciphertext encoding to slots
    if (ringDim > 2 * slots) {  // if the encoding is full, this does not execute
        indexRotationHomDec.reserve(indexRotationHomDec.size() + GetMSB(ringDim) - 2);
        for (uint32_t j = 1; j < ringDim / (2 * slots); j <<= 1) {
            indexRotationHomDec.emplace_back(j * slots);
        }
    }

    // Remove possible duplicates and zero
    sort(indexRotationHomDec.begin(), indexRotationHomDec.end());
    indexRotationHomDec.erase(unique(indexRotationHomDec.begin(), indexRotationHomDec.end()),
                              indexRotationHomDec.end());
    indexRotationHomDec.erase(std::remove(indexRotationHomDec.begin(), indexRotationHomDec.end(), 0),
                              indexRotationHomDec.end());

    auto algo     = ccCKKS->GetScheme();
    auto evalKeys = algo->EvalAtIndexKeyGen(publicKey, privateKey, indexRotationHomDec);

    // Compute multiplication key
    ccCKKS->EvalMultKeyGen(privateKey);

    return evalKeys;
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                                   uint32_t numCtxts, uint32_t numSlots, uint32_t p, double pmin,
                                                   double pmax, uint32_t dim1) const {
    if (!LWECiphertexts.size())
        OPENFHE_THROW("Empty input FHEW ciphertext vector");

    // This is the number of CKKS slots to use in eg_coefficientsFHEW128_9ncoding
    const uint32_t slots = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    uint32_t numLWECtxts = LWECiphertexts.size();
    uint32_t numValues   = (numCtxts == 0) ? numLWECtxts : std::min(numCtxts, numLWECtxts);
    numValues = std::min(numValues, slots);  // This is the number of LWE ciphertexts to pack into the CKKS ciphertext

    uint32_t n = LWECiphertexts[0]->GetA().GetLength();

    auto ccCKKS                 = m_FHEWtoCKKSswk->GetCryptoContext();
    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS->GetCryptoParameters());

    uint32_t m    = 4 * slots;
    uint32_t M    = ccCKKS->GetCyclotomicOrder();
    uint32_t N    = ccCKKS->GetRingDimension();
    bool isSparse = (M != m) ? true : false;

    double K = 0.0;
    std::vector<double> coefficientsFHEW;  // EvalFHEWtoCKKS assumes lattice parameter n is at most 2048.
    if (n == 32) {
        K = 16.0;
        coefficientsFHEW.assign(g_coefficientsFHEW16);
    }
    else {
        K = 128.0;  // Failure probability of 2^{-49}
        if (p <= 4) {
            // If the output messages are bits, we could use a lower degree polynomial
            coefficientsFHEW.assign(g_coefficientsFHEW128_8);
        }
        else {
            coefficientsFHEW.assign(g_coefficientsFHEW128_9);
        }
    }

    // Step 1. Form matrix A and vector b from the LWE ciphertexts, but only extract the first necessary number of them
    std::vector<std::vector<std::complex<double>>> A(numValues);

    // To have the same encoding as A*s, create b with the appropriate number of elements
    const uint32_t b_size = ((numValues % n) != 0) ? (numValues + n - (numValues % n)) : numValues;
    std::vector<std::complex<double>> b(b_size);

    // Combine the scale with the division by K to consume fewer levels, but careful since the value might be too small
    const double prescale = (1.0 / LWECiphertexts[0]->GetModulus().ConvertToDouble()) / K;

#pragma omp parallel for
    for (uint32_t i = 0; i < numValues; i++) {
        auto a = LWECiphertexts[i]->GetA();
        A[i]   = std::vector<std::complex<double>>(a.GetLength());
        for (uint32_t j = 0; j < a.GetLength(); j++) {
            A[i][j] = std::complex<double>(a[j].ConvertToDouble(), 0);
        }
        b[i] = std::complex<double>(prescale * LWECiphertexts[i]->GetB().ConvertToDouble(), 0);
    }

    // Step 2. Perform the homomorphic linear transformation of A*skLWE
    if (dim1 == 0) {
        dim1 = m_dim1FC;
    }
    Ciphertext<DCRTPoly> AdotS = EvalPartialHomDecryption(*ccCKKS, A, m_FHEWtoCKKSswk, dim1, prescale, 0);

    // Step 3. Get the ciphertext of B - A*s
    Plaintext BPlain = ccCKKS->MakeCKKSPackedPlaintext(b, AdotS->GetNoiseScaleDeg(), AdotS->GetLevel(), nullptr, N / 2);

    auto BminusAdotS = ccCKKS->EvalAdd(ccCKKS->EvalNegate(AdotS), BPlain);

    if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
        ccCKKS->ModReduceInPlace(BminusAdotS);
    }
    else {
        if (BminusAdotS->GetNoiseScaleDeg() == 2)
            ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS, BASE_NUM_LEVELS_TO_DROP);
    }

    // Step 4. Do the modulus reduction: homomorphically evaluate modular function. We do it by using sine approximation.
    // auto BminusAdotS2 = BminusAdotS;  // Instead of zeroing out slots which are not of interest as done above

    double a_cheby = -1;
    double b_cheby = 1;  // The division by K was performed before

    // double a_cheby = -K; double b_cheby = K; // Alternatively, do this separately to not lose precision when scaling with everything at once

    auto BminusAdotS3 = ccCKKS->EvalChebyshevSeries(BminusAdotS, coefficientsFHEW, a_cheby, b_cheby);

    if (cryptoParamsCKKS->GetScalingTechnique() != FIXEDMANUAL) {
        ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS3, BASE_NUM_LEVELS_TO_DROP);
    }

    enum { BT_ITER = 3 };
    for (int32_t j = 1; j < BT_ITER + 1; j++) {
        BminusAdotS3 = ccCKKS->EvalMult(BminusAdotS3, BminusAdotS3);
        ccCKKS->EvalAddInPlace(BminusAdotS3, BminusAdotS3);
        double scalar = 1.0 / std::pow((2.0 * Pi), std::pow(2.0, j - BT_ITER));
        ccCKKS->EvalSubInPlace(BminusAdotS3, scalar);
        if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
            ccCKKS->ModReduceInPlace(BminusAdotS3);
        }
        else {
            ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS3, BASE_NUM_LEVELS_TO_DROP);
        }
    }

    /* For p <= 4 and when we only encrypt bits, we don't need sin(2pi*x)/2pi to approximate x,
     * we can directly use sin(0) for 0 and sin(pi/2) for 1.
     * Here pmax is actually the plaintext modulus, not the maximum value of the messages that we
     * consider. For plaintext modulus > 4, even if we only care about encrypting bits, 2pi is not
     * the correct post-scaling factor.
     * Moreover, we have to account for the different encoding the end ciphertext should have.
     */
    double postScale = (p >= 1 && p <= 4) ? (static_cast<double>(2) * Pi) : static_cast<double>(p);
    double postBias  = 0.0;
    if (pmin != 0) {
        postScale *= (pmax - pmin) / 4.0;
        postBias = (pmax - pmin) / 4.0;
    }

    // numValues are set; the rest of values up to N/2 are made zero when creating the plaintext
    std::vector<std::complex<double>> postScaleVec(numValues, std::complex<double>(postScale, 0));
    std::vector<std::complex<double>> postBiasVec(numValues, std::complex<double>(postBias, 0));

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

    uint32_t towersToDrop = BminusAdotS3->GetLevel() + BminusAdotS3->GetNoiseScaleDeg() - 1;
    for (uint32_t i = 0; i < towersToDrop; i++)
        elementParams.PopLastParam();

    const auto& paramsQ = elementParams.GetParams();
    const auto& paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();

    size_t sizeQP = paramsQ.size() + paramsP.size();
    std::vector<NativeInteger> moduli;
    moduli.reserve(sizeQP);
    std::vector<NativeInteger> roots;
    roots.reserve(sizeQP);
    for (const auto& elem : paramsQ) {
        moduli.emplace_back(elem->GetModulus());
        roots.emplace_back(elem->GetRootOfUnity());
    }
    for (const auto& elem : paramsP) {
        moduli.emplace_back(elem->GetModulus());
        roots.emplace_back(elem->GetRootOfUnity());
    }

    auto elementParamsPtr  = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
    auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);

    // Use full packing here to clear up the junk in the slots after numValues
    auto postScalePlain = ccCKKS->MakeCKKSPackedPlaintext(postScaleVec, 1, towersToDrop, elementParamsPtr2, N / 2);
    auto BminusAdotSres = ccCKKS->EvalMult(BminusAdotS3, postScalePlain);

    // Add the plaintext for bias at the correct level and depth
    auto postBiasPlain = ccCKKS->MakeCKKSPackedPlaintext(postBiasVec, BminusAdotSres->GetNoiseScaleDeg(),
                                                         BminusAdotSres->GetLevel(), nullptr, N / 2);

    ccCKKS->EvalAddInPlace(BminusAdotSres, postBiasPlain);

    // Go back to the sparse encoding if needed
    if (isSparse) {
        for (uint32_t j = 1; j < N / (2 * slots); j <<= 1) {
            auto temp = ccCKKS->EvalAtIndex(BminusAdotSres, j * slots);
            ccCKKS->EvalAddInPlace(BminusAdotSres, temp);
        }
        BminusAdotSres->SetSlots(slots);
    }

    if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
        ccCKKS->ModReduceInPlace(BminusAdotSres);
    }

    return BminusAdotSres;
}

LWEPrivateKey SWITCHCKKSRNS::EvalSchemeSwitchingSetup(const SchSwchParams& params) {
    // CKKS to FHEW
    auto lwesk = EvalCKKStoFHEWSetup(params);

    // FHEW to CKKS
    // Save the parameters to be used in EvalSchemeSwitchingKeyGen
    m_argmin = params.GetComputeArgmin();
    m_oneHot = params.GetOneHotEncoding();
    m_alt    = params.GetUseAltArgmin();

    // Set parameters for linear transform for FHEW to CKKS
    if (!m_argmin || (m_argmin && m_alt)) {
        m_numCtxts = (params.GetNumValues() == 0) ? m_numSlotsCKKS : params.GetNumValues();
    }
    else {  // argmin not in the alternative mode
        m_numCtxts = (params.GetNumValues() == 0) ? m_numSlotsCKKS / 2 : params.GetNumValues() / 2;
    }

    // There are multiple dim1's required in argmin, but they are specified individually in EvalSchemeSwitchingKeyGen
    m_dim1FC = (params.GetBStepLTrFHEWtoCKKS() == 0) ? getRatioBSGSLT(m_numCtxts) : params.GetBStepLTrFHEWtoCKKS();
    m_LFC    = params.GetLevelLTrFHEWtoCKKS();

    return lwesk;
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> SWITCHCKKSRNS::EvalSchemeSwitchingKeyGen(
    const KeyPair<DCRTPoly>& keyPair, ConstLWEPrivateKey& lwesk) {
    auto privateKey = keyPair.secretKey;
    auto publicKey  = keyPair.publicKey;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS to FHEW scheme switching is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS to FHEW scheme switching is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    auto ccCKKS = privateKey->GetCryptoContext();

    uint32_t M       = ccCKKS->GetCyclotomicOrder();
    uint32_t slots   = m_numSlotsCKKS;
    uint32_t n       = lwesk->GetElement().GetLength();
    uint32_t ringDim = ccCKKS->GetRingDimension();

    // Intermediate cryptocontext for CKKS to FHEW
    auto keys2 = m_ccKS->KeyGen();

    Plaintext ptxtZeroKS = m_ccKS->MakeCKKSPackedPlaintext(std::vector<double>{0.0}, 1, 0, nullptr, slots);
    m_ctxtKS             = m_ccKS->Encrypt(keys2.publicKey, ptxtZeroKS);

    // Compute switching key between RLWE and LWE via the intermediate cryptocontext, keep it in RLWE form
    m_CKKStoFHEWswk = switchingKeyGenRLWEcc(keys2.secretKey, privateKey, lwesk);

    // Generate FHEW to CKKS switching key, i.e., CKKS encryption of FHEW secret key. Pad up to the closest power of two
    uint32_t n_po2     = 1 << static_cast<uint32_t>(std::ceil(std::log2(n)));
    auto skLWEElements = lwesk->GetElement();
    std::vector<std::complex<double>> skLWEDouble(n_po2);
    for (uint32_t i = 0; i < n; i++) {
        auto tmp = skLWEElements[i].ConvertToDouble();
        if (tmp == lwesk->GetModulus().ConvertToInt() - 1)
            tmp = -1;
        skLWEDouble[i] = std::complex<double>(tmp, 0);
    }

    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    Plaintext skLWEPlainswk;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, BASE_NUM_LEVELS_TO_DROP,
                                                        nullptr, ringDim / 2);
    else
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, 0, nullptr, ringDim / 2);

    m_FHEWtoCKKSswk = ccCKKS->Encrypt(publicKey, skLWEPlainswk);

    // Compute automorphism keys

    /* CKKS to FHEW */
    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> indexRotationS2C = FindLTRotationIndicesSwitch(m_dim1CF, M, slots);
    indexRotationS2C.emplace_back(static_cast<int32_t>(slots));

    // Compute indices for rotations for sparse packing
    if (ringDim > 2 * slots) {  // if the encoding is full, this does not execute
        indexRotationS2C.reserve(indexRotationS2C.size() + GetMSB(ringDim) - 2 + GetMSB(slots) - 1);
        for (uint32_t i = 1; i < ringDim / 2; i <<= 1) {
            indexRotationS2C.emplace_back(static_cast<int32_t>(i));
            if (i <= slots)
                indexRotationS2C.emplace_back(-static_cast<int32_t>(i));
        }
    }

    /* FHEW to CKKS */
    std::vector<int32_t> indexRotationHomDec;
    std::vector<int32_t> indexRotationArgmin;

    if (!m_argmin || (m_argmin && m_alt)) {
        // Compute indices for rotations for homomorphic decryption
        indexRotationHomDec = FindLTRotationIndicesSwitch(m_dim1FC, M, m_numCtxts);

        // If the linear transform is wide instead of tall, we need extra rotations
        if (m_numCtxts < n_po2) {
            uint32_t logl = lbcrypto::GetMSB(n_po2 / m_numCtxts) - 1;  // These are powers of two, so log(l) is integer
            indexRotationHomDec.reserve(indexRotationHomDec.size() + logl);
            for (size_t j = 1; j <= logl; ++j) {
                indexRotationHomDec.emplace_back(m_numCtxts * (1 << (j - 1)));
            }
        }
        if (m_argmin) {
            // Rotations for postprocessing after a level of the binary tree
            indexRotationArgmin.reserve(GetMSB(m_numCtxts) - 2);
            for (uint32_t i = 1; i < m_numCtxts; i <<= 1) {
                indexRotationArgmin.emplace_back(static_cast<int32_t>(m_numCtxts / (2 * i)));
            }
        }
    }
    else {  // argmin not in the alternative mode
        // Compute indices for rotations for all homomorphic decryptions for the levels of the tree
        indexRotationHomDec = FindLTRotationIndicesSwitchArgmin(M, m_numCtxts, n_po2);

        // Rotations for postprocessing after a level of the binary tree
        indexRotationArgmin.reserve(GetMSB(m_numCtxts) - 1 + 2 * (GetMSB(m_numCtxts) - 1));
        for (uint32_t i = 1; i < 2 * m_numCtxts; i <<= 1) {
            indexRotationArgmin.emplace_back(static_cast<int32_t>(m_numCtxts / (2 * i)));
            indexRotationArgmin.emplace_back(-static_cast<int32_t>(m_numCtxts / (2 * i)));
            if (i > 1) {
                for (uint32_t j = 2 * m_numCtxts / i; j < 2 * m_numCtxts; j <<= 1)
                    indexRotationArgmin.emplace_back(-static_cast<int32_t>(j));
            }
        }
    }

    // Compute indices for rotations to bring back the final CKKS ciphertext encoding to slots
    if (ringDim > 2 * slots) {  // if the encoding is full, this does not execute
        indexRotationHomDec.reserve(indexRotationHomDec.size() + GetMSB(ringDim) - 2);
        for (uint32_t j = 1; j < ringDim / (2 * slots); j <<= 1) {
            indexRotationHomDec.emplace_back(j * slots);
        }
    }

    // Combine the indices lists
    indexRotationS2C.reserve(indexRotationS2C.size() + indexRotationHomDec.size() + indexRotationArgmin.size());
    indexRotationS2C.insert(indexRotationS2C.end(), indexRotationHomDec.begin(), indexRotationHomDec.end());
    indexRotationS2C.insert(indexRotationS2C.end(), indexRotationArgmin.begin(), indexRotationArgmin.end());

    // Remove possible duplicates and zero
    sort(indexRotationS2C.begin(), indexRotationS2C.end());
    indexRotationS2C.erase(unique(indexRotationS2C.begin(), indexRotationS2C.end()), indexRotationS2C.end());
    indexRotationS2C.erase(std::remove(indexRotationS2C.begin(), indexRotationS2C.end(), 0), indexRotationS2C.end());

    auto algo     = ccCKKS->GetScheme();
    auto evalKeys = algo->EvalAtIndexKeyGen(publicKey, privateKey, indexRotationS2C);

    // Compute conjugation key
    auto conjKey       = ConjugateKeyGen(privateKey);
    (*evalKeys)[M - 1] = conjKey;

    // Compute multiplication key
    ccCKKS->EvalMultKeyGen(privateKey);

    // Compute automorphism keys if we don't want one hot encoding for argmin
    if (m_argmin && (m_oneHot == false)) {
        ccCKKS->EvalSumKeyGen(privateKey);
    }

    /* FHEW computations */
    // Generate the bootstrapping keys (refresh and switching keys)
    m_ccLWE->BTKeyGen(lwesk);

    return evalKeys;
}

void SWITCHCKKSRNS::EvalCompareSwitchPrecompute(const CryptoContextImpl<DCRTPoly>& ccCKKS, uint32_t pLWE,
                                                double scaleSign, bool unit) {
    double scaleCF = 1.0;
    if ((pLWE != 0) && (!unit)) {  // The messages are already scaled between 0 and 1, no need to divide by pLWE
        scaleCF = 1.0 / pLWE;
    }
    // Else perform no scaling; the implicit FHEW plaintext modulus will be m_modulus_CKKS_initial / scFactor
    scaleCF *= scaleSign;

    EvalCKKStoFHEWPrecompute(ccCKKS, scaleCF);
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalCompareSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext1,
                                                               ConstCiphertext<DCRTPoly> ciphertext2, uint32_t numCtxts,
                                                               uint32_t numSlots, uint32_t pLWE, double scaleSign,
                                                               bool unit) {
    auto ccCKKS             = ciphertext1->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS->GetCryptoParameters());

    auto cDiff = ccCKKS->EvalSub(ciphertext1, ciphertext2);

    if (unit) {
        if (pLWE == 0)
            OPENFHE_THROW("To scale to the unit circle, pLWE must be non-zero.");
        else {
            cDiff = ccCKKS->EvalMult(cDiff, 1.0 / static_cast<double>(pLWE));
            cDiff = ccCKKS->Rescale(cDiff);
        }
    }

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        double scaleCF = 1.0;
        if ((pLWE != 0) && (!unit)) {
            scaleCF = 1.0 / pLWE;
        }
        scaleCF *= scaleSign;

        EvalCKKStoFHEWPrecompute(*ccCKKS, scaleCF);
    }

    auto LWECiphertexts = EvalCKKStoFHEW(cDiff, numCtxts);

    std::vector<LWECiphertext> cSigns(LWECiphertexts.size());
#pragma omp parallel for
    for (uint32_t i = 0; i < LWECiphertexts.size(); i++) {
        cSigns[i] = m_ccLWE->EvalSign(LWECiphertexts[i], true);
    }

    return EvalFHEWtoCKKS(cSigns, numCtxts, numSlots, 4, -1.0, 1.0, 0);
}

std::vector<Ciphertext<DCRTPoly>> SWITCHCKKSRNS::EvalMinSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                                        PublicKey<DCRTPoly> publicKey,
                                                                        uint32_t numValues, uint32_t numSlots,
                                                                        uint32_t pLWE, double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        double scaleCF = 1.0 / pLWE;
        scaleCF *= scaleSign;
        EvalCKKStoFHEWPrecompute(*cc, scaleCF);
    }

    uint32_t towersToDrop = 12;  // How many levels are consumed in the EvalFHEWtoCKKS
    uint32_t slots        = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (m_oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // Compute CKKS ciphertext encoding difference of the first numValues
        auto cDiff = cc->EvalSub(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        // Transform the ciphertext from CKKS to FHEW
        auto cTemp = EvalCKKStoFHEW(cDiff, numValues / (2 * M));

        // Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        std::vector<LWECiphertext> LWESign(numValues / (2 * M));
#pragma omp parallel for
        for (uint32_t j = 0; j < numValues / (2 * M); j++) {
            LWESign[j] = m_ccLWE->EvalSign(cTemp[j], true);
        }

        // Scheme switching from FHEW to CKKS
        auto dim1    = getRatioBSGSLT(numValues / (2 * M));
        auto cSelect = EvalFHEWtoCKKS(LWESign, numValues / (2 * M), numSlots, 4, -1.0, 1.0, dim1);

        std::vector<std::complex<double>> ones(numValues / (2 * M), 1.0);
        Plaintext ptxtOnes = cc->MakeCKKSPackedPlaintext(ones, 1, 0, nullptr, slots);
        cc->EvalAddInPlace(cSelect,
                           cc->EvalAtIndex(cc->EvalSub(ptxtOnes, cSelect), -static_cast<int32_t>(numValues / (2 * M))));

        auto cExpandSelect = cSelect;
        if (M > 1) {
            for (uint32_t j = numValues / M; j < numValues; j <<= 1)
                cc->EvalAddInPlace(cExpandSelect, cc->EvalAtIndex(cExpandSelect, -static_cast<int32_t>(j)));
        }

        // Update the ciphertext of values and the indicator
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        cc->EvalAddInPlace(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }

        cInd = cc->EvalMult(cInd, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(cInd);
        }
    }
    // After computing the minimum and argument
    if (!m_oneHot) {
        cInd = cc->EvalSum(cInd, numValues);
    }

    std::vector<Ciphertext<DCRTPoly>> cRes{newCiphertext, cInd};

    return cRes;
}

std::vector<Ciphertext<DCRTPoly>> SWITCHCKKSRNS::EvalMinSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                           PublicKey<DCRTPoly> publicKey,
                                                                           uint32_t numValues, uint32_t numSlots,
                                                                           uint32_t pLWE, double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        double scaleCF = 1.0 / pLWE;
        scaleCF *= scaleSign;
        EvalCKKStoFHEWPrecompute(*cc, scaleCF);
    }

    uint32_t towersToDrop = 12;  // How many levels are consumed in the EvalFHEWtoCKKS, for binary FHEW output.
    uint32_t slots        = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (m_oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // Compute CKKS ciphertext encoding difference of the first numValues
        auto cDiff = cc->EvalSub(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        // Transform the ciphertext from CKKS to FHEW
        auto cTemp = EvalCKKStoFHEW(cDiff, numValues / (2 * M));

        // Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        std::vector<LWECiphertext> LWESign(numValues);
#pragma omp parallel for
        for (uint32_t j = 0; j < numValues / (2 * M); j++) {
            LWECiphertext tempSign    = m_ccLWE->EvalSign(cTemp[j], true);
            LWECiphertext negTempSign = std::make_shared<LWECiphertextImpl>(*tempSign);
            m_ccLWE->GetLWEScheme()->EvalAddConstEq(negTempSign, negTempSign->GetModulus() >> 1);  // "negated" tempSign
            for (uint32_t i = 0; i < 2 * M; i += 2) {
                LWESign[i * numValues / (2 * M) + j]       = tempSign;
                LWESign[(i + 1) * numValues / (2 * M) + j] = negTempSign;
            }
        }

        // Scheme switching from FHEW to CKKS
        auto dim1          = getRatioBSGSLT(numValues);
        auto cExpandSelect = EvalFHEWtoCKKS(LWESign, numValues, numSlots, 4, -1.0, 1.0, dim1);

        // Update the ciphertext of values and the indicator
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        cc->EvalAddInPlace(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }

        cInd = cc->EvalMult(cInd, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(cInd);
        }
    }
    // After computing the minimum and argument
    if (!m_oneHot) {
        cInd = cc->EvalSum(cInd, numValues);
    }

    std::vector<Ciphertext<DCRTPoly>> cRes{newCiphertext, cInd};

    return cRes;
}

std::vector<Ciphertext<DCRTPoly>> SWITCHCKKSRNS::EvalMaxSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                                        PublicKey<DCRTPoly> publicKey,
                                                                        uint32_t numValues, uint32_t numSlots,
                                                                        uint32_t pLWE, double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        double scaleCF = 1.0 / pLWE;
        scaleCF *= scaleSign;
        EvalCKKStoFHEWPrecompute(*cc, scaleCF);
    }

    uint32_t towersToDrop = 12;  // How many levels are consumed in the EvalFHEWtoCKKS, for binary FHEW output.
    uint32_t slots        = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (m_oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // Compute CKKS ciphertext encoding difference of the first numValues
        auto cDiff = cc->EvalSub(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        // Transform the ciphertext from CKKS to FHEW
        auto cTemp = EvalCKKStoFHEW(cDiff, numValues / (2 * M));

        // Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        std::vector<LWECiphertext> LWESign(numValues / (2 * M));
#pragma omp parallel for
        for (uint32_t j = 0; j < numValues / (2 * M); j++) {
            LWESign[j] = m_ccLWE->EvalSign(cTemp[j], true);
        }

        // Scheme switching from FHEW to CKKS
        auto dim1    = getRatioBSGSLT(numValues / (2 * M));
        auto cSelect = EvalFHEWtoCKKS(LWESign, numValues / (2 * M), numSlots, 4, -1.0, 1.0, dim1);

        std::vector<std::complex<double>> ones(numValues / (2 * M), 1.0);
        Plaintext ptxtOnes = cc->MakeCKKSPackedPlaintext(ones, 1, 0, nullptr, slots);
        cSelect            = cc->EvalAdd(cc->EvalSub(ptxtOnes, cSelect),
                                         cc->EvalAtIndex(cSelect, -static_cast<int32_t>(numValues / (2 * M))));

        auto cExpandSelect = cSelect;
        if (M > 1) {
            for (uint32_t j = numValues / M; j < numValues; j <<= 1)
                cc->EvalAddInPlace(cExpandSelect, cc->EvalAtIndex(cExpandSelect, -static_cast<int32_t>(j)));
        }

        // Update the ciphertext of values and the indicator
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        cc->EvalAddInPlace(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }

        cInd = cc->EvalMult(cInd, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(cInd);
        }
    }
    // After computing the minimum and argument
    if (!m_oneHot) {
        cInd = cc->EvalSum(cInd, numValues);
    }

    std::vector<Ciphertext<DCRTPoly>> cRes{newCiphertext, cInd};

    return cRes;
}

std::vector<Ciphertext<DCRTPoly>> SWITCHCKKSRNS::EvalMaxSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                           PublicKey<DCRTPoly> publicKey,
                                                                           uint32_t numValues, uint32_t numSlots,
                                                                           uint32_t pLWE, double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        double scaleCF = 1.0 / pLWE;
        scaleCF *= scaleSign;
        EvalCKKStoFHEWPrecompute(*cc, scaleCF);
    }

    uint32_t towersToDrop = 12;  // How many levels are consumed in the EvalFHEWtoCKKS, for binary FHEW output
    uint32_t slots        = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (m_oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // Compute CKKS ciphertext encoding difference of the first numValues
        auto cDiff = cc->EvalSub(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        // Transform the ciphertext from CKKS to FHEW
        auto cTemp = EvalCKKStoFHEW(cDiff, numValues / (2 * M));

        // Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        std::vector<LWECiphertext> LWESign(numValues);
#pragma omp parallel for
        for (uint32_t j = 0; j < numValues / (2 * M); j++) {
            LWECiphertext tempSign    = m_ccLWE->EvalSign(cTemp[j], true);
            LWECiphertext negTempSign = std::make_shared<LWECiphertextImpl>(*tempSign);
            m_ccLWE->GetLWEScheme()->EvalAddConstEq(negTempSign, negTempSign->GetModulus() >> 1);  // "negated" tempSign
            for (uint32_t i = 0; i < 2 * M; i += 2) {
                LWESign[i * numValues / (2 * M) + j]       = negTempSign;
                LWESign[(i + 1) * numValues / (2 * M) + j] = tempSign;
            }
        }

        // Scheme switching from FHEW to CKKS
        auto dim1          = getRatioBSGSLT(numValues);
        auto cExpandSelect = EvalFHEWtoCKKS(LWESign, numValues, numSlots, 4, -1.0, 1.0, dim1);

        // Update the ciphertext of values and the indicator
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        cc->EvalAddInPlace(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }

        cInd = cc->EvalMult(cInd, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(cInd);
        }
    }
    // After computing the minimum and argument
    if (!m_oneHot) {
        cInd = cc->EvalSum(cInd, numValues);
    }

    std::vector<Ciphertext<DCRTPoly>> cRes{newCiphertext, cInd};

    return cRes;
}

}  // namespace lbcrypto
