//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  Benchmarks for CKKS FE functional bootstrapping (EvalFEFuncBootstrap), which bootstraps a ciphertext with slot
  values in [-1/2, 1/2) and evaluates a continuous function, given by its Fourier extension, in the same step
 */

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "benchmark/benchmark.h"
#include "config_core.h"
#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"

using namespace lbcrypto;

namespace {

// The Fourier extensions below were generated with https://github.com/openfheorg/fefbt-python. The degree of each one
// is the lowest at which the precision of FE functional bootstrapping reaches the noise floor set by the scaling
// factor, or the highest one that costs no more depth: degrees 6-13, 14-27 and 28-59 use 3, 4 and 5 levels.
// Fourier extension of x in [-0.5, 0.5] of degree 5: 11.8 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_identity_1_double_5{
        std::complex<double>(-2.285817111521e-15, 0.000000000000e+00),
        std::complex<double>(4.156226072539e-15, -2.893149352722e-01),
        std::complex<double>(-3.077519273434e-15, 1.077756144464e-01),
        std::complex<double>(1.790623291292e-15, -4.268125549152e-02),
        std::complex<double>(-7.277774822611e-16, 1.416141576562e-02),
        std::complex<double>(2.341474105248e-16, -3.029673466666e-03)};

// Fourier extension of x in [-0.5, 0.5] of degree 27: 37.8 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_identity_1_double_27{
        std::complex<double>(-3.537721645838e-06, 0.000000000000e+00),
        std::complex<double>(6.854298493758e-06, -3.083907189556e-01),
        std::complex<double>(-6.229556107760e-06, 1.401833275333e-01),
        std::complex<double>(5.306709853693e-06, -7.965460979087e-02),
        std::complex<double>(-4.230129984770e-06, 4.766244973371e-02),
        std::complex<double>(3.147572516912e-06, -2.840873617926e-02),
        std::complex<double>(-2.178674512163e-06, 1.641767256310e-02),
        std::complex<double>(1.396183815057e-06, -9.042888434183e-03),
        std::complex<double>(-8.229848292313e-07, 4.682576169158e-03),
        std::complex<double>(4.421516384416e-07, -2.249108160821e-03),
        std::complex<double>(-2.136597766680e-07, 9.864894514206e-04),
        std::complex<double>(9.098651766737e-08, -3.868782000063e-04),
        std::complex<double>(-3.297985195008e-08, 1.312743647062e-04),
        std::complex<double>(9.485538216003e-09, -3.623432339830e-05),
        std::complex<double>(-1.769223640855e-09, 6.934187318083e-06),
        std::complex<double>(-1.660846460361e-11, -2.763527359587e-07),
        std::complex<double>(1.465381652827e-10, -3.786654014393e-07),
        std::complex<double>(-4.217563960834e-11, 1.298815321960e-07),
        std::complex<double>(-4.053070379317e-12, 2.968790126928e-10),
        std::complex<double>(6.973375869801e-12, -1.381453275211e-08),
        std::complex<double>(-2.025003428829e-12, 3.222138233311e-09),
        std::complex<double>(-1.158877681318e-12, 1.120385132759e-09),
        std::complex<double>(1.967082746690e-12, -7.070271382248e-10),
        std::complex<double>(-2.099275614453e-14, -3.822331340331e-11),
        std::complex<double>(-2.065063154115e-12, 1.297642679074e-10),
        std::complex<double>(7.715989305823e-13, -1.755544234289e-11),
        std::complex<double>(2.046010930123e-12, -2.229859873137e-11),
        std::complex<double>(-1.504484904713e-12, 8.942316071653e-12)};

// Fourier extension of std::exp(x) in [-2, 2] of degree 5: 10.0 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_exp_2_double_5{
        std::complex<double>(2.853949280566e+00, 0.000000000000e+00),
        std::complex<double>(-3.154667652114e+00, -2.588873605845e+00),
        std::complex<double>(1.036506108677e+00, 1.800828815528e+00),
        std::complex<double>(-2.904997645398e-01, -8.511891779108e-01),
        std::complex<double>(6.046105584088e-02, 3.040823468835e-01),
        std::complex<double>(-3.764341711148e-03, -6.821369353810e-02)};

// Fourier extension of std::exp(x) in [-2, 2] of degree 27: 36.3 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_exp_2_double_27{
        std::complex<double>(3.232008085468e+00, 0.000000000000e+00),
        std::complex<double>(-3.866708233958e+00, -3.050524112978e+00),
        std::complex<double>(1.630734885139e+00, 2.586430315112e+00),
        std::complex<double>(-7.291551894745e-01, -1.750090625375e+00),
        std::complex<double>(3.462143762699e-01, 1.122158777056e+00),
        std::complex<double>(-1.678574605920e-01, -6.917924533307e-01),
        std::complex<double>(8.057822448295e-02, 4.073961940249e-01),
        std::complex<double>(-3.742169113675e-02, -2.270060422157e-01),
        std::complex<double>(1.649042616105e-02, 1.184478864751e-01),
        std::complex<double>(-6.765362592232e-03, -5.719560073872e-02),
        std::complex<double>(2.527677101858e-03, 2.518466968216e-02),
        std::complex<double>(-8.342239495864e-04, -9.906461106018e-03),
        std::complex<double>(2.310549237427e-04, 3.369662133075e-03),
        std::complex<double>(-4.791248763232e-05, -9.321593507883e-04),
        std::complex<double>(4.600888196547e-06, 1.788640507478e-04),
        std::complex<double>(1.313229938182e-06, -7.254983049309e-06),
        std::complex<double>(-6.614418914981e-07, -9.738282478480e-06),
        std::complex<double>(6.211432189429e-08, 3.353421374228e-06),
        std::complex<double>(4.663615250054e-08, 4.465941311205e-09),
        std::complex<double>(-1.695608688179e-08, -3.560693575778e-07),
        std::complex<double>(-2.040586022638e-09, 8.341352293606e-08),
        std::complex<double>(2.662958360766e-09, 2.883731016305e-08),
        std::complex<double>(-1.852494616039e-10, -1.825973786063e-08),
        std::complex<double>(-3.968207984428e-10, -1.004026709862e-09),
        std::complex<double>(8.714936194573e-11, 3.355891294021e-09),
        std::complex<double>(6.298038479624e-11, -4.165606544600e-10),
        std::complex<double>(-1.456071678160e-11, -5.990700296943e-10),
        std::complex<double>(-1.493132700814e-11, 1.970154430223e-10)};

// Fourier extension of std::tanh(x) in [-4, 4] of degree 5: 7.1 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_tanh_4_double_5{
        std::complex<double>(2.544045682050e-17, 0.000000000000e+00),
        std::complex<double>(-3.637717904505e-18, -5.015318450598e-01),
        std::complex<double>(-4.892281812275e-17, -1.250484159163e-01),
        std::complex<double>(1.494892090882e-17, -4.074371919482e-02),
        std::complex<double>(1.002200798270e-16, -3.351107411171e-02),
        std::complex<double>(-1.294260455076e-17, -2.613091453250e-02)};

// Fourier extension of std::tanh(x) in [-4, 4] of degree 8: 9.7 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_tanh_4_double_8{
        std::complex<double>(-5.587972526942e-18, 0.000000000000e+00),
        std::complex<double>(3.762483789929e-17, -5.452856402023e-01),
        std::complex<double>(-4.383532142871e-17, -7.665719172656e-02),
        std::complex<double>(-1.849732227087e-17, -6.022336971242e-02),
        std::complex<double>(1.386639821861e-16, -3.955997713543e-02),
        std::complex<double>(-9.542140291583e-18, -1.841721426681e-02),
        std::complex<double>(-1.796181208171e-17, -7.926764183622e-03),
        std::complex<double>(1.578700925042e-16, -5.121297463198e-03),
        std::complex<double>(4.473637681723e-17, -3.572811563456e-03)};

// Fourier extension of std::tanh(x) in [-4, 4] of degree 40: 38.3 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_tanh_4_double_40{
        std::complex<double>(-1.137744746365e-12, 0.000000000000e+00),
        std::complex<double>(2.158733147036e-12, -6.006359696107e-01),
        std::complex<double>(-1.840465896697e-12, 3.224650847478e-03),
        std::complex<double>(1.403606916084e-12, -1.281117527789e-01),
        std::complex<double>(-9.492995474663e-13, -8.817787937992e-04),
        std::complex<double>(5.615606447432e-13, -3.332750337699e-02),
        std::complex<double>(-2.836048317132e-13, -3.329264551001e-03),
        std::complex<double>(1.172620954474e-13, -7.456714071858e-03),
        std::complex<double>(-3.559083979927e-14, -2.242925539078e-03),
        std::complex<double>(5.326023988930e-15, -1.601099853365e-03),
        std::complex<double>(1.784249992195e-15, -8.392330990502e-04),
        std::complex<double>(-1.175956885786e-15, -4.330706371793e-04),
        std::complex<double>(1.246600019259e-16, -2.400589345762e-04),
        std::complex<double>(3.547461069250e-16, -1.305553653342e-04),
        std::complex<double>(-6.120159328025e-16, -6.942811895560e-05),
        std::complex<double>(2.430503515255e-15, -3.746089951304e-05),
        std::complex<double>(-7.799375180808e-15, -2.040209459432e-05),
        std::complex<double>(1.971171857018e-14, -1.098785308928e-05),
        std::complex<double>(-4.544132076398e-14, -5.889805871819e-06),
        std::complex<double>(9.969359602277e-14, -3.187912533182e-06),
        std::complex<double>(-1.991009366054e-13, -1.730042986658e-06),
        std::complex<double>(3.657076478200e-13, -9.300154970209e-07),
        std::complex<double>(-6.148297743552e-13, -4.991961209296e-07),
        std::complex<double>(9.481800688392e-13, -2.707505659342e-07),
        std::complex<double>(-1.342917312983e-12, -1.469256672888e-07),
        std::complex<double>(1.742596623095e-12, -7.874619265512e-08),
        std::complex<double>(-2.069718923349e-12, -4.222297342142e-08),
        std::complex<double>(2.240871187258e-12, -2.301093100527e-08),
        std::complex<double>(-2.200113025814e-12, -1.251481807595e-08),
        std::complex<double>(1.938297480178e-12, -6.654590078200e-09),
        std::complex<double>(-1.509268754414e-12, -3.554114742094e-09),
        std::complex<double>(1.007916143277e-12, -1.963387026745e-09),
        std::complex<double>(-5.446674221618e-13, -1.074371888329e-09),
        std::complex<double>(1.995742146008e-13, -5.579869838748e-10),
        std::complex<double>(-4.958104860667e-15, -2.948716305851e-10),
        std::complex<double>(-6.456547069450e-14, -1.699909201575e-10),
        std::complex<double>(5.307950651158e-14, -9.446368513799e-11),
        std::complex<double>(-2.050113087801e-14, -4.535986365163e-11),
        std::complex<double>(-5.443987948663e-15, -2.324333260584e-11),
        std::complex<double>(1.021676143561e-14, -1.554268302603e-11),
        std::complex<double>(-6.064304362654e-15, -8.961947503550e-12)};

// Fourier extension of 1 / (1 + std::exp(-x)) in [-8, 8] of degree 5: 7.1 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_sigmoid_8_double_5{
        std::complex<double>(2.500000000000e-01, 0.000000000000e+00),
        std::complex<double>(-2.775557561563e-17, -2.507659225299e-01),
        std::complex<double>(-4.857225732735e-17, -6.252420795814e-02),
        std::complex<double>(-6.938893903907e-18, -2.037185959741e-02),
        std::complex<double>(3.268869550044e-17, -1.675553705586e-02),
        std::complex<double>(-4.163336342344e-17, -1.306545726625e-02)};

// Fourier extension of 1 / (1 + std::exp(-x)) in [-8, 8] of degree 8: 9.7 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_sigmoid_8_double_8{
        std::complex<double>(2.500000000000e-01, 0.000000000000e+00),
        std::complex<double>(1.665334536938e-16, -2.726428201011e-01),
        std::complex<double>(-6.245004513517e-17, -3.832859586328e-02),
        std::complex<double>(-6.245004513517e-17, -3.011168485621e-02),
        std::complex<double>(4.483175983228e-17, -1.977998856771e-02),
        std::complex<double>(0.000000000000e+00, -9.208607133403e-03),
        std::complex<double>(-4.423544863741e-17, -3.963382091811e-03),
        std::complex<double>(0.000000000000e+00, -2.560648731599e-03),
        std::complex<double>(7.779150587583e-18, -1.786405781728e-03)};

// Fourier extension of 1 / (1 + std::exp(-x)) in [-8, 8] of degree 40: 38.3 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_sigmoid_8_double_40{
        std::complex<double>(2.499999999821e-01, 0.000000000000e+00),
        std::complex<double>(3.404651560679e-11, -3.003179848016e-01),
        std::complex<double>(-2.946162411255e-11, 1.612325417225e-03),
        std::complex<double>(2.304446911072e-11, -6.405587638177e-02),
        std::complex<double>(-1.616905247930e-11, -4.408894041664e-04),
        std::complex<double>(1.004840655128e-11, -1.666375168275e-02),
        std::complex<double>(-5.415817100340e-12, -1.664632279329e-03),
        std::complex<double>(2.438431401242e-12, -3.728357033808e-03),
        std::complex<double>(-8.478299713763e-13, -1.121462770474e-03),
        std::complex<double>(1.786973347073e-13, -8.005499263908e-04),
        std::complex<double>(1.168336261070e-14, -4.196165495624e-04),
        std::complex<double>(-2.426357725849e-14, -2.165353186087e-04),
        std::complex<double>(5.222296933002e-15, -1.200294672768e-04),
        std::complex<double>(2.725250580760e-15, -6.527768266717e-05),
        std::complex<double>(-1.687403027466e-15, -3.471405947992e-05),
        std::complex<double>(-2.480654570647e-16, -1.873044975592e-05),
        std::complex<double>(4.060743711773e-16, -1.020104729669e-05),
        std::complex<double>(-1.405126015541e-16, -5.493926545036e-06),
        std::complex<double>(-1.034426281340e-16, -2.944902935970e-06),
        std::complex<double>(2.081668171172e-17, -1.593956266385e-06),
        std::complex<double>(8.733926125729e-17, -8.650214933410e-07),
        std::complex<double>(-4.336808689942e-17, -4.650077486747e-07),
        std::complex<double>(-4.894452830767e-17, -2.495980604535e-07),
        std::complex<double>(4.683753385137e-17, -1.353752829083e-07),
        std::complex<double>(-9.116160331089e-17, -7.346283367477e-08),
        std::complex<double>(3.122502256758e-17, -3.937309645765e-08),
        std::complex<double>(1.593415616364e-16, -2.111148667168e-08),
        std::complex<double>(2.688821387764e-17, -1.150546540312e-08),
        std::complex<double>(-2.688821387764e-17, -6.257409040575e-09),
        std::complex<double>(4.770489558936e-17, -3.327295039070e-09),
        std::complex<double>(-3.438260257627e-17, -1.777057194972e-09),
        std::complex<double>(-3.642919299551e-17, -9.816935402605e-10),
        std::complex<double>(4.064402894105e-17, -5.371860074821e-10),
        std::complex<double>(1.708702623837e-16, -2.789936882864e-10),
        std::complex<double>(-1.585103576174e-16, -1.474356661063e-10),
        std::complex<double>(6.071532165919e-18, -8.499555794155e-11),
        std::complex<double>(9.700348366898e-17, -4.723200129619e-11),
        std::complex<double>(8.760353553683e-17, -2.267993634749e-11),
        std::complex<double>(-8.650239270540e-17, -1.162159431189e-11),
        std::complex<double>(8.760353553683e-17, -7.771379686250e-12),
        std::complex<double>(-4.182987506721e-17, -4.480889617686e-12)};

// Fourier extension of the GELU (tanh approximation) in [-8, 8] of degree 5: 7.1 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_gelu_8_double_5{
        std::complex<double>(1.892200678910e+00, 0.000000000000e+00),
        std::complex<double>(-1.453138225984e+00, -2.127317207871e+00),
        std::complex<double>(-1.549343597780e-01, 5.881974557496e-01),
        std::complex<double>(-9.942247821770e-02, -1.052337812183e-01),
        std::complex<double>(-6.405022152961e-02, -1.838117049218e-02),
        std::complex<double>(-3.956058646837e-02, 1.500165849216e-02)};

// Fourier extension of the GELU (tanh approximation) in [-8, 8] of degree 10: 10.2 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_gelu_8_double_10{
        std::complex<double>(1.946742959658e+00, 0.000000000000e+00),
        std::complex<double>(-1.549579796989e+00, -2.314519482177e+00),
        std::complex<double>(-8.930821676366e-02, 8.622049155709e-01),
        std::complex<double>(-1.317962505921e-01, -3.414500439321e-01),
        std::complex<double>(-5.449019151042e-02, 1.132913261249e-01),
        std::complex<double>(-3.966508159979e-02, -2.423738773332e-02),
        std::complex<double>(-2.716058820184e-02, -3.922374923920e-04),
        std::complex<double>(-1.854155390260e-02, 2.255556946569e-03),
        std::complex<double>(-1.276227004641e-02, -3.133977748725e-04),
        std::complex<double>(-8.656186677440e-03, -3.367605739171e-04),
        std::complex<double>(-5.705228803801e-03, 1.039627180057e-04)};

// Fourier extension of the GELU (tanh approximation) in [-8, 8] of degree 40: 33.6 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_gelu_8_double_40{
        std::complex<double>(1.965885389160e+00, 0.000000000000e+00),
        std::complex<double>(-1.585185251324e+00, -2.400826388161e+00),
        std::complex<double>(-6.075558472547e-02, 1.004119203241e+00),
        std::complex<double>(-1.513414256769e-01, -4.938489978745e-01),
        std::complex<double>(-4.329750904595e-02, 2.382546424573e-01),
        std::complex<double>(-4.482433869134e-02, -1.047772931657e-01),
        std::complex<double>(-2.539768695910e-02, 3.953439049822e-02),
        std::complex<double>(-1.888984262761e-02, -1.168774432292e-02),
        std::complex<double>(-1.277979962149e-02, 2.113440379157e-03),
        std::complex<double>(-8.628372611977e-03, 1.099882690865e-04),
        std::complex<double>(-5.704075996804e-03, -2.002114710226e-04),
        std::complex<double>(-3.654530064721e-03, 3.174356265544e-05),
        std::complex<double>(-2.269807516947e-03, 2.009949751462e-05),
        std::complex<double>(-1.366910519652e-03, -8.458401612760e-06),
        std::complex<double>(-7.981635107833e-04, -2.298167540521e-06),
        std::complex<double>(-4.528733339960e-04, 2.058211246679e-06),
        std::complex<double>(-2.508134102034e-04, 2.561387895533e-07),
        std::complex<double>(-1.363428476754e-04, -5.453961856301e-07),
        std::complex<double>(-7.313503392943e-05, -1.023957696411e-08),
        std::complex<double>(-3.885611526067e-05, 1.605058616329e-07),
        std::complex<double>(-2.044897030611e-05, -1.164042311153e-08),
        std::complex<double>(-1.059347014257e-05, -5.214442653600e-08),
        std::complex<double>(-5.324544263742e-06, 8.205654891680e-09),
        std::complex<double>(-2.534324100321e-06, 1.849862291603e-08),
        std::complex<double>(-1.095174074094e-06, -4.417020062208e-09),
        std::complex<double>(-3.891722267849e-07, -7.088805484235e-09),
        std::complex<double>(-7.136585446145e-08, 2.255128847550e-09),
        std::complex<double>(5.050510596544e-08, 2.906183412844e-09),
        std::complex<double>(8.126187085538e-08, -1.151160090862e-09),
        std::complex<double>(7.539869812528e-08, -1.264163444607e-09),
        std::complex<double>(5.882372174516e-08, 5.980871076172e-10),
        std::complex<double>(4.214485697235e-08, 5.793967133329e-10),
        std::complex<double>(2.871202445720e-08, -3.183001848206e-10),
        std::complex<double>(1.893026122662e-08, -2.781478862339e-10),
        std::complex<double>(1.220055629962e-08, 1.738465482681e-10),
        std::complex<double>(7.716397694424e-09, 1.391581077800e-10),
        std::complex<double>(4.786944765274e-09, -9.743696127718e-11),
        std::complex<double>(2.912962926427e-09, -7.224785028050e-11),
        std::complex<double>(1.743222402908e-09, 5.598976837717e-11),
        std::complex<double>(1.026621100630e-09, 3.878135442989e-11),
        std::complex<double>(5.929134875128e-10, -3.293805506122e-11)};

// Fourier extension of the GELU (tanh approximation) in [-8, 8] of degree 45: 38.2 bits (mean error relative to the range)
const std::vector<std::complex<double>> coeff_gelu_8_double_45{
        std::complex<double>(1.977054792853e+00, 0.000000000000e+00),
        std::complex<double>(-1.606533219629e+00, -2.458200630004e+00),
        std::complex<double>(-4.213655522183e-02, 1.105202411837e+00),
        std::complex<double>(-1.661315140100e-01, -6.163645706635e-01),
        std::complex<double>(-3.263567506999e-02, 3.589748914992e-01),
        std::complex<double>(-5.176115742282e-02, -2.063253266295e-01),
        std::complex<double>(-2.135634638718e-02, 1.137448041793e-01),
        std::complex<double>(-2.097457702963e-02, -5.898994425179e-02),
        std::complex<double>(-1.184281945679e-02, 2.828942477130e-02),
        std::complex<double>(-8.986605074529e-03, -1.230715183662e-02),
        std::complex<double>(-5.591891521073e-03, 4.733430185476e-03),
        std::complex<double>(-3.681437663399e-03, -1.543712043673e-03),
        std::complex<double>(-2.265578712310e-03, 3.920462518747e-04),
        std::complex<double>(-1.367070840573e-03, -5.901711969690e-05),
        std::complex<double>(-7.983054759936e-04, -5.072379977947e-06),
        std::complex<double>(-4.528010444384e-04, 5.795424932661e-06),
        std::complex<double>(-2.508352473839e-04, -1.109206261382e-06),
        std::complex<double>(-1.363487355949e-04, -3.170786175865e-07),
        std::complex<double>(-7.312660209881e-05, 2.043444410627e-07),
        std::complex<double>(-3.885661180762e-05, -2.474084378340e-09),
        std::complex<double>(-2.045148929104e-05, -2.970757924381e-08),
        std::complex<double>(-1.059293613565e-05, 6.093375697460e-09),
        std::complex<double>(-5.323746327000e-06, 4.186334980061e-09),
        std::complex<double>(-2.534591411953e-06, -1.882500733639e-09),
        std::complex<double>(-1.095452350977e-06, -5.658887178295e-10),
        std::complex<double>(-3.890485569882e-07, 5.016928840678e-10),
        std::complex<double>(-7.125963272670e-08, 6.141030739482e-11),
        std::complex<double>(5.044715169211e-08, -1.329482583051e-10),
        std::complex<double>(8.121807940987e-08, 9.752268437246e-13),
        std::complex<double>(7.542680165867e-08, 3.633919033741e-11),
        std::complex<double>(5.884298721675e-08, -4.496306105217e-12),
        std::complex<double>(4.213070409209e-08, -1.032628409864e-11),
        std::complex<double>(2.870305569234e-08, 2.521517716847e-12),
        std::complex<double>(1.893764677019e-08, 3.025103605114e-12),
        std::complex<double>(1.220499777513e-08, -1.102493096816e-12),
        std::complex<double>(7.712358453260e-09, -8.417736993560e-13),
        std::complex<double>(4.784647160460e-09, 4.092420846646e-13),
        std::complex<double>(2.915286255456e-09, 1.995055596421e-13),
        std::complex<double>(1.744462703847e-09, -7.046446759418e-14),
        std::complex<double>(1.025182216896e-09, -2.509223297892e-14),
        std::complex<double>(5.922519152619e-10, -1.069630495287e-13),
        std::complex<double>(3.366221155987e-10, 2.994094772460e-14),
        std::complex<double>(1.877325284702e-10, 2.829125822501e-13),
        std::complex<double>(1.027702853373e-10, -9.481608206907e-14),
        std::complex<double>(5.552482903797e-11, -1.837384411285e-13),
        std::complex<double>(2.933686280016e-11, 1.459542664679e-13)};

enum FEFunction { IDENTITY, EXP, TANH, SIGMOID, GELU };

struct fe_function {
    std::string name;
    double radius;  // the function is evaluated in [-radius, radius]
    double (*eval)(double);
};

const std::vector<fe_function> fe_functions = {
        {"identity", 0.5, [](double x) { return x; }},
        {"exp", 2.0, [](double x) { return std::exp(x); }},
        {"tanh", 4.0, [](double x) { return std::tanh(x); }},
        {"sigmoid", 8.0, [](double x) { return 1.0 / (1.0 + std::exp(-x)); }},
        {"gelu", 8.0,
         [](double x) { return 0.5 * x * (1.0 + std::tanh(std::sqrt(2.0 / M_PI) * (x + 0.044715 * std::pow(x, 3)))); }},
};

struct fefbt_config {
    FEFunction func;
    ScalingTechnique scalTech;
    uint32_t scalingModSize;  // the first modulus is one bit larger, as FE functional bootstrapping requires
    uint32_t levelsAfter;
    uint32_t ringDim;
    uint32_t dnum;
    std::vector<uint32_t> lvlb;
    const std::vector<std::complex<double>>* coeffs;
};

[[maybe_unused]] constexpr ScalingTechnique FM = FIXEDMANUAL;
[[maybe_unused]] constexpr ScalingTechnique FA = FLEXIBLEAUTO;

// All configurations use SPARSE_ENCAPSULATED secrets and full packing (N/2 slots), and keep log(QP) within the
// 128-bit limits for sparse secrets (767 / 1553 / 3104 bits at N = 2^15 / 2^16 / 2^17). The ring dimension, dnum and
// level budget of each group are the fastest combination measured (36 threads). The smallest ring dimension is not
// always the fastest: with several levels after bootstrapping, staying at the smaller ring dimension forces a {2,2}
// budget and a large dnum, so six levels run about 40% faster at N = 2^16 than at N = 2^15 (29-bit scaling) and 8-17%
// faster at N = 2^17 than at N = 2^16 (where only 53-55-bit scaling fits), with half the memory or less. With one
// level, the larger dnum at the smaller ring dimension costs less than doubling N. Likewise the smallest dnum is not
// always the fastest: ten levels at N = 2^17 run about 18% faster with {5,4} and dnum 3 than with {4,3} and dnum 2.
// levelsAfter is the number of levels added on top of GetFEFBTDepth; the output also keeps the lvlb[1] levels that
// the SlotsToCoeffs of the next FE functional bootstrapping consumes. Mean precision (bits relative to the range of
// the function): about 8.3-8.5 at 29 bits and 34-35 at 59 bits for FLEXIBLEAUTO; about 3 bits lower for FIXEDMANUAL.
// clang-format off
const std::vector<fefbt_config> fefbt_configs = {
    // func,  scalTech, scalingModSize, levelsAfter, ringDim, dnum, lvlb, coeffs                      log(QP)
    // 29-bit scaling, one level: N = 2^15
    {IDENTITY, FA, 29,  1, 1 << 15,  4, {3, 2}, &coeff_identity_1_double_5},   //  761
    {EXP,      FA, 29,  1, 1 << 15,  4, {3, 2}, &coeff_exp_2_double_5},        //  761
    {TANH,     FA, 29,  1, 1 << 15,  7, {3, 2}, &coeff_tanh_4_double_8},       //  730
    {SIGMOID,  FA, 29,  1, 1 << 15,  7, {3, 2}, &coeff_sigmoid_8_double_8},    //  730
    {GELU,     FA, 29,  1, 1 << 15,  7, {3, 2}, &coeff_gelu_8_double_10},      //  730
    // 29-bit scaling, six levels: N = 2^16 (N = 2^15 fits only with {2,2}, one tower per digit and a degree-5 series)
    {IDENTITY, FA, 29,  6, 1 << 16,  2, {5, 4}, &coeff_identity_1_double_5},   // 1321
    {EXP,      FA, 29,  6, 1 << 16,  2, {5, 4}, &coeff_exp_2_double_5},        // 1321
    {TANH,     FA, 29,  6, 1 << 16,  2, {5, 4}, &coeff_tanh_4_double_8},       // 1350
    {SIGMOID,  FA, 29,  6, 1 << 16,  2, {5, 4}, &coeff_sigmoid_8_double_8},    // 1350
    {GELU,     FA, 29,  6, 1 << 16,  2, {5, 4}, &coeff_gelu_8_double_10},      // 1350
    // 59-bit scaling, one level: N = 2^16
    {IDENTITY, FA, 59,  1, 1 << 16,  8, {3, 2}, &coeff_identity_1_double_27},  // 1539
    {EXP,      FA, 59,  1, 1 << 16,  8, {3, 2}, &coeff_exp_2_double_27},       // 1539
    {TANH,     FA, 59,  1, 1 << 16, 12, {3, 2}, &coeff_tanh_4_double_40},      // 1538
    {SIGMOID,  FA, 59,  1, 1 << 16, 12, {3, 2}, &coeff_sigmoid_8_double_40},   // 1538
    {GELU,     FA, 59,  1, 1 << 16, 12, {3, 2}, &coeff_gelu_8_double_45},      // 1538
    {IDENTITY, FM, 59,  1, 1 << 16,  8, {3, 2}, &coeff_identity_1_double_27},  // 1539
    {EXP,      FM, 59,  1, 1 << 16,  8, {3, 2}, &coeff_exp_2_double_27},       // 1539
    {TANH,     FM, 59,  1, 1 << 16, 12, {3, 2}, &coeff_tanh_4_double_40},      // 1538
    {SIGMOID,  FM, 59,  1, 1 << 16, 12, {3, 2}, &coeff_sigmoid_8_double_40},   // 1538
    {GELU,     FM, 59,  1, 1 << 16, 12, {3, 2}, &coeff_gelu_8_double_45},      // 1538
    // 59-bit scaling, six levels: N = 2^17 (N = 2^16 fits only with {2,2}, dnum 13-14 and 53-55-bit scaling)
    {IDENTITY, FA, 59,  6, 1 << 17,  4, {5, 4}, &coeff_identity_1_double_27},  // 2310
    {EXP,      FA, 59,  6, 1 << 17,  4, {5, 4}, &coeff_exp_2_double_27},       // 2310
    {TANH,     FA, 59,  6, 1 << 17,  4, {5, 4}, &coeff_tanh_4_double_40},      // 2369
    {SIGMOID,  FA, 59,  6, 1 << 17,  4, {5, 4}, &coeff_sigmoid_8_double_40},   // 2369
    {GELU,     FA, 59,  6, 1 << 17,  4, {5, 4}, &coeff_gelu_8_double_45},      // 2369
    {IDENTITY, FM, 59,  6, 1 << 17,  4, {5, 4}, &coeff_identity_1_double_27},  // 2310
    {EXP,      FM, 59,  6, 1 << 17,  4, {5, 4}, &coeff_exp_2_double_27},       // 2310
    {TANH,     FM, 59,  6, 1 << 17,  4, {5, 4}, &coeff_tanh_4_double_40},      // 2369
    {SIGMOID,  FM, 59,  6, 1 << 17,  4, {5, 4}, &coeff_sigmoid_8_double_40},   // 2369
    {GELU,     FM, 59,  6, 1 << 17,  4, {5, 4}, &coeff_gelu_8_double_45},      // 2369
    // 59-bit scaling, ten levels: N = 2^17
    {IDENTITY, FA, 59, 10, 1 << 17,  3, {5, 4}, &coeff_identity_1_double_27},  // 2786
    {EXP,      FA, 59, 10, 1 << 17,  3, {5, 4}, &coeff_exp_2_double_27},       // 2786
    {TANH,     FA, 59, 10, 1 << 17,  3, {5, 4}, &coeff_tanh_4_double_40},      // 2845
    {SIGMOID,  FA, 59, 10, 1 << 17,  3, {5, 4}, &coeff_sigmoid_8_double_40},   // 2845
    {GELU,     FA, 59, 10, 1 << 17,  3, {5, 4}, &coeff_gelu_8_double_45},      // 2845
    {IDENTITY, FM, 59, 10, 1 << 17,  3, {5, 4}, &coeff_identity_1_double_27},  // 2786
    {EXP,      FM, 59, 10, 1 << 17,  3, {5, 4}, &coeff_exp_2_double_27},       // 2786
    {TANH,     FM, 59, 10, 1 << 17,  3, {5, 4}, &coeff_tanh_4_double_40},      // 2845
    {SIGMOID,  FM, 59, 10, 1 << 17,  3, {5, 4}, &coeff_sigmoid_8_double_40},   // 2845
    {GELU,     FM, 59, 10, 1 << 17,  3, {5, 4}, &coeff_gelu_8_double_45},      // 2845
};
// clang-format on

double LogQPLimit(uint32_t ringDim) {
    switch (ringDim) {
        case 1 << 15:
            return 767;
        case 1 << 16:
            return 1553;
        case 1 << 17:
            return 3104;
        default:
            return 0;
    }
}

double LogModulus(const std::shared_ptr<ILDCRTParams<BigInteger>>& params) {
    double bits = 0;
    for (const auto& p : params->GetParams())
        bits += std::log2(p->GetModulus().ConvertToDouble());
    return bits;
}

uint32_t GetDepth(const fefbt_config& t) {
    return FHECKKSRNS::GetFEFBTDepth(t.lvlb, *t.coeffs, SPARSE_ENCAPSULATED, t.scalingModSize + 1) + t.levelsAfter;
}

CryptoContext<DCRTPoly> GenFEFBTContext(const fefbt_config& t) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(SPARSE_ENCAPSULATED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(t.ringDim);
    parameters.SetNumLargeDigits(t.dnum);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingModSize(t.scalingModSize);
    parameters.SetFirstModSize(t.scalingModSize + 1);
    parameters.SetScalingTechnique(t.scalTech);
    parameters.SetBatchSize(t.ringDim / 2);
    parameters.SetMultiplicativeDepth(GetDepth(t));

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

std::vector<double> BuildInput(uint32_t slots) {
    std::vector<double> input(slots);
    for (uint32_t i = 0; i < slots; ++i)
        input[i] = -0.5 + static_cast<double>(i) / slots;
    return input;
}

// mean absolute error relative to the range of the function, as in FE-functional-bootstrapping-ckks.cpp
double MeanPrecisionBits(const std::vector<double>& expected, const std::vector<double>& actual) {
    double minExpected = expected[0];
    double maxExpected = expected[0];
    double sumError = 0.0;
    for (size_t i = 0; i < expected.size(); ++i) {
        minExpected = std::min(minExpected, expected[i]);
        maxExpected = std::max(maxExpected, expected[i]);
        sumError += std::abs(expected[i] - actual[i]);
    }
    const double meanError = sumError / expected.size();
    return (meanError == 0.0) ? std::numeric_limits<double>::infinity() :
                                -std::log2(meanError / (maxExpected - minExpected));
}

[[maybe_unused]] void FEFBT(benchmark::State& state, const fefbt_config& t) {
    auto cc = GenFEFBTContext(t);
    auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    double logQP = LogModulus(cryptoParams->GetElementParams()) + LogModulus(cryptoParams->GetParamsP());
    if (logQP > LogQPLimit(t.ringDim)) {
        state.SkipWithError("log(QP) exceeds the 128-bit limit for the ring dimension");
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        return;
    }

    uint32_t depth = GetDepth(t);
    uint32_t slots = t.ringDim / 2;

    cc->EvalFEFuncBootstrapSetup(t.lvlb, {0, 0}, slots);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalBootstrapKeyGen(keyPair.secretKey, slots);

    auto x = BuildInput(slots);
    auto ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - (t.lvlb[1] + 1), nullptr, slots);
    auto ctxt = cc->Encrypt(keyPair.publicKey, ptxt);

    Ciphertext<DCRTPoly> ctxtAfter;
    for (auto _ : state)
        ctxtAfter = cc->EvalFEFuncBootstrap(ctxt, *t.coeffs);

    const auto& f = fe_functions[t.func];
    std::vector<double> expected(slots);
    for (uint32_t i = 0; i < slots; ++i)
        expected[i] = f.eval(2.0 * f.radius * x[i]);

    Plaintext result;
    cc->Decrypt(keyPair.secretKey, ctxtAfter, &result);
    result->SetLength(slots);
    state.counters["logQP"] = logQP;
    state.counters["precision"] = MeanPrecisionBits(expected, result->GetRealPackedValue());

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

// setup and key generation for the sigmoid with 59-bit scaling and one level after bootstrapping (FLEXIBLEAUTO)
const fefbt_config& setup_config = fefbt_configs[13];

[[maybe_unused]] void FEFBTSetup(benchmark::State& state) {
    auto cc = GenFEFBTContext(setup_config);
    for (auto _ : state)
        cc->EvalFEFuncBootstrapSetup(setup_config.lvlb, {0, 0}, setup_config.ringDim / 2);
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

[[maybe_unused]] void FEFBTKeyGen(benchmark::State& state) {
    auto cc = GenFEFBTContext(setup_config);
    auto slots = setup_config.ringDim / 2;
    cc->EvalFEFuncBootstrapSetup(setup_config.lvlb, {0, 0}, slots);
    auto keyPair = cc->KeyGen();
    for (auto _ : state) {
        state.PauseTiming();
        CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
        CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
        state.ResumeTiming();
        cc->EvalBootstrapKeyGen(keyPair.secretKey, slots);
        cc->EvalMultKeyGen(keyPair.secretKey);
    }
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

}  // namespace

int main(int argc, char** argv) {
    for (const auto& t : fefbt_configs) {
        std::string name = "FEFBT/" + fe_functions[t.func].name + (t.scalTech == FA ? "/FA" : "/FM") +
                           "/sf:" + std::to_string(t.scalingModSize) + "/levels:" + std::to_string(t.levelsAfter) +
                           "/logN:" + std::to_string(static_cast<uint32_t>(std::log2(t.ringDim)));
        benchmark::RegisterBenchmark(name, FEFBT, t)->Unit(benchmark::kSecond)->Iterations(4);
    }
    benchmark::RegisterBenchmark("FEFBTSetup", FEFBTSetup)->Unit(benchmark::kSecond)->Iterations(10);
    benchmark::RegisterBenchmark("FEFBTKeyGen", FEFBTKeyGen)->Unit(benchmark::kSecond)->Iterations(4);

    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
