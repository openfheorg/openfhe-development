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
  Example of integer Gaussian sampling
 */

#include "openfhecore.h"
// #include <vld.h>
using namespace lbcrypto;

int main() {
    // double std = 1000;
    // double std = 10000;

    double stdBase   = 34;
    double std       = (1 << 22);
    int CENTER_COUNT = 1024;

    // Random bit generator required by the base samplers
    BitGenerator bg;
    DiscreteGaussianGeneratorImpl<NativeVector> dgg(4);
    DiscreteGaussianGeneratorImpl<NativeVector> dggRejection(4);
    DiscreteGaussianGeneratorImpl<NativeVector> dgg4(stdBase);  // for Peikert's method
    double start, finish;
    size_t count               = 1000;
    double SMOOTHING_PARAMETER = 6;

    std::cout << "Distribution parameter = " << std << std::endl;

    // Initialization of the base samplers used in generic sampler
    BaseSampler** peikert_samplers = new BaseSampler*[CENTER_COUNT];
    BaseSampler** ky_samplers      = new BaseSampler*[CENTER_COUNT];

    // BaseSampler sampler(mean,std,bg,PEIKERT);
    std::cout << "Started creating base samplers" << std::endl;
    for (int i = 0; i < CENTER_COUNT; i++) {
        double center = (static_cast<double>(i) / static_cast<double>(CENTER_COUNT));
        // Base sampler takes the parameters mean of the distribution, standard
        // deviation of distribution, bit generator used for random bits and the
        // type of the sampler
        peikert_samplers[i] = new BaseSampler(static_cast<double>(center), stdBase, &bg, PEIKERT);
        ky_samplers[i]      = new BaseSampler(static_cast<double>(center), stdBase, &bg, KNUTH_YAO);
    }
    std::cout << "Ended creating base samplers, Started sampling" << std::endl;

    start = currentDateTime();
    for (int k = 0; k < CENTER_COUNT; k++) {
        double center = k / static_cast<double>(CENTER_COUNT);
        for (size_t i = 0; i < count; i++) {
            dggRejection.GenerateInteger(center, std, 8192);
        }
    }
    finish = currentDateTime();
    std::cout << "Sampling " << std::to_string(count) << " integers (Rejection): " << (finish - start) / CENTER_COUNT
              << " ms\n";

    start = currentDateTime();
    for (int k = 0; k < CENTER_COUNT; k++) {
        double center = k / static_cast<double>(CENTER_COUNT);
        for (size_t i = 0; i < count; i++) {
            dgg.GenerateIntegerKarney(center, std);
        }
    }

    finish = currentDateTime();
    std::cout << "Sampling " << std::to_string(count) << " integers (Karney): " << (finish - start) / CENTER_COUNT
              << " ms\n";

    int base = std::log(CENTER_COUNT) / std::log(2);
    // Initialization for the generic sampler, takes the parameters array of base
    // samplers, standard deviation of the base sampler base=(which is log2(number
    // of cosets or centers)) and smoothing parameter Make sure that stdBase>= 4 *
    // sqrt(2) * smoothing parameter
    DiscreteGaussianGeneratorGeneric dgg2(peikert_samplers, stdBase, base, SMOOTHING_PARAMETER);
    start = currentDateTime();
    for (int k = 0; k < CENTER_COUNT; k++) {
        double center = k / static_cast<double>(CENTER_COUNT);
        for (size_t i = 0; i < count; i++) {
            // To generate integer with the generic sampler, parameters are mean of
            // the distribution and the standard deviation of the distribution
            dgg2.GenerateInteger(center, std);  // k/CENTER_COUNT
        }
    }
    finish = currentDateTime();
    std::cout << "Sampling " << std::to_string(count)
              << " integers (Generic - Peikert): " << (finish - start) / CENTER_COUNT << " ms\n";

    DiscreteGaussianGeneratorGeneric dgg3(ky_samplers, stdBase, base, SMOOTHING_PARAMETER);
    start = currentDateTime();
    for (int k = 0; k < CENTER_COUNT; k++) {
        double center = k / static_cast<double>(CENTER_COUNT);
        for (size_t i = 0; i < count; i++) {
            dgg3.GenerateInteger(center, std);
            // dgg3.GenerateIntegerKnuthYaoAlt(0);
        }
    }
    finish = currentDateTime();
    std::cout << "Sampling " << std::to_string(count)
              << " integers (Generic - Knuth Yao): " << (finish - start) / CENTER_COUNT << " ms\n";
}
