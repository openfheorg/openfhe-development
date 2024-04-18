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
  This code tests the transform feature of the OpenFHE lattice encryption library.
 */

#include "gtest/gtest.h"
#include "lattice/lat-hal.h"
#include "math/distrgen.h"
#include "testdefs.h"
#include "utils/debug.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

/*-TESTING METHODS OF LATTICE ELEMENTS    ----------------*/
// all the common_* tests work for both Poly and DCRTPoly
// NOTE tests that only work on Poly because DCRT versions have not been
// coded are in UnitTestPolyElements.cpp
// When they are completed and run for both types,  they move to this file.

template <typename Element>
static void common_basic_ops(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    using ParmType = typename Element::Params;

    uint32_t m    = 8;
    auto ilparams = std::make_shared<ParmType>(m);

    OPENFHE_DEBUGEXP(*ilparams);
    Element ilvector2n1(ilparams);
    ilvector2n1 = {"1", "2", "0", "1"};
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n1.GetLength(), m / 2) << msg << " Failure: ={init list string}";

    OPENFHE_DEBUGEXP(ilvector2n1);
    Element ilvector2n2(ilparams);
    ilvector2n2 = {1, 2, 0, 1};
    EXPECT_EQ(ilvector2n2.GetLength(), m / 2) << msg << " Failure: ={init list int}";
    OPENFHE_DEBUGEXP(ilvector2n2);

    // test ctor(ilparams), ==
    EXPECT_EQ(ilvector2n1, ilvector2n2) << msg << " Failure:  ctor(ilparams) or op ==";

    {  // test copy ctor(Element)
        Element ilv1(ilvector2n1);
        EXPECT_EQ(ilvector2n1, ilv1) << msg << " Failure: copy ctor";
    }
    // TODO does not test any other ctor
    {  // test operator=
        Element ilv1 = ilvector2n1;
        EXPECT_EQ(ilvector2n1, ilv1) << msg << " Failure: op=";
    }
    OPENFHE_DEBUGEXP(ilvector2n1);
    // TODO move += -= to arithmetic ops
    {  // test operator-=
        Element ilv1 = ilvector2n1;
        OPENFHE_DEBUGEXP(ilvector2n1);
        OPENFHE_DEBUGEXP(ilv1);
        Element zero(ilparams);
        zero = {0, 0, 0, 0};
        OPENFHE_DEBUGEXP(zero);
        ilv1 -= ilvector2n1;
        OPENFHE_DEBUGEXP(ilv1);
        EXPECT_EQ(zero, ilv1) << msg << "Failure: Operator-=";

        // test !=
        EXPECT_NE(ilvector2n1, zero) << msg << " Failure: Operator!= value comparison";
        OPENFHE_DEBUGEXP(ilvector2n1);
        OPENFHE_DEBUGEXP(ilv1);
    }

    {  // test operator+=
        Element ilv1 = ilvector2n1;
        OPENFHE_DEBUGEXP(ilv1);
        Element two(ilparams);
        two = {2, 2, 2, 2};
        ilv1 += ilvector2n1;
        EXPECT_EQ(two * ilvector2n1, ilv1) << msg << "Failure: Operator+= ";
    }
}

// instantiate ops for various backend combos
TEST(UTPoly,  // NOLINTNEXTLINE
     common_basic_ops){RUN_ALL_POLYS(common_basic_ops, "Poly basic_ops")}

TEST(UTDCRTPoly, common_basic_ops) {
    RUN_BIG_DCRTPOLYS(common_basic_ops, "DCRT basic_ops")
}

// template for common_set_format()
template <typename Element>
void common_set_format(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");
    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);

    Element ilvector2n(ilparams, Format::COEFFICIENT);
    ilvector2n = {"3", "0", "0", "0"};
    OPENFHE_DEBUGEXP(ilvector2n);
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n.GetLength(), m / 2) << msg << " Failure: ={init list string}";
    Element ilvector2nInEval(ilparams, Format::EVALUATION);
    ilvector2nInEval = {"3", "3", "3", "3"};
    OPENFHE_DEBUGEXP(ilvector2nInEval);
    {  // test SetFormat()
        Element ilv(ilvector2n);

        ilv.SetFormat(Format::COEFFICIENT);
        EXPECT_EQ(ilvector2n, ilv) << msg << " Failure: SetFormat() to Format::COEFFICIENT";

        ilv.SetFormat(Format::EVALUATION);
        EXPECT_EQ(ilvector2nInEval, ilv) << msg << " Failure: SetFormat() to Format::EVALUATION";
    }
}

// instantiate various test for common_set_format()
TEST(UTPoly, common_set_format) {
    RUN_ALL_POLYS(common_set_format, "Poly common_set_format");
}

// TODO DCRTPoly needs a common_set_format()
TEST(UTDCRTPoly, common_set_format) {
    RUN_BIG_DCRTPOLYS(common_set_format, "DCRT common_set_format");
}

// template for common_setters_getters()
template <typename Element>
void common_setters_getters(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);

    {  // test getters
        Element ilvector2n(ilparams);
        ilvector2n = {"1", "2", "0", "1"};
        Element bbv(ilparams);
        bbv = {"1", "2", "0", "1"};
        OPENFHE_DEBUGEXP(ilvector2n);
        OPENFHE_DEBUGEXP(bbv);

        // test for bug where length was 0
        EXPECT_EQ(ilvector2n.GetLength(), m / 2) << msg << " Failure: ={init list string}";

        EXPECT_EQ(ilparams->GetModulus(), ilvector2n.GetModulus()) << msg << "Failure: GetModulus()";
        EXPECT_EQ(m, ilvector2n.GetCyclotomicOrder()) << msg << "Failure: GetCyclotomicOrder()";
        EXPECT_EQ(ilparams->GetRootOfUnity(), ilvector2n.GetRootOfUnity()) << msg << "Failure: GetRootOfUnity()";
        EXPECT_EQ(Format::EVALUATION, ilvector2n.GetFormat()) << msg << "Failure: GetFormat()";
        EXPECT_EQ(m / 2, ilvector2n.GetLength()) << msg << "Failure: GetLength()";
    }
}

// instantiate common_setters_getters() for various combos
TEST(UTPoly, common_setters_getters) {
    RUN_ALL_POLYS(common_setters_getters, "common_setters_getters");
}

TEST(UTDCRTPoly, common_setters_getters) {
    RUN_BIG_DCRTPOLYS(common_setters_getters, "common_setters_getters");
}

// template for common_binary_ops()
template <typename Element>
void common_binary_ops(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;
    using IntType  = typename Element::Vector::Integer;

    uint32_t m = 8;

    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");
    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);

    Element ilvector2n1(ilparams);
    ilvector2n1 = {"2", "1", "1", "1"};
    OPENFHE_DEBUGEXP(ilvector2n1);

    // test for bug where length was 0
    EXPECT_EQ(ilvector2n1.GetLength(), m / 2) << msg << " Failure: ={init list string}";

    Element ilvector2n2(ilparams);
    ilvector2n2 = {"1", "0", "1", "1"};
    OPENFHE_DEBUGEXP(ilvector2n2);

    Element ilvector2n3(ilparams, Format::COEFFICIENT);
    ilvector2n3 = {"2", "1", "1", "1"};
    OPENFHE_DEBUGEXP(ilvector2n3);

    Element ilvector2n4(ilparams, Format::COEFFICIENT);
    ilvector2n4 = {"1", "0", "1", "1"};
    OPENFHE_DEBUGEXP(ilvector2n4);

    {  // test Plus
        Element ilv1(ilvector2n1);
        OPENFHE_DEBUGEXP(ilv1);
        Element ilv2 = ilv1.Plus(ilvector2n2);
        OPENFHE_DEBUGEXP(ilv2);
        Element expected(ilparams, Format::EVALUATION);
        expected = {"3", "1", "2", "2"};
        EXPECT_EQ(expected, ilv2) << msg << " Failure: Plus()";
    }
    {  // test Minus
        Element ilv1(ilvector2n1);
        OPENFHE_DEBUGEXP(ilv1);
        Element ilv2 = ilv1.Minus(ilvector2n2);
        Element expected(ilparams, Format::EVALUATION);
        expected = {"1", "1", "0", "0"};
        EXPECT_EQ(expected, ilv2) << msg << " Failure: Minus()";
    }

    {  // test times
        Element ilv1(ilvector2n1);
        OPENFHE_DEBUGEXP(ilv1);
        Element ilv2 = ilv1.Times(ilvector2n2);
        Element expected(ilparams, Format::EVALUATION);
        expected = {"2", "0", "1", "1"};
        EXPECT_EQ(expected, ilv2) << msg << " Failure: Times()";
    }

    {  // test SwitchFormat()
        ilvector2n3.SwitchFormat();
        OPENFHE_DEBUGEXP(ilvector2n3);
        ilvector2n4.SwitchFormat();
        OPENFHE_DEBUGEXP(ilvector2n4);

        Element ilv3(ilvector2n3);
        Element ilv4 = ilv3.Times(ilvector2n4);
        OPENFHE_DEBUGEXP(ilv3);
        OPENFHE_DEBUGEXP(ilv4);

        ilv4.SwitchFormat();
        OPENFHE_DEBUGEXP(ilv4);
        Element expected(ilparams, Format::COEFFICIENT);
        std::stringstream tmpstr;
        tmpstr << (ilv4.GetModulus() - IntType(1));
        expected = {"0", tmpstr.str(), "2", "4"};
        EXPECT_EQ(expected, ilv4) << msg << " Failure: Times() using SwitchFormat()";
    }
}

// Instantiations of common_binary_ops
TEST(UTPoly, common_binary_ops) {
    RUN_ALL_POLYS(common_binary_ops, "Poly common_binary_ops");
}

TEST(UTDCRTPoly, common_binary_ops) {
    RUN_BIG_DCRTPOLYS(common_binary_ops, "DCRT common_binary_ops");
}

// templet for common_clone_ops
template <typename Element>
void common_clone_ops(const std::string& msg) {
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;
    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);

    Element ilv(ilparams);
    ilv = {"2", "1", "1", "1"};

    // test for bug where length was 0
    EXPECT_EQ(ilv.GetLength(), m / 2) << msg << " Failure: ={init list string}";

    {
        Element ilvClone = ilv.CloneParametersOnly();

        EXPECT_EQ(ilv.GetCyclotomicOrder(), ilvClone.GetCyclotomicOrder())
            << msg << " Failure: CloneParametersOnly GetCyclotomicOrder()";
        EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus()) << msg << " Failure: CloneParametersOnly GetModulus()";
        EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity())
            << msg << " Failure: CloneParametersOnly GetRootOfUnity()";
        EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat()) << msg << " Failure: CloneParametersOnly GetFormat()";
    }
    {
        float stdDev = 4;
        DiscreteGaussianGeneratorImpl<VecType> dgg(stdDev);
        Element ilvClone = ilv.CloneWithNoise(dgg, ilv.GetFormat());

        EXPECT_EQ(ilv.GetCyclotomicOrder(), ilvClone.GetCyclotomicOrder())
            << msg << " Failure: CloneWithNoise GetCyclotomicOrder()";
        EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus()) << msg << " Failure: CloneWithNoise GetModulus()";
        EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity())
            << msg << " Failure: CloneWithNoise GetRootOfUnity()";
        EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat()) << msg << " Failure: CloneWithNoise GetFormat()";
    }
}
// Instantiations of common_clone_ops()
TEST(UTPoly, common_clone_ops) {
    RUN_ALL_POLYS(common_clone_ops, "common_clone_ops");
}

TEST(UTDCRTPoly, common_clone_ops) {
    RUN_BIG_DCRTPOLYS(common_clone_ops, "common_clone_ops");
}

// template for common_arithmetic_ops_element()
template <typename Element>
void common_arithmetic_ops_element(const std::string& msg) {
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;
    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);

    Element ilv(ilparams);
    ilv = {"2", "1", "4", "1"};

    // test for bug where length was 0
    EXPECT_EQ(ilv.GetLength(), m / 2) << msg << " Failure: ={init list string}";

    typename VecType::Integer element("1");

    {
        Element ilvector2n(ilparams, Format::COEFFICIENT);
        ilvector2n = {"1", "3", "4", "1"};

        ilvector2n = ilvector2n.Plus(element);

        Element expected(ilparams, Format::COEFFICIENT);
        expected = {"2", "3", "4", "1"};
        EXPECT_EQ(expected, ilvector2n) << msg << " Failure: Plus()";
    }
    {
        Element ilvector2n = ilv.Minus(element);
        Element expected(ilparams);
        expected = {"1", "0", "3", "0"};
        EXPECT_EQ(expected, ilvector2n) << msg << " Failure: Minus()";
    }
    {
        typename VecType::Integer ele("2");
        Element ilvector2n = ilv.Times(ele);
        Element expected(ilparams);
        expected = {"4", "2", "8", "2"};
        EXPECT_EQ(expected, ilvector2n) << msg << " Failure: Times()";
    }
    {
        Element ilvector2n(ilparams, Format::COEFFICIENT);
        ilvector2n = {"1", "3", "4", "1"};

        ilvector2n += element;
        Element expected(ilparams, Format::COEFFICIENT);
        expected = {"2", "3", "4", "1"};
        EXPECT_EQ(expected, ilvector2n) << msg << " Failure: op+=";
    }
    {
        Element ilvector2n = ilv.Minus(element);
        Element expected(ilparams);
        expected = {"1", "0", "3", "0"};
        EXPECT_EQ(expected, ilvector2n) << msg << " Failure: Minus()";
    }
    {
        Element ilvector2n(ilv);
        ilvector2n -= element;
        Element expected(ilparams);
        expected = {"1", "0", "3", "0"};
        EXPECT_EQ(expected, ilvector2n) << msg << " Failure: op-=";
    }
}

// instantiations for common_arithmetic_ops_element()
TEST(UTPoly, common_arithmetic_ops_element) {
    RUN_ALL_POLYS(common_arithmetic_ops_element, "Poly common_arithmetic_ops_element");
}

TEST(UTDCRTPoly, common_arithmetic_ops_element) {
    RUN_BIG_DCRTPOLYS(common_arithmetic_ops_element, "DCRT common_arithmetic_ops_element");
}

// template fore common_other_methods()
template <typename Element>
void common_other_methods(const std::string& msg) {
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    OPENFHE_DEBUG_FLAG(false);
    uint32_t m = 8;
    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);

    Element ilvector2n(ilparams);
    ilvector2n = {"2", "1", "3", "2"};
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n.GetLength(), m / 2) << msg << " Failure: ={init list string}";

    OPENFHE_DEBUG("AddILElementOne");
    {
        Element ilv(ilvector2n);

        ilv.AddILElementOne();
        Element expected(ilparams);
        expected = {"3", "2", "4", "3"};
        EXPECT_EQ(expected, ilv) << msg << " Failure: AddILElementOne()";
    }

    OPENFHE_DEBUG("ModByTwo");
    {
        Element ilv(ilvector2n);
        ilv = ilv.ModByTwo();
        Element expected(ilparams);
        expected = {"0", "1", "1", "0"};
        EXPECT_EQ(expected, ilv) << msg << " Failure: ModByTwo()";
    }

    OPENFHE_DEBUG("MakeSparse(2)");
    {
        Element ilv(ilvector2n);
        ilv.MakeSparse(2);
        Element expected(ilparams);
        expected = {"2", "0", "3", "0"};
        EXPECT_EQ(expected, ilv) << msg << " Failure: MakeSparse(2)";

        Element ilv1(ilvector2n);
        ilv1.MakeSparse(3);
        expected = {"2", "0", "0", "2"};

        EXPECT_EQ(expected, ilv1) << msg << " Failure: MakeSparse(3)";
    }

    OPENFHE_DEBUG("InverseExists");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"2", "4", "3", "2"};

        Element ilv1(ilparams, Format::COEFFICIENT);
        ilv1 = {"2", "0", "3", "2"};

        Element ilv2(ilparams, Format::COEFFICIENT);
        ilv2 = {"2", "1", "3", "2"};

        EXPECT_EQ(true, ilv.InverseExists()) << msg << " Failure: ilv.InverseExists()";
        EXPECT_EQ(false, ilv1.InverseExists()) << msg << " Failure: ilv1.InverseExists()";
        EXPECT_EQ(true, ilv2.InverseExists()) << msg << " Failure: ilv2.InverseExists()";
    }
}

// Instantiations of common_other_methods()
TEST(UTPoly, common_other_methods) {
    RUN_ALL_POLYS(common_other_methods, "common_other_methods");
}

template <typename Element>
void common_cyclotomicOrder(const std::string& msg) {
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;
    auto ilparams0 =
        std::make_shared<ParmType>(m, typename VecType::Integer("1234"), typename VecType::Integer("5678"));
    Element ilv0(ilparams0);
    EXPECT_EQ(ilparams0->GetCyclotomicOrder(), ilv0.GetCyclotomicOrder()) << msg << " Failure: GetCyclotomicOrder()";
}

// Instantiations of cyclotomicOrder()
TEST(UTPoly, common_cyclotomicOrder) {
    RUN_ALL_POLYS(common_cyclotomicOrder, "Poly common_cyclotomicOrder");
}

TEST(UTDCRTPoly, common_cyclotomicOrder) {
    RUN_BIG_DCRTPOLYS(common_cyclotomicOrder, "DCRT common_cyclotomicOrder");
}
