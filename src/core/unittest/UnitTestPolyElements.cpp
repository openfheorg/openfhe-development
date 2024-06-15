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
  This code tests the transform feature of the OpenFHE lattice encryption library
 */

#include "gtest/gtest.h"
#include "lattice/lat-hal.h"
#include "math/distrgen.h"
#include "testdefs.h"
#include "utils/debug.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

// --------------- TESTING METHODS OF LATTICE ELEMENTS ---------------
// these tests only work on Poly, and have not been ported to DCRT
// NOTE tests that only work on Poly because DCRT versions have not been
// coded are here
// When they are completed and run for both types,  they move to
// UnitTestCommonElements.cpp

template <typename Element>
void rounding_ops(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer q("73");
    typename VecType::Integer primitiveRootOfUnity("22");
    typename VecType::Integer p("8");

    auto ilparams = std::make_shared<ParmType>(m, q, primitiveRootOfUnity);

    // temporary larger modulus that is used for polynomial multiplication before
    // rounding
    typename VecType::Integer q2("16417");
    typename VecType::Integer primitiveRootOfUnity2("13161");

    auto ilparams2 = std::make_shared<ParmType>(m, q2, primitiveRootOfUnity2);

    Element ilvector2n1(ilparams, Format::COEFFICIENT);
    ilvector2n1 = {"31", "21", "15", "34"};
    OPENFHE_DEBUGEXP(ilvector2n1);
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n1.GetLength(), m / 2) << msg << " Failure: ={init list string}";

    Element ilvector2n2(ilparams, Format::COEFFICIENT);
    ilvector2n2 = {"21", "11", "35", "32"};
    OPENFHE_DEBUGEXP(ilvector2n2);

    OPENFHE_DEBUG("unit test for MultiplyAndRound");
    Element roundingCorrect1(ilparams, Format::COEFFICIENT);
    roundingCorrect1 = {"3", "2", "2", "4"};

    OPENFHE_DEBUGEXP(ilvector2n1);

    Element rounding1 = ilvector2n1.MultiplyAndRound(p, q);

    EXPECT_EQ(roundingCorrect1, rounding1) << msg << " Failure: Rounding p*polynomial/q";

    OPENFHE_DEBUG("unit test for MultiplyAndRound after a polynomial");
    OPENFHE_DEBUG("multiplication using the larger modulus");

    Element roundingCorrect2(ilparams2, Format::COEFFICIENT);
    roundingCorrect2 = {"16316", "16320", "60", "286"};

    ilvector2n1.SwitchModulus(q2, primitiveRootOfUnity2, 0, 0);
    ilvector2n2.SwitchModulus(q2, primitiveRootOfUnity2, 0, 0);
    OPENFHE_DEBUGEXP(ilvector2n1);
    OPENFHE_DEBUGEXP(ilvector2n2);

    ilvector2n1.SwitchFormat();
    ilvector2n2.SwitchFormat();
    OPENFHE_DEBUGEXP(ilvector2n1);
    OPENFHE_DEBUGEXP(ilvector2n2);

    Element rounding2 = ilvector2n1 * ilvector2n2;

    OPENFHE_DEBUGEXP(rounding2);
    rounding2.SwitchFormat();
    OPENFHE_DEBUGEXP(rounding2);
    rounding2 = rounding2.MultiplyAndRound(p, q);
    OPENFHE_DEBUGEXP(rounding2);
    EXPECT_EQ(roundingCorrect2, rounding2) << msg << " Failure: Rounding p*polynomial1*polynomial2/q";

    OPENFHE_DEBUG("makes sure the result is correct after");
    OPENFHE_DEBUG("going back to the original modulus");

    rounding2.SwitchModulus(q, primitiveRootOfUnity, 0, 0);
    OPENFHE_DEBUGEXP(rounding2);

    Element roundingCorrect3(ilparams, Format::COEFFICIENT);
    roundingCorrect3 = {"45", "49", "60", "67"};

    EXPECT_EQ(roundingCorrect3, rounding2) << msg << " Failure p*polynomial1*polynomial2/q (mod q)";
}

// instantiate various test for rounding_ops()
TEST(UTPoly, rounding_ops) {
    RUN_ALL_POLYS(rounding_ops, "Poly rounding_ops");
}

// TODO DCRTPoly needs an assignment op/ctor
TEST(UTDCRTPoly, rounding_ops) {
    // std::cerr<<"*** skipping DCRT rounding_ops till MultiplyAndRound is
    // coded"<<std::endl; RUN_BIG_DCRTPOLYS(rounding_ops, "DCRT rounding_ops");
}

// template for set_get_values()
template <typename Element>
void set_get_values(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);
    {  // test SetValues()
        Element ilvector2n(ilparams);
        VecType bbv(m / 2, primeModulus);
        bbv = {"3", "0", "0", "0"};
        ilvector2n.SetValues(bbv, Format::COEFFICIENT);
        OPENFHE_DEBUGEXP(ilvector2n);
        // test for bug where length was 0
        EXPECT_EQ(ilvector2n.GetLength(), m / 2) << msg << " Failure: ={init list string}";

        Element ilvector2n2(ilparams);
        VecType bbv2(m / 2, primeModulus);
        bbv2 = {"3", "3", "3", "3"};
        ilvector2n2.SetValues(bbv2, Format::COEFFICIENT);

        // test SetValues()
        EXPECT_NE(ilvector2n, ilvector2n2) << msg << " Failure: SetValues NE";
        bbv2 = bbv;
        ilvector2n2.SetValues(bbv2, Format::COEFFICIENT);
        EXPECT_EQ(ilvector2n, ilvector2n2) << msg << " Failure: SetValues EQ";
    }
    {  // test GetValue() and at()
        Element ilvector2n(ilparams);
        ilvector2n = {"1", "2", "0", "1"};
        Element bbv(ilparams);
        bbv = {"1", "2", "0", "1"};
        OPENFHE_DEBUGEXP(ilvector2n);
        OPENFHE_DEBUGEXP(bbv);

        EXPECT_EQ(bbv.GetValues(), ilvector2n.GetValues()) << msg << "Failure: GetValues()";

        uint32_t index = 3;
        bbv[index]     = 11;
        for (uint32_t i = 0; i < m / 2; ++i) {
            if (i == index) {
                EXPECT_NE(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
            }
            else {
                EXPECT_EQ(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
            }
        }
    }
}

// instantiate various test for set_get_values()
TEST(UTPoly, set_get_values) {
    RUN_ALL_POLYS(set_get_values, "Poly set_get_values");
}

// TODO DCRTPoly needs a set_get_values()
TEST(UTDCRTPoly, set_get_values) {
    // std::cerr<<"*** skipping DCRT set_get_values till coded"<<std::endl;
    // RUN_BIG_DCRTPOLYS(set_get_values, "DCRT set_values");
}

// template for at()
template <typename Element>
void at(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);

    {  // test and at() and []
        Element ilvector2n(ilparams);
        ilvector2n = {"1", "2", "0", "1"};
        Element bbv(ilparams);
        bbv = {"1", "2", "0", "1"};
        OPENFHE_DEBUGEXP(ilvector2n);
        OPENFHE_DEBUGEXP(bbv);
        // test for bug where length was 0
        EXPECT_EQ(ilvector2n.GetLength(), m / 2) << msg << " Failure: ={init list string}";

        uint32_t index = 3;
        bbv[index]     = 11;
        for (uint32_t i = 0; i < m / 2; ++i) {
            if (i == index) {
                EXPECT_NE(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
            }
            else {
                EXPECT_EQ(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
            }
        }
        bbv.at(index) = 1;
        for (uint32_t i = 0; i < m / 2; ++i) {
            EXPECT_EQ(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
        }
    }
}

// instantiate various test for at()
TEST(UTPoly, at) {
    RUN_ALL_POLYS(at, "Poly at");
}

// TODO DCRTPoly needs a at() and []
TEST(UTDCRTPoly, at) {
    // std::cerr<<"*** skipping DCRT at till coded"<<std::endl;
    // RUN_BIG_DCRTPOLYS(at, "DCRT at");
}

// template for switch_modulus

template <typename Element>
void switch_modulus(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;
    // using IntType = typename Element::Vector::Integer;

    uint32_t m = 8;
    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);
    OPENFHE_DEBUG("SwitchModulus");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"56", "1", "37", "2"};
        // test for bug where length was 0
        EXPECT_EQ(ilv.GetLength(), m / 2) << msg << " Failure: ={init list string}";

        typename VecType::Integer modulus("17");
        typename VecType::Integer rootOfUnity("15");

        ilv.SwitchModulus(modulus, rootOfUnity, 0, 0);

        auto ilparams2 = std::make_shared<ParmType>(m, modulus, rootOfUnity);
        Element expected(ilparams2, Format::COEFFICIENT);
        expected = {"0", "1", "15", "2"};
        EXPECT_EQ(expected, ilv) << msg << " Failure: SwitchModulus()";

        Element ilv1(ilparams, Format::COEFFICIENT);
        ilv1 = {"56", "43", "35", "28"};
        typename VecType::Integer modulus1("193");
        typename VecType::Integer rootOfUnity1("150");

        ilv1.SwitchModulus(modulus1, rootOfUnity1, 0, 0);
        auto ilparams3 = std::make_shared<ParmType>(m, modulus1, rootOfUnity1);
        Element expected2(ilparams3, Format::COEFFICIENT);
        expected2 = {"176", "163", "35", "28"};
        EXPECT_EQ(expected2, ilv1) << msg << " Failure: SwitchModulus()";
    }
}
// instantiations for switch_modulus()
TEST(UTPoly, switch_modulus) {
    RUN_ALL_POLYS(switch_modulus, "Poly switch_modulus");
}

TEST(UTDCRTPoly, switch_modulus) {
    // std::cerr<<"*** skipping DCRT switch_modulus till coded"<<std::endl;
    // //RUN_BIG_DCRTPOLYS(switch_modulus, "Poly switch_modulus");
}

// template fore rn_generators()
template <typename Element>
void rn_generators(const std::string& msg) {
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    OPENFHE_DEBUG_FLAG(false);
    uint32_t m = 8;
    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    float stdDev = 4.0f;
    typename Element::DggType dgg(stdDev);
    typename Element::BugType bug;
    typename Element::DugType dug;

    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);

    OPENFHE_DEBUG("DestroyPreComputedSamples");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"2", "1", "3", "2"};
        // test for bug where length was 0
        EXPECT_EQ(ilv.GetLength(), m / 2) << msg << " Failure: ={init list string}";

        Element ilvector2n1(ilparams);
        Element ilvector2n2(ilparams);
        Element ilvector2n3(ilv);
        Element ilvector2n4(dgg, ilparams);
        Element ilvector2n5(bug, ilparams);
        Element ilvector2n6(dug, ilparams);

        EXPECT_EQ(true, ilvector2n1.IsEmpty()) << msg << " Failure: DestroyPreComputedSamples() 2n1";
        EXPECT_EQ(true, ilvector2n2.IsEmpty()) << msg << " Failure: DestroyPreComputedSamples() 2n2";
        EXPECT_EQ(false, ilvector2n3.IsEmpty()) << msg << " Failure: DestroyPreComputedSamples() 2n3";
        EXPECT_EQ(false, ilvector2n4.IsEmpty()) << msg << " Failure: DestroyPreComputedSamples() 2n4";
        EXPECT_EQ(false, ilvector2n5.IsEmpty()) << msg << " Failure: DestroyPreComputedSamples() 2n5";
        EXPECT_EQ(false, ilvector2n6.IsEmpty()) << msg << " Failure: DestroyPreComputedSamples() 2n6";
    }
}

// Instantiations of rn_generators()
TEST(UTPoly, rn_generators) {
    RUN_ALL_POLYS(rn_generators, "Poly rn_generators");
}

TEST(UTDCRTPoly, rn_generators) {
    // std::cerr<<"*** skipping DCRT rn_generators till coded"<<std::endl;
    // RUN_BIG_DCRTPOLYS(rn_generators, "DCRT rn_generators");
}

// template fore poly_other_methods()
template <typename Element>
void poly_other_methods(const std::string& msg) {
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

    OPENFHE_DEBUG("SwitchFormat");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"2", "1", "3", "2"};

        ilv.SwitchFormat();

        EXPECT_EQ(primeModulus, ilv.GetModulus()) << msg << " Failure: SwitchFormat() ilv modulus";
        EXPECT_EQ(primitiveRootOfUnity, ilv.GetRootOfUnity()) << msg << " Failure: SwitchFormat() ilv rootOfUnity";
        EXPECT_EQ(Format::EVALUATION, ilv.GetFormat()) << msg << " Failure: SwitchFormat() ilv format";
        Element expected(ilparams);
        expected = {"69", "65", "44", "49"};
        EXPECT_EQ(expected, ilv) << msg << " Failure: ivl.SwitchFormat() values";

        Element ilv1(ilparams, Format::EVALUATION);
        ilv1 = {"2", "3", "1", "2"};

        ilv1.SwitchFormat();

        EXPECT_EQ(primeModulus, ilv1.GetModulus()) << msg << " Failure: SwitchFormat() ilv1 modulus";
        EXPECT_EQ(primitiveRootOfUnity, ilv1.GetRootOfUnity()) << msg << " Failure: SwitchFormat() ilv1 rootOfUnity";
        EXPECT_EQ(Format::COEFFICIENT, ilv1.GetFormat()) << msg << " Failure: SwitchFormat() ilv1 format";
        Element expected2(ilparams, Format::COEFFICIENT);
        expected2 = {"2", "3", "50", "3"};
        EXPECT_EQ(expected2, ilv1) << msg << " Failure: ivl1.SwitchFormat() values";
    }

    OPENFHE_DEBUG("MultiplicativeInverse");
    {
        Element ilv1(ilparams, Format::EVALUATION);
        ilv1 = {"2", "4", "3", "2"};

        Element ilvInverse1 = ilv1.MultiplicativeInverse();
        Element ilvProduct1 = ilv1 * ilvInverse1;

        for (uint32_t i = 0; i < m / 2; ++i) {
            EXPECT_EQ(ilvProduct1[i], typename Element::Integer(1))
                << msg << " Failure: ilvProduct1.MultiplicativeInverse() @ index " << i;
        }
    }

    OPENFHE_DEBUG("Norm");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"56", "1", "37", "1"};
        EXPECT_EQ(36, ilv.Norm()) << msg << " Failure: Norm()";
    }
}

// Instantiations of poly_other_methods()
TEST(UTPoly, poly_other_methods) {
    RUN_ALL_POLYS(poly_other_methods, "poly_other_methods");
}

// TODO
TEST(UTDCRTPoly, poly_other_methods) {
    // std::cerr<<"*** skipping DCRT poly_other_methods till these functions are
    // coded"<<std::endl;
    //   RUN_BIG_DCRTPOLYS(poly_other_methods, "DCRT poly_other_methods");
}

// Signed mod must handle the modulo operation for both positive and negative
// numbers It is used in decoding/decryption of homomorphic encryption schemes
template <typename Element>
void signed_mod(const std::string& msg) {
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer primeModulus("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    auto ilparams = std::make_shared<ParmType>(m, primeModulus, primitiveRootOfUnity);

    Element ilvector2n1(ilparams, Format::COEFFICIENT);
    ilvector2n1 = {"62", "7", "65", "8"};
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n1.GetLength(), m / 2) << msg << " Failure: ={init list string}";

    {
        Element ilv1(ilparams, Format::COEFFICIENT);
        ilv1 = ilvector2n1.Mod(2);
        Element expected(ilparams, Format::COEFFICIENT);
        expected = {"1", "1", "0", "0"};
        EXPECT_EQ(expected, ilv1) << msg << " Failure: ilv1.Mod(TWO)";
    }

    {
        Element ilv1(ilparams, Format::COEFFICIENT);
        ilv1 = ilvector2n1.Mod(5);
        Element expected(ilparams, Format::COEFFICIENT);
        expected = {"4", "2", "2", "3"};
        EXPECT_EQ(expected, ilv1) << msg << " Failure: ilv1.Mod(FIVE)";
    }
}
// Instantiations of signed_mod()
TEST(UTPoly, signed_mod) {
    RUN_ALL_POLYS(signed_mod, "signed_mod");
}

// TODO
TEST(UTDCRTPoly, signed_mod) {
    // std::cerr<<"*** skipping DCRT signed_mod till coded"<<std::endl;
    //  RUN_BIG_DCRTPOLYS(signed_mod, "signed_mod");
}

// template fore automorphismTransform()
template <typename Element>
void automorphismTransform(const std::string& msg) {
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

    OPENFHE_DEBUG("AutomorphismTransform");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"56", "1", "37", "2"};

        uint32_t index = 3;
        Element ilvAuto(ilv.AutomorphismTransform(index));
        Element expected(ilparams, Format::COEFFICIENT);
        expected = {"56", "2", "36", "1"};
        EXPECT_EQ(expected, ilvAuto) << msg << " Failure: AutomorphismTransform()";
    }
}
// Instantiations of automorphismTransform()
TEST(UTPoly, automorphismTransform) {
    RUN_ALL_POLYS(automorphismTransform, "Poly automorphismTransform");
}

// TODO
TEST(UTDCRTPoly, automorphismTransform) {
    // std::cerr<<"*** skipping DCRT automorphismTransform till coded"<<std::endl;
    //  RUN_BIG_DCRTPOLYS(automorphismTransform, "DCRT automorphismTransform");
}

template <typename Element>
void transposition(const std::string& msg) {
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    OPENFHE_DEBUG_FLAG(false);
    uint32_t m = 8;

    typename VecType::Integer q("73");
    typename VecType::Integer primitiveRootOfUnity("22");

    auto ilparams = std::make_shared<ParmType>(m, q, primitiveRootOfUnity);

    Element ilvector2n1(ilparams, Format::COEFFICIENT);
    ilvector2n1 = {"31", "21", "15", "34"};
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n1.GetLength(), m / 2) << msg << " Failure: ={init list string}";

    // converts to Format::EVALUATION representation
    ilvector2n1.SwitchFormat();
    OPENFHE_DEBUG("ilvector2n1 a " << ilvector2n1);

    ilvector2n1 = ilvector2n1.Transpose();
    OPENFHE_DEBUG("ilvector2n1 b " << ilvector2n1);

    // converts back to Format::COEFFICIENT representation
    ilvector2n1.SwitchFormat();

    OPENFHE_DEBUG("ilvector2n1 c " << ilvector2n1);

    Element ilvector2n2(ilparams, Format::COEFFICIENT);
    ilvector2n2 = {"31", "39", "58", "52"};

    OPENFHE_DEBUG("ilvector2n2 a " << ilvector2n2);

    EXPECT_EQ(ilvector2n2, ilvector2n1) << msg << " Failure: transposition test";
}
// Instantiations of transposition()
TEST(UTPoly, transposition) {
    RUN_ALL_POLYS(transposition, "transposition");
}

// TODO
TEST(UTDCRTPoly, transposition) {
    // std::cerr<<"*** skipping DCRT transposition till coded"<<std::endl;
    //  RUN_BIG_DCRTPOLYS(transposition, "transposition");
}

template <typename Element>
void Poly_mod_ops_on_two_elements(const std::string& msg) {
    using VecType  = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t order = 8;
    uint32_t nBits = 7;

    typename VecType::Integer primeModulus = LastPrime<typename VecType::Integer>(nBits, order);
    auto ilparams                          = std::make_shared<ParmType>(order, primeModulus);

    typename Element::DugType distrUniGen;

    Element ilv1(distrUniGen, ilparams);
    VecType bbv1(ilv1.GetValues());

    Element ilv2(distrUniGen, ilparams);
    VecType bbv2(ilv2.GetValues());

    {
        Element ilvResult = ilv1 + ilv2;
        VecType bbvResult(ilvResult.GetValues());

        for (uint32_t i = 0; i < order / 2; i++) {
            EXPECT_EQ(bbvResult[i], (bbv1[i] + bbv2[i]).Mod(primeModulus))
                << msg << " Poly + operation returns incorrect results.";
        }
    }

    {
        Element ilvResult = ilv1 * ilv2;
        VecType bbvResult(ilvResult.GetValues());

        for (uint32_t i = 0; i < order / 2; i++) {
            EXPECT_EQ(bbvResult[i], (bbv1[i] * bbv2[i]).Mod(primeModulus))
                << msg << " Poly * operation returns incorrect results.";
        }
    }
}

TEST(UTPoly, Poly_mod_ops_on_two_elements) {
    RUN_ALL_POLYS(Poly_mod_ops_on_two_elements, "Poly Poly_mod_ops_on_two_elements");
}
