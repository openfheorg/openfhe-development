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

void testDCRTPolyConstructorNegative(std::vector<NativePoly>& towers);

// --------------- TESTING METHODS OF LATTICE ELEMENTS ---------------
// these tests work only for DCRTPoly

template <typename Element>
void DCRT_constructors(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    uint32_t m         = 8;
    uint32_t towersize = 3;

    std::vector<NativeInteger> moduli(towersize);
    moduli = {NativeInteger("8353"), NativeInteger("8369"), NativeInteger("8513")};
    std::vector<NativeInteger> rootsOfUnity(towersize);
    rootsOfUnity = {NativeInteger("8163"), NativeInteger("6677"), NativeInteger("156")};

    typename Element::Integer modulus(1);
    for (uint32_t i = 0; i < towersize; ++i) {
        modulus = modulus * typename Element::Integer(moduli[i].ConvertToInt());
    }

    auto ilparams0 = std::make_shared<ILNativeParams>(m, moduli[0], rootsOfUnity[0]);
    auto ilparams1 = std::make_shared<ILNativeParams>(m, moduli[1], rootsOfUnity[1]);
    auto ilparams2 = std::make_shared<ILNativeParams>(m, moduli[2], rootsOfUnity[2]);

    NativePoly ilv0(ilparams0);
    NativeVector bbv0(m / 2, moduli[0]);
    bbv0 = {"2", "4", "3", "2"};
    ilv0.SetValues(bbv0, Format::EVALUATION);

    NativePoly ilv1(ilv0);
    ilv1.SwitchModulus(moduli[1], rootsOfUnity[1], 0, 0);

    NativePoly ilv2(ilv0);
    ilv2.SwitchModulus(moduli[2], rootsOfUnity[2], 0, 0);

    auto ildcrtparams = std::make_shared<ILDCRTParams<typename Element::Integer>>(m, moduli, rootsOfUnity);

    std::vector<NativePoly> ilvector2nVector;
    ilvector2nVector.push_back(ilv0);
    ilvector2nVector.push_back(ilv1);
    ilvector2nVector.push_back(ilv2);

    OPENFHE_DEBUG("1");
    float stdDev = 4.0;
    typename Element::DggType dgg(stdDev);

    {
        Element ilva(ildcrtparams);

        EXPECT_EQ(Format::EVALUATION, ilva.GetFormat()) << msg << " Failure: ildcrtparams ctor ilva.GetFormat()";
        EXPECT_EQ(modulus, ilva.GetModulus()) << msg << " Failure: ildcrtparams ctor ilva.GetModulus()";
        EXPECT_EQ(m, ilva.GetCyclotomicOrder()) << msg << " Failure: ildcrtparams ctor ilva.GetModulus()";
        EXPECT_EQ(towersize, ilva.GetNumOfElements()) << msg << " Failure: ildcrtparams ctor ilva.GetNumOfElements()";
    }

    OPENFHE_DEBUG("2");
    {
        Element ilva(ilvector2nVector);

        OPENFHE_DEBUG("2.0");
        EXPECT_EQ(Format::EVALUATION, ilva.GetFormat()) << msg << " Failure: ctor ilva.GetFormat()";
        EXPECT_EQ(modulus, ilva.GetModulus()) << msg << " Failure: ctor ilva.GetModulus()";
        EXPECT_EQ(m, ilva.GetCyclotomicOrder()) << msg << " Failure: ctor ilva.GetCyclotomicOrder()";
        EXPECT_EQ(towersize, ilva.GetNumOfElements()) << msg << " Failure: ctor ilva.GetNumOfElements()";

        OPENFHE_DEBUG("2.1");
        std::vector<NativePoly> ilvector2nVectorInconsistent(towersize);
        auto ilparamsNegativeTestCase =
            std::make_shared<ILNativeParams>(128, NativeInteger("1231"), NativeInteger("213"));
        NativePoly ilvNegative(ilparamsNegativeTestCase);
        ilvector2nVectorInconsistent[0] = ilvNegative;
        ilvector2nVectorInconsistent[1] = ilv1;
        ilvector2nVectorInconsistent[2] = ilv2;

        OPENFHE_DEBUG("2.2");
        for (size_t ii = 0; ii < ilvector2nVectorInconsistent.size(); ii++) {
            OPENFHE_DEBUG(ii << " item " << ilvector2nVectorInconsistent.at(ii).GetParams().use_count());
        }
        EXPECT_THROW(testDCRTPolyConstructorNegative(ilvector2nVectorInconsistent), OpenFHEException)
            << msg << " Failure: ilvector2nVectorInconsistent";
    }

    OPENFHE_DEBUG("4");
    {
        Element ilva0;
        Element ilva1(ildcrtparams);
        Element ilva2(ilvector2nVector);

        std::vector<Element> ilvaVector({ilva0, ilva1, ilva2});

        // copy constructor
        Element ilva0Copy(ilva0);
        Element ilva1Copy(ilva1);
        Element ilva2Copy(ilva2);

        std::vector<Element> ilvaCopyVector({ilva0Copy, ilva1Copy, ilva2Copy});

        for (uint32_t i = 0; i < 3; ++i) {
            EXPECT_EQ(ilvaVector[i].GetFormat(), ilvaCopyVector[i].GetFormat())
                << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetFormat()";
            EXPECT_EQ(ilvaVector[i].GetModulus(), ilvaCopyVector[i].GetModulus())
                << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetModulus()";
            EXPECT_EQ(ilvaVector[i].GetCyclotomicOrder(), ilvaCopyVector[i].GetCyclotomicOrder())
                << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetCyclotomicOrder()";
            EXPECT_EQ(ilvaVector[i].GetNumOfElements(), ilvaCopyVector[i].GetNumOfElements())
                << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetNumOfElements()";
            // to ensure that GetElementAtIndex is not called
            // on uninitialized DCRTPoly objects.
            if (i == 0 || i == 1)
                continue;
            for (uint32_t j = 0; j < towersize; ++j) {
                EXPECT_EQ(ilvaVector[i].GetElementAtIndex(j), ilvaCopyVector[i].GetElementAtIndex(j))
                    << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetElementAtIndex(" << j << ")";
            }
        }
    }

    OPENFHE_DEBUG("5");
    {
        OPENFHE_DEBUG("ild mod " << ildcrtparams->GetModulus());
        Element ilva(dgg, ildcrtparams);

        EXPECT_EQ(Format::EVALUATION, ilva.GetFormat()) << msg << " Failure: ctor(dgg, ldcrtparams) ilva.GetFormat()";
        EXPECT_EQ(modulus, ilva.GetModulus()) << msg << " Failure: ctor(dgg, ildcrtparams) ilva.GetModulus()";
        EXPECT_EQ(m, ilva.GetCyclotomicOrder()) << msg << " Failure: ctor(dgg, ildcrtparams) ilva.GetCyclotomicOrder()";
        EXPECT_EQ(towersize, ilva.GetNumOfElements())
            << msg << " Failure: ctor(dgg, ildcrtparams) ilva.GetNumOfElements()";
    }

    OPENFHE_DEBUG("6");
    {
        Element ilva(dgg, ildcrtparams);
        Element ilvaClone(ilva.CloneParametersOnly());

        std::vector<NativePoly> towersInClone = ilvaClone.GetAllElements();

        EXPECT_EQ(Format::EVALUATION, ilva.GetFormat()) << msg << "Failure: clone parameters format mismatch";
        EXPECT_EQ(ilva.GetParams(), ilvaClone.GetParams()) << msg << "Failure: clone parameters parameter mismatch";
        EXPECT_EQ(towersInClone.size(), ilva.GetAllElements().size())
            << msg << "Failure: clone parameters towers size mismatch";
    }
}

TEST(UTDCRTPoly, DCRT_constructors) {
    RUN_BIG_DCRTPOLYS(DCRT_constructors, "DCRT constructors");
}

template <typename Element>
void DCRT_getters_and_ops(const std::string& msg) {
    uint32_t m         = 8;
    uint32_t towersize = 3;

    std::vector<NativeInteger> moduli(towersize);
    moduli = {NativeInteger("8353"), NativeInteger("8369"), NativeInteger("8513")};

    std::vector<NativeInteger> rootsOfUnity(towersize);

    rootsOfUnity = {NativeInteger("8163"), NativeInteger("6677"), NativeInteger("156")};

    typename Element::Integer modulus(1);
    for (uint32_t i = 0; i < towersize; ++i) {
        modulus = modulus * typename Element::Integer(moduli[i].ConvertToInt());
    }

    auto ilparams0 = std::make_shared<ILNativeParams>(m, moduli[0], rootsOfUnity[0]);
    auto ilparams1 = std::make_shared<ILNativeParams>(m, moduli[1], rootsOfUnity[1]);
    auto ilparams2 = std::make_shared<ILNativeParams>(m, moduli[2], rootsOfUnity[2]);

    NativePoly ilv0(ilparams0);
    NativeVector bbv0(ilparams0->GetRingDimension(), moduli[0]);
    bbv0 = {"2", "4", "3", "2"};
    ilv0.SetValues(bbv0, Format::EVALUATION);

    NativePoly ilv1(ilv0);
    ilv1.SwitchModulus(moduli[1], rootsOfUnity[1], 0, 0);

    NativePoly ilv2(ilv0);
    ilv2.SwitchModulus(moduli[2], rootsOfUnity[2], 0, 0);

    auto ildcrtparams = std::make_shared<ILDCRTParams<typename Element::Integer>>(m, moduli, rootsOfUnity);

    std::vector<NativePoly> ilvector2nVector(towersize);

    ilvector2nVector = {ilv0, ilv1, ilv2};
    {
        Element ilva(ildcrtparams);

        EXPECT_EQ(Format::EVALUATION, ilva.GetFormat()) << msg << " Failure: ilva format";
        EXPECT_EQ(modulus, ilva.GetModulus()) << msg << " Failure: ilva modulus";
        EXPECT_EQ(m, ilva.GetCyclotomicOrder()) << msg << " Failure: ilva cyclotomicOrder";
        EXPECT_EQ(towersize, ilva.GetNumOfElements()) << msg << " Failure: ilva number of elements";
    }

    Element ilva(ilvector2nVector);

    {
        Element ilva1(ilva);
        EXPECT_TRUE(ilva == ilva1) << msg << " Failure: ilva CTOR";
    }

    {
        Element ilva1 = ilva;
        EXPECT_EQ(ilva, ilva1) << msg << " Failure: ilva operator=";
    }

    {
        Element ilva1(ildcrtparams);
        ilva1 = {2, 4, 3, 2};
        EXPECT_EQ(ilva, ilva1) << msg << " Failure: ilva CTOR(params)";
    }

    {
        NativePoly ilvect0(ilparams0);
        NativeVector bbv1(m / 2, moduli[0]);
        bbv1 = {"2", "1", "3", "2"};
        ilvect0.SetValues(bbv1, Format::EVALUATION);

        NativePoly ilvect1(ilvect0);
        ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1], 0, 0);

        NativePoly ilvect2(ilvect0);
        ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2], 0, 0);

        std::vector<NativePoly> ilvector2nVector1(towersize);
        ilvector2nVector1 = {ilvect0, ilvect1, ilvect2};

        Element ilva1(ilvector2nVector1);

        EXPECT_TRUE(ilva != ilva1) << msg << " Failure: ilva operator!=";
    }
}

TEST(UTDCRTPoly, DCRT_getters_and_ops) {
    RUN_BIG_DCRTPOLYS(DCRT_getters_and_ops, "DCRT getters_and_ops");
}

template <typename Element>
void DCRT_arithmetic_ops_element(const std::string& msg) {
    uint32_t m         = 8;
    uint32_t towersize = 3;

    std::vector<NativeInteger> moduli(towersize);
    moduli = {NativeInteger("8353"), NativeInteger("8369"), NativeInteger("8513")};
    std::vector<NativeInteger> rootsOfUnity(towersize);
    rootsOfUnity = {NativeInteger("8163"), NativeInteger("6677"), NativeInteger("156")};

    typename Element::Integer modulus(1);
    for (uint32_t i = 0; i < towersize; ++i) {
        modulus = modulus * typename Element::Integer(moduli[i].ConvertToInt());
    }

    auto ilparams0 = std::make_shared<ILNativeParams>(m, moduli[0], rootsOfUnity[0]);
    auto ilparams1 = std::make_shared<ILNativeParams>(m, moduli[1], rootsOfUnity[1]);
    auto ilparams2 = std::make_shared<ILNativeParams>(m, moduli[2], rootsOfUnity[2]);

    NativePoly ilv0(ilparams0);
    NativeVector bbv0(m / 2, moduli[0]);
    bbv0 = {"2", "4", "3", "2"};
    ilv0.SetValues(bbv0, Format::EVALUATION);

    NativePoly ilv1(ilv0);
    ilv1.SwitchModulus(moduli[1], rootsOfUnity[1], 0, 0);

    NativePoly ilv2(ilv0);
    ilv2.SwitchModulus(moduli[2], rootsOfUnity[2], 0, 0);

    auto ildcrtparams = std::make_shared<ILDCRTParams<typename Element::Integer>>(m, moduli, rootsOfUnity);

    std::vector<NativePoly> ilvector2nVector(towersize);
    ilvector2nVector[0] = ilv0;
    ilvector2nVector[1] = ilv1;
    ilvector2nVector[2] = ilv2;

    Element ilva(ilvector2nVector);

    NativePoly ilvect0(ilparams0);
    NativeVector bbv1(m / 2, moduli[0]);
    bbv1 = {"2", "1", "2", "0"};
    ilvect0.SetValues(bbv1, Format::EVALUATION);

    NativePoly ilvect1(ilvect0);
    ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1], 0, 0);

    NativePoly ilvect2(ilvect0);
    ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2], 0, 0);

    std::vector<NativePoly> ilvector2nVector1(towersize);
    ilvector2nVector1[0] = ilvect0;
    ilvector2nVector1[1] = ilvect1;
    ilvector2nVector1[2] = ilvect2;

    Element ilva1(ilvector2nVector1);

    // Plus method
    {
        Element ilvaCopy(ilva.Plus(ilva1));

        for (uint32_t i = 0; i < ilvaCopy.GetNumOfElements(); ++i) {
            NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
            NativeVector expected(4, ilv.GetModulus());
            expected = {"4", "5", "5", "2"};
            EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: Plus()";
        }
    }

    // operator+ (which is ModAdd)
    {
        Element ilvaCopy(ilva + ilva1);

        for (uint32_t i = 0; i < ilvaCopy.GetNumOfElements(); ++i) {
            NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
            NativeVector expected(4, ilv.GetModulus());
            expected = {"4", "5", "5", "2"};
            EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: +";
        }
    }

    // += (which is ModAddEq)
    {
        Element ilvaCopy(ilva);
        ilvaCopy += ilva1;

        for (uint32_t i = 0; i < ilvaCopy.GetNumOfElements(); ++i) {
            NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
            NativeVector expected(4, ilv.GetModulus());
            expected = {"4", "5", "5", "2"};
            EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: +=";
        }
    }

    {
        Element ilvaCopy(ilva.Minus(ilva1));
        for (uint32_t i = 0; i < ilvaCopy.GetNumOfElements(); ++i) {
            NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
            NativeVector expected(4, ilv.GetModulus());
            expected = {"0", "3", "1", "2"};
            EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: Minus";
        }
    }
    {
        Element ilvaResult(ilva);
        ilvaResult -= ilva1;
        for (uint32_t i = 0; i < ilvaResult.GetNumOfElements(); ++i) {
            NativePoly ilv = ilvaResult.GetElementAtIndex(i);
            NativeVector expected(4, ilv.GetModulus());
            expected = {"0", "3", "1", "2"};
            EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: -=";
        }
    }
    {
        Element ilvaResult(ilva.Times(ilva1));
        for (uint32_t i = 0; i < ilvaResult.GetNumOfElements(); ++i) {
            NativePoly ilv = ilvaResult.GetElementAtIndex(i);
            NativeVector expected(4, ilv.GetModulus());
            expected = {"4", "4", "6", "0"};
            EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: Times()";
        }
    }
    {
        Element ilvaCopy(ilva);
        ilvaCopy.AddILElementOne();

        for (uint32_t i = 0; i < ilvaCopy.GetNumOfElements(); ++i) {
            NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
            NativeVector expected(4, ilv.GetModulus());
            expected = {"3", "5", "4", "3"};
            EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: AddILElementOne";
        }
    }

    {
        Element ilvaInv(ilva.MultiplicativeInverse());

        NativePoly ilvectInv0 = ilvaInv.GetElementAtIndex(0);
        // TODO: SHOULD BE ABLE TO SAY NativePoly ilvectInv0 = ilvaInv[0];
        NativePoly ilvectInv1 = ilvaInv.GetElementAtIndex(1);
        NativePoly ilvectInv2 = ilvaInv.GetElementAtIndex(2);
        NativeVector expected0(4, ilvectInv0.GetModulus());
        expected0 = {"4177", "6265", "5569", "4177"};
        EXPECT_EQ(expected0, ilvectInv0.GetValues()) << msg << " Failure: ilvectInv0 MultiplicativeInverse()";
        EXPECT_EQ(NativeInteger("8353"), ilvectInv0.GetModulus())
            << msg << " Failure: ilvectInv0 MultiplicativeInverse() modulus";
        EXPECT_EQ(NativeInteger("8163"), ilvectInv0.GetRootOfUnity())
            << msg << " Failure: ilvectInv0 MultiplicativeInverse() rootOfUnity";

        NativeVector expected1(4, ilvectInv1.GetModulus());
        expected1 = {"4185", "6277", "2790", "4185"};
        EXPECT_EQ(expected1, ilvectInv1.GetValues()) << msg << " Failure: ilvectInv1 MultiplicativeInverse()";
        EXPECT_EQ(NativeInteger("8369"), ilvectInv1.GetModulus())
            << msg << " Failure: ilvectInv1 MultiplicativeInverse() modulus";
        EXPECT_EQ(NativeInteger("6677"), ilvectInv1.GetRootOfUnity())
            << msg << " Failure: ilvectInv1 MultiplicativeInverse() rootOfUnity";

        NativeVector expected2(4, ilvectInv2.GetModulus());
        expected2 = {"4257", "6385", "2838", "4257"};
        EXPECT_EQ(expected2, ilvectInv2.GetValues()) << msg << " Failure: ilvectInv2 MultiplicativeInverse()";
        EXPECT_EQ(NativeInteger("8513"), ilvectInv2.GetModulus())
            << msg << " Failure: ilvectInv2 MultiplicativeInverse() modulus";
        EXPECT_EQ(NativeInteger("156"), ilvectInv2.GetRootOfUnity())
            << msg << " Failure: ilvectInv2 MultiplicativeInverse() rootOfUnity";
        EXPECT_THROW(ilva1.MultiplicativeInverse(), OpenFHEException)
            << msg << " Failure: throw MultiplicativeInverse()";
    }

    // DCRTPoly::MakeSparse() Only used by RingSwitching, which is no longer supported
    if (false) {
        Element ilvaCopy(ilva);

        ilvaCopy.MakeSparse(2);

        for (uint32_t i = 0; i < ilvaCopy.GetNumOfElements(); ++i) {
            NativePoly ilv = ilvaCopy.GetElementAtIndex(i);

            EXPECT_EQ(NativeInteger(0), ilv.at(1)) << msg << " Failure MakeSparse() index 1";
            EXPECT_EQ(NativeInteger(0), ilv.at(3)) << msg << " Failure MakeSparse() index 3";
        }
    }

    {
        EXPECT_TRUE(ilva.InverseExists()) << msg << " Failure: ilva.InverseExists()";
        EXPECT_FALSE(ilva1.InverseExists()) << msg << " Failure: ilva1.InverseExists()";
    }

    // this case is NOT used because SwitchModulus is not really defined for an
    // DCRTPoly, so...
    if (false) {
        NativePoly ilvS0(ilparams0);
        NativeVector bbvS0(m / 2, moduli[0]);
        bbvS0 = {"23462", "467986", "33863", "2113"};
        ilvS0.SetValues(bbvS0, Format::EVALUATION);

        NativePoly ilvS1(ilvS0);
        NativePoly ilvS2(ilvS0);

        ilvS0.SwitchModulus(moduli[0], rootsOfUnity[0], 0, 0);
        ilvS1.SwitchModulus(moduli[1], rootsOfUnity[1], 0, 0);
        ilvS2.SwitchModulus(moduli[2], rootsOfUnity[2], 0, 0);

        std::vector<NativePoly> ilvector2nVectorS(towersize);
        ilvector2nVectorS[0] = ilvS0;
        ilvector2nVectorS[1] = ilvS1;
        ilvector2nVectorS[2] = ilvS2;

        Element ilvaS(ilvector2nVectorS);
        typename Element::Integer modulus2("113");
        typename Element::Integer rootOfUnity2(lbcrypto::RootOfUnity<typename Element::Integer>(m, modulus2));

        ilvaS.SwitchModulus(modulus2, rootOfUnity2, 0, 0);

        NativePoly ilvectS0 = ilvaS.GetElementAtIndex(0);
        NativePoly ilvectS1 = ilvaS.GetElementAtIndex(1);
        NativePoly ilvectS2 = ilvaS.GetElementAtIndex(2);

        EXPECT_EQ(NativeInteger("80"), ilvectS0.at(0));
        EXPECT_EQ(NativeInteger("62"), ilvectS0.at(1));
        EXPECT_EQ(NativeInteger("85"), ilvectS0.at(2));
        EXPECT_EQ(NativeInteger("79"), ilvectS0.at(3));
        EXPECT_EQ(NativeInteger("113"), ilvectS0.GetModulus());
        EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS0.GetRootOfUnity().ConvertToInt());

        EXPECT_EQ(NativeInteger("66"), ilvectS1.at(0));
        EXPECT_EQ(NativeInteger("16"), ilvectS1.at(1));
        EXPECT_EQ(NativeInteger("64"), ilvectS1.at(2));
        EXPECT_EQ(NativeInteger("79"), ilvectS1.at(3));
        EXPECT_EQ(NativeInteger("113"), ilvectS1.GetModulus());
        EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS1.GetRootOfUnity().ConvertToInt());

        EXPECT_EQ(NativeInteger(4), ilvectS2.at(0));
        EXPECT_EQ(NativeInteger("44"), ilvectS2.at(1));
        EXPECT_EQ(NativeInteger("84"), ilvectS2.at(2));
        EXPECT_EQ(NativeInteger("79"), ilvectS2.at(3));
        EXPECT_EQ(NativeInteger("113"), ilvectS2.GetModulus());
        EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS2.GetRootOfUnity().ConvertToInt());
    }

    {
        Element ilvaCopy(ilva);
        typename Element::Integer modulus2("113");
        typename Element::Integer rootOfUnity2(lbcrypto::RootOfUnity<typename Element::Integer>(m, modulus2));
        ilvaCopy.SwitchModulusAtIndex(0, modulus2, rootOfUnity2);

        for (uint32_t i = 0; i < ilvaCopy.GetNumOfElements(); ++i) {
            NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
            NativeVector expected(4, ilv.GetModulus());
            expected = {"2", "4", "3", "2"};
            EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: ilv.SwitchModulusAtIndex";

            if (i == 0) {
                EXPECT_EQ(modulus2.ConvertToInt(), ilv.GetModulus().ConvertToInt())
                    << msg << " Failure: SwitchModulusAtIndex modulus";
                EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilv.GetRootOfUnity().ConvertToInt())
                    << msg << " Failure: SwitchModulusAtIndex rootOfUnity";
            }
        }
    }
}

TEST(UTDCRTPoly, DCRT_arithmetic_ops_element) {
    RUN_BIG_DCRTPOLYS(DCRT_arithmetic_ops_element, "DCRT_arithmetic_ops_element");
}

template <typename Element>
void DCRT_mod_ops_on_two_elements(const std::string& msg) {
    uint32_t order     = 16;
    uint32_t nBits     = 24;
    uint32_t towersize = 3;

    auto ildcrtparams = std::make_shared<ILDCRTParams<typename Element::Integer>>(order, towersize, nBits);

    typename Element::DugType dug;

    Element op1(dug, ildcrtparams);
    Element op2(dug, ildcrtparams);

    {
        Element sum = op1 + op2;

        for (uint32_t i = 0; i < towersize; i++) {
            for (uint32_t j = 0; j < ildcrtparams->GetRingDimension(); j++) {
                NativeInteger actualResult(sum.GetElementAtIndex(i).at(j));
                NativeInteger expectedResult((op1.GetElementAtIndex(i).at(j) + op2.GetElementAtIndex(i).at(j))
                                                 .Mod(ildcrtparams->GetParams()[i]->GetModulus()));
                EXPECT_EQ(actualResult, expectedResult)
                    << msg << " Failure: DCRTPoly + operation tower " << i << " index " << j;
            }
        }
    }

    {
        Element prod = op1 * op2;

        for (uint32_t i = 0; i < towersize; i++) {
            for (uint32_t j = 0; j < ildcrtparams->GetRingDimension(); j++) {
                NativeInteger actualResult(prod.GetElementAtIndex(i).at(j));
                NativeInteger expectedResult((op1.GetElementAtIndex(i).at(j) * op2.GetElementAtIndex(i).at(j))
                                                 .Mod(ildcrtparams->GetParams()[i]->GetModulus()));
                EXPECT_EQ(actualResult, expectedResult)
                    << msg << " Failure: DCRTPoly * operation tower " << i << " index " << j;
            }
        }
    }
}

TEST(UTDCRTPoly, DCRT_mod_ops_on_two_elements) {
    RUN_BIG_DCRTPOLYS(DCRT_mod_ops_on_two_elements, "DCRT DCRT_mod_ops_on_two_elements");
}

// only need to try this with one
void testDCRTPolyConstructorNegative(std::vector<NativePoly>& towers) {
    DCRTPoly expectException(towers);
}
