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
  This file contains google test code that exercises the big int vector library of the OpenFHE lattice encryption library.
 */

#include "config_core.h"
#ifdef WITH_BE4

    #include <fstream>
    #include <iostream>
    #include "gtest/gtest.h"

    #include "lattice/lat-hal.h"
    #include "math/math-hal.h"
    #include "math/nbtheory.h"
    #include "utils/inttypes.h"

    #include "math/distrgen.h"
    #include "utils/utilities.h"

using namespace lbcrypto;

/************************************************
 *  TESTING BASIC METHODS OF mubintvec CLASS
 ************************************************/
TEST(UTmubintvec, ctor_access_eq_neq) {
    OPENFHE_DEBUG_FLAG(false);
    // a bigger number
    bigintdyn::xubint q("1234567");

    // calling constructor to create a vector of length 5
    bigintdyn::xmubintvec m(5);
    // note all values are zero.

    m.SetModulus(q);

    bigintdyn::xmubintvec n(5, q);  // calling contructor with modulus

    EXPECT_EQ(5U, m.GetLength()) << "Failure in GetLength()";
    EXPECT_EQ(5U, n.GetLength()) << "Failure in GetLength()";

    // Old fashioned soon to be deprecated way of
    // setting value of the value at different index locations

    // test at(string)
    m.at(0) = "9868";
    m.at(1) = "5879";
    m.at(2) = "4554";
    m.at(3) = "2343";
    m.at(4) = "4624";

    OPENFHE_DEBUG("m " << m);
    EXPECT_EQ(9868U, m.at(0).ConvertToInt<uint32_t>()) << "Failure in at(0)";

    // old fashioned way of expect
    EXPECT_EQ(9868U, m.at(0).ConvertToInt<uint32_t>()) << "Failure in at(str)";
    EXPECT_EQ(5879U, m.at(1).ConvertToInt<uint32_t>()) << "Failure in at(str)";
    EXPECT_EQ(4554U, m.at(2).ConvertToInt<uint32_t>()) << "Failure in at(str)";
    EXPECT_EQ(2343U, m.at(3).ConvertToInt<uint32_t>()) << "Failure in at(str)";
    EXPECT_EQ(4624U, m.at(4).ConvertToInt<uint32_t>()) << "Failure in at(str)";

    EXPECT_EQ(bigintdyn::xubint(9868U), m.at(0)) << "Failure in at()";
    EXPECT_EQ(bigintdyn::xubint(5879U), m.at(1)) << "Failure in at()";
    EXPECT_EQ(bigintdyn::xubint(4554U), m.at(2)) << "Failure in at()";
    EXPECT_EQ(bigintdyn::xubint(2343U), m.at(3)) << "Failure in at()";
    EXPECT_EQ(bigintdyn::xubint(4624U), m.at(4)) << "Failure in at()";

    // new way of setting value of the value at different index locations
    n[0] = "4";
    n[1] = 9;                        // int (implied)
    n[2] = bigintdyn::xubint("66");  // bigintdyn::xubint
    n[3] = 33L;                      // long
    n[4] = 7UL;                      // unsigned long

    // new way of accessing
    EXPECT_EQ(bigintdyn::xubint(4), n[0]) << "Failure in []";
    EXPECT_EQ(bigintdyn::xubint(9), n[1]) << "Failure in []";
    EXPECT_EQ(bigintdyn::xubint(66), n[2]) << "Failure in []";
    EXPECT_EQ(bigintdyn::xubint(33), n[3]) << "Failure in []";
    EXPECT_EQ(bigintdyn::xubint(7), n[4]) << "Failure in []";

    // test at(bigintdyn::xubint)
    n.at(0) = bigintdyn::xubint("4");
    n.at(1) = bigintdyn::xubint("9");
    n.at(2) = bigintdyn::xubint("66");
    n.at(3) = bigintdyn::xubint("33");
    n.at(4) = bigintdyn::xubint("7");

    EXPECT_EQ(bigintdyn::xubint(4), n[0]) << "Failure in at(bigintdyn::xubint)";
    EXPECT_EQ(bigintdyn::xubint(9), n[1]) << "Failure in at(bigintdyn::xubint)";
    EXPECT_EQ(bigintdyn::xubint(66), n[2]) << "Failure in at(bigintdyn::xubint)";
    EXPECT_EQ(bigintdyn::xubint(33), n[3]) << "Failure in at(bigintdyn::xubint)";
    EXPECT_EQ(bigintdyn::xubint(7), n[4]) << "Failure in at(bigintdyn::xubint)";

    m += n;

    usint expectedResult[5] = {9872, 5888, 4620, 2376, 4631};

    for (usint i = 0; i < 5; ++i) {
        EXPECT_EQ(expectedResult[i], (m.at(i)).ConvertToInt<uint32_t>()) << "Failure testing method_add_equals";
    }

    // test initializer list of various types
    bigintdyn::xmubintvec expectedvecstr(5);
    expectedvecstr = {"9872", "5888", "4620", "2376", "4631"};  // strings
    expectedvecstr.SetModulus(q);
    EXPECT_EQ(expectedvecstr, m) << "Failure string initializer list";

    bigintdyn::xmubintvec expectedvecint(5);
    expectedvecint.SetModulus(q);

    //  expectedvecint =
    //  {bigintdyn::xubint(9872U),bigintdyn::xubint(5888U),bigintdyn::xubint(4620U),bigintdyn::xubint(2376U),bigintdyn::xubint(4631U)};
    //  //ubints
    //  EXPECT_EQ (expectedvecint, m)<< "Failure bigintdyn::xubint initializer
    //  list";

    expectedvecint = {9872ULL, 5888ULL, 4620ULL, 2376ULL, 4631ULL};  // usints
    EXPECT_EQ(expectedvecint, m) << "Failure usint initializer list";

    expectedvecint = {9872, 5888, 4620, 2376, 4631};  // ints (compiler promotes)
    EXPECT_EQ(expectedvecint, m) << "Failure int initializer list";

    // test Single()
    bigintdyn::xmubintvec s =
        bigintdyn::xmubintvec::Single(bigintdyn::xubint("3"), bigintdyn::xubint("5"));  // value 3, mod 5
    EXPECT_EQ(1U, s.GetLength()) << "Failure Single.GetLength()";
    EXPECT_EQ(bigintdyn::xubint(3), s[0]) << "Failure Single() value";

    // test assignment of single bigintdyn::xubint (puts it in the 0 the
    // position), zeros out the rest
    // test that the vector is zeroed on init like this.
    bigintdyn::xmubintvec eqtest(10);
    EXPECT_EQ(10U, eqtest.GetLength()) << "Failure create bigintdyn::xmubintvec of 10 zeros";

    for (usint i = 0; i < eqtest.GetLength(); ++i) {
        EXPECT_EQ(bigintdyn::xubint(0U), eqtest[i]) << "Failure create bigintdyn::xmubintvec of zeros";
    }

    // test assignment of single bigintdyn::xubint
    eqtest = bigintdyn::xubint(1);
    EXPECT_EQ(bigintdyn::xubint(1), eqtest[0]) << "Failure assign single bigintdyn::xubint 0 index";
    for (usint i = 1; i < eqtest.GetLength(); i++) {
        EXPECT_EQ(bigintdyn::xubint(0U), eqtest[i]) << "Failure assign single bigintdyn::xubint nonzero index";
    }

    // test assignment of single usint
    eqtest = 5U;
    EXPECT_EQ(bigintdyn::xubint(5U), eqtest[0]) << "Failure assign single bigintdyn::xubint 0 index";
    for (usint i = 1; i < eqtest.GetLength(); ++i) {
        EXPECT_EQ(bigintdyn::xubint(0U), eqtest[i]) << "Failure assign single bigintdyn::xubint nonzero index";
    }

    // test comparisons == and !=
    m          = n;
    bool test1 = m == n;
    bool test2 = m != n;
    EXPECT_TRUE(test1) << "Failure ==";
    EXPECT_FALSE(test2) << "Failure !=";

    n.SetModulus(bigintdyn::xubint(n.GetModulus() + bigintdyn::xubint(1)));
    // reset n to a different modulus, comparison will fail.
    test1 = m == n;
    test2 = m != n;
    EXPECT_FALSE(test1) << "Failure == different mods";
    EXPECT_TRUE(test2) << "Failure != different mods";

    // set it back
    n.SetModulus(n.GetModulus() - bigintdyn::xubint(1));
    m     = n + n;
    test1 = m == n;
    test2 = m != n;
    EXPECT_FALSE(test1) << "Failure ==";
    EXPECT_TRUE(test2) << "Failure !=";

    for (usint i = 0; i < m.GetLength(); ++i) {
        m[i] = n[i];  // test both lhs and rhs []
    }

    test1 = m == n;
    EXPECT_TRUE(test1) << "Failure [] lhs rhs";
}

TEST(UTmubintvec, constructorTest) {
    OPENFHE_DEBUG_FLAG(false);
    bigintdyn::xmubintvec m(10);

    m.at(0) = "48";
    m.at(1) = "53";
    m.at(2) = "7";
    m.at(3) = "178";
    m.at(4) = "190";
    m.at(5) = "120";
    m.at(6) = "79";
    m.at(7) = "108";
    m.at(8) = "60";
    m.at(9) = "12";

    OPENFHE_DEBUG("m: " << m);

    uint64_t expectedResult[10] = {48,  53, 7,   178, 190,
                                   120, 79, 108, 60,  12};  // the expected values are stored as one dimensional
                                                            // integer array

    for (usint i = 0; i < 10; i++) {
        OPENFHE_DEBUG("val " << i << " is " << m.at(i));
        EXPECT_EQ(expectedResult[i], (m.at(i)).ConvertToInt());
    }

    bigintdyn::xmubintvec binvect(m);

    for (usint i = 0; i < 10; i++) {
        EXPECT_EQ(expectedResult[i], (binvect.at(i)).ConvertToInt());
    }
}

TEST(UTmubintvec, mod) {
    bigintdyn::xmubintvec m(10);  // calling constructor to create a vector of length 10 zeroed

    // setting value of the value at different index locations
    m.at(0) = "987968";
    m.at(1) = "587679";
    m.at(2) = "456454";
    m.at(3) = "234343";
    m.at(4) = "769789";
    m.at(5) = "465654";
    m.at(6) = "79";
    m.at(7) = "346346";
    m.at(8) = "325328";
    m.at(9) = "7698798";

    bigintdyn::xubint q("233");  // calling costructor of bigintdyn::xubint Class
                                 // to create object for modulus
    // set modulus
    m.SetModulus(q);  // should take modulus as well.

    bigintdyn::xmubintvec calculatedResult = m.Mod(q);
    // the expected values are stored as one dimensional integer array
    usint expectedResult[10] = {48, 53, 7, 178, 190, 120, 79, 108, 60, 12};

    for (size_t i = 0; i < 10; i++) {
        EXPECT_EQ(expectedResult[i], calculatedResult[i].ConvertToInt<uint32_t>());
    }
}

TEST(UTmubintvec, basic_vector_vector_mod_math_1_limb) {
    OPENFHE_DEBUG_FLAG(false);

    // q1 modulus 1:
    bigintdyn::xubint q1("163841");
    // a1:
    bigintdyn::xmubintvec a1(16, q1);
    OPENFHE_DEBUG("a1.modulus " << a1.GetModulus());
    a1 = {
        "127753", "077706", "017133", "022582", "112132", "027625", "126773", "008924",
        "125972", "002551", "113837", "112045", "100953", "077352", "132013", "057029",
    };

    // b1:
    bigintdyn::xmubintvec b1;
    b1.SetModulus(q1);
    OPENFHE_DEBUG("b1.modulus " << b1.GetModulus());

    b1 = {
        "066773", "069572", "142134", "141115", "123182", "155822", "128147", "094818",
        "135782", "030844", "088634", "099407", "053647", "111689", "028502", "026401",
    };

    // modadd1:
    bigintdyn::xmubintvec modadd1;
    modadd1 = {
        "030685", "147278", "159267", "163697", "071473", "019606", "091079", "103742",
        "097913", "033395", "038630", "047611", "154600", "025200", "160515", "083430",
    };

    modadd1.SetModulus(a1);  // sets modadd1.modulus to the same as a1
    OPENFHE_DEBUG("modadd1.modulus " << modadd1.GetModulus());

    // modsub1:
    std::vector<std::string> modsub1sv = {
        "060980", "008134", "038840", "045308", "152791", "035644", "162467", "077947",
        "154031", "135548", "025203", "012638", "047306", "129504", "103511", "030628",
    };
    bigintdyn::xmubintvec modsub1(modsub1sv, q1);

    // modmul1:
    std::vector<std::string> modmul1sv = {
        "069404", "064196", "013039", "115321", "028519", "151998", "089117", "080908",
        "057386", "039364", "008355", "146135", "061336", "031598", "025961", "087680",
    };
    bigintdyn::xmubintvec modmul1(modmul1sv, q1);

    bigintdyn::xmubintvec c1;
    bigintdyn::xmubintvec d1;

    // now Mod operations
    c1 = a1.ModAdd(b1);
    EXPECT_EQ(c1, modadd1) << "Failure 1 limb vector vector ModAdd()";

    OPENFHE_DEBUG("modadd1 modulus" << modadd1.GetModulus());
    OPENFHE_DEBUG("c1 modulus" << c1.GetModulus());
    OPENFHE_DEBUG("c1 " << c1 << " modadd " << modadd1);

    c1 = a1 + b1;
    EXPECT_EQ(c1, modadd1) << "Failure 1 limb vector vector +";

    d1 = a1;
    d1 += b1;
    EXPECT_EQ(d1, modadd1) << "Failure 1 limb vector vector +=";

    c1 = a1.ModSub(b1);
    EXPECT_EQ(c1, modsub1) << "Failure 1 limb vector vector ModSub()";

    c1 = a1 - b1;
    EXPECT_EQ(c1, modsub1) << "Failure 1 limb vector vector -";

    d1 = a1;
    d1 -= b1;
    EXPECT_EQ(d1, modsub1) << "Failure 1 limb vector vector -=";

    c1 = a1.ModMul(b1);
    EXPECT_EQ(c1, modmul1) << "Failure 1 limb vector vector ModMul()";
    c1 = a1 * b1;
    EXPECT_EQ(c1, modmul1) << "Failure 1 limb vector vector *";

    d1 = a1;
    d1 *= b1;
    EXPECT_EQ(d1, modmul1) << "Failure 1 limb vector vector *=";
}
TEST(UTmubintvec, basic_vector_scalar_mod_math_2_limb) {
    // basic vector scalar mod math
    // todo this is very simple, should probably add sub mul by bigger numbers.

    // q2:
    bigintdyn::xubint q2("4057816419532801");
    // a2:
    std::vector<std::string> a2sv = {
        "0185225172798255", "0098879665709163", "3497410031351258", "4012431933509255",
        "1543020758028581", "0135094568432141", "3976954337141739", "4030348521557120",
        "0175940803531155", "0435236277692967", "3304652649070144", "2032520019613814",
        "0375749152798379", "3933203511673255", "2293434116159938", "1201413067178193",
    };

    bigintdyn::xmubintvec a2(a2sv, q2);
    bigintdyn::xmubintvec a2op1(a2.GetLength(), q2);
    bigintdyn::xmubintvec a2op1test(a2.GetLength(), q2);

    bigintdyn::xubint myone(1);

    for (usint i = 0; i < a2.GetLength(); i++) {
        a2op1[i] = a2[i] + myone;
        a2op1[i] %= q2;
    }
    a2op1test = a2.ModAdd(myone);
    EXPECT_EQ(a2op1, a2op1test) << "Failure vector scalar ModAdd()";

    for (usint i = 0; i < a2.GetLength(); i++) {
        a2op1[i] = a2[i] - myone;
        a2op1[i] %= q2;
    }
    a2op1test = a2.ModSub(myone);
    EXPECT_EQ(a2op1, a2op1test) << "Failure vector scalar ModSub()";

    for (usint i = 0; i < a2.GetLength(); i++) {
        a2op1[i] = a2[i] * myone;
        a2op1[i] %= q2;
    }
    a2op1test = a2.ModMul(myone);
    EXPECT_EQ(a2op1, a2op1test) << "Failure vector scalar ModMul()";
}

TEST(UTmubintvec, basic_vector_vector_mod_math_2_limb) {
    // q2 modulus 2:
    bigintdyn::xubint q2("4057816419532801");
    // a2:
    std::vector<std::string> a2sv = {
        "0185225172798255", "0098879665709163", "3497410031351258", "4012431933509255",
        "1543020758028581", "0135094568432141", "3976954337141739", "4030348521557120",
        "0175940803531155", "0435236277692967", "3304652649070144", "2032520019613814",
        "0375749152798379", "3933203511673255", "2293434116159938", "1201413067178193",
    };
    bigintdyn::xmubintvec a2(a2sv, q2);

    // b2:
    std::vector<std::string> b2sv = {
        "0698898215124963", "0039832572186149", "1835473200214782", "1041547470449968",
        "1076152419903743", "0433588874877196", "2336100673132075", "2990190360138614",
        "0754647536064726", "0702097990733190", "2102063768035483", "0119786389165930",
        "3976652902630043", "3238750424196678", "2978742255253796", "2124827461185795",
    };

    bigintdyn::xmubintvec b2(b2sv, q2);

    // modadd2:
    std::vector<std::string> modadd2sv = {
        "0884123387923218", "0138712237895312", "1275066812033239", "0996162984426422",
        "2619173177932324", "0568683443309337", "2255238590741013", "2962722462162933",
        "0930588339595881", "1137334268426157", "1348899997572826", "2152306408779744",
        "0294585635895621", "3114137516337132", "1214359951880933", "3326240528363988",
    };
    bigintdyn::xmubintvec modadd2(modadd2sv, q2);

    // modsub2:
    std::vector<std::string> modsub2sv = {
        "3544143377206093", "0059047093523014", "1661936831136476", "2970884463059287",
        "0466868338124838", "3759322113087746", "1640853664009664", "1040158161418506",
        "3479109686999230", "3790954706492578", "1202588881034661", "1912733630447884",
        "0456912669701137", "0694453087476577", "3372508280438943", "3134402025525199",
    };
    bigintdyn::xmubintvec modsub2(modsub2sv, q2);

    // modmul2:
    std::vector<std::string> modmul2sv = {
        "0585473140075497", "3637571624495703", "1216097920193708", "1363577444007558",
        "0694070384788800", "2378590980295187", "0903406520872185", "0559510929662332",
        "0322863634303789", "1685429502680940", "1715852907773825", "2521152917532260",
        "0781959737898673", "2334258943108700", "2573793300043944", "1273980645866111",
    };
    bigintdyn::xmubintvec modmul2(modmul2sv, q2);

    bigintdyn::xmubintvec c2;
    bigintdyn::xmubintvec d2;

    // now Mod operations
    c2 = a2.ModAdd(b2);
    EXPECT_EQ(c2, modadd2) << "Failure 2 limb vector vector ModAdd()";

    c2 = a2 + b2;
    EXPECT_EQ(c2, modadd2) << "Failure 2 limb vector vector +";

    d2 = a2;
    d2 += b2;
    EXPECT_EQ(d2, modadd2) << "Failure 2 limb vector vector +=";

    c2 = a2.ModSub(b2);
    EXPECT_EQ(c2, modsub2) << "Failure 2 limb vector vector ModSub()";

    c2 = a2 - b2;
    EXPECT_EQ(c2, modsub2) << "Failure 2 limb vector vector -";

    d2 = a2;
    d2 -= b2;
    EXPECT_EQ(d2, modsub2) << "Failure 2 limb vector vector -=";

    c2 = a2.ModMul(b2);
    EXPECT_EQ(c2, modmul2) << "Failure 2 limb vector vector ModMul()";

    c2 = a2 * b2;
    EXPECT_EQ(c2, modmul2) << "Failure 2 limb vector vector *";

    d2 = a2;
    d2 *= b2;
    EXPECT_EQ(d2, modmul2) << "Failure 2 limb vector vector *=";
}

TEST(UTmubintvec, basic_vector_vector_mod_math_big_numbers) {
    // q3:
    bigintdyn::xubint q3(
        "327339060789614187001318969682759915221664204604306478948329136809613379"
        "640467455488327009232590415715088668412756007100921725654588539305332852"
        "7589431");
    bigintdyn::xmubintvec a3;
    a3 = {
        "225900248779616490466577212189407858454340174415515429831272620924775168"
        "917218925565386635596420076848457541897386430736475723794694073374744664"
        "3725054",
        "147874381630800973466899287363338011091215980339799901595521201997125323"
        "152858946678960307474601044419913242155559832908255705398624026507153764"
        "7362089",
        "244225076656133434116682278367439513399555649531231801643114134874948273"
        "974978817417308131292727488014632998036342497756563800105684124567866178"
        "2610982",
        "917779106114096279364098211126816308037915672568153320523308800097705587"
        "686270523428976942621563981845568821206569141624247183330715577260930218"
        "556767",
        "214744931049447103852875386182628152420432967632133352449560778740158135"
        "437968557572597545037670326240142368149137864407874100658923913041236510"
        "842284",
        "302293102452655424148384130069043208311291201187071201820955225306834759"
        "262804310166292626381040137853241665577373849968102627833547035505519224"
        "0903881",
        "217787945810785525769991433173714489627467626905506243282655280886934812"
        "540767119958256354369228711471264229948214495931683561442667304898763469"
        "9368975",
        "297233451802123294436846683552230198845414118375785255038220841170372509"
        "047202030175469239142902723134737621108313142071558385068315554041062888"
        "072990"};
    a3.SetModulus(q3);

    bigintdyn::xmubintvec b3;
    b3.SetModulus(a3);
    b3 = {
        "174640495219258626838115152142237214318214552597783670042038223724040064"
        "288925129795441832567518442778934843362636945066989255720843940121510948"
        "9355089",
        "220598825371098531288665964851212313477741334812037568788443848101743931"
        "352326362481681721872150902208420539619641973896119680592696228972313317"
        "042316",
        "163640803586734778369958874046918235045216548674527720352542780797135206"
        "316962206648897722950642085601703148269143908928802026200674823395417766"
        "9740311",
        "139186068174349558644651864688393305168565871835272263369428575847412480"
        "384747334906466055561884795171951026382969929229711913192643604521436425"
        "2430665",
        "840450278810654165061961485691366961514650606247291814263792869596294713"
        "810125269780258316551932763106025157596216051681623225968811609560121609"
        "943365",
        "232973186215009491235578658370287843476643614073859427486789149471300253"
        "408565273192088889150752235586797479161968667357492813737646810383958692"
        "1126803",
        "305947231662739654827190605151766588770023419265248863943743125469728517"
        "048418945877016815280052070202031309123443780623620419652619345575011736"
        "3744648",
        "132216870748476988853044482759545262615616157934129470128771906579101230"
        "690441206392939162889560305016204867157725209170345968349185675785497832"
        "527174"};

    bigintdyn::xmubintvec modadd3;
    modadd3.SetModulus(a3);
    modadd3 = {
        "732016832092609303033733946488851575508905224089926209249817078392018535"
        "656765998725014589313481039123037168472673687025432538609494741909227605"
        "490712",
        "169934264167910826595765883848459242438990113821003658474365586807299716"
        "288091582927128479661816134640755296117524030297867673457893649404385096"
        "4404405",
        "805268194532540254853221827315978332231079936014530430473277788624701006"
        "514735685778788450107791579012474778927303995844441006517704086579510924"
        "761862",
        "230963978785759186581061685801074935972357439092087595421759455857183039"
        "153374387249363749824041193356507908503626843392136631525715162247529447"
        "0987432",
        "105519520986010126891483687187399511393508357387942516671335364833645284"
        "924809382735285586158960308934616752574535391608949732662773552260135812"
        "0785649",
        "207927227878050728382643818756571136566270610656624150359415237968521633"
        "030902127870054506299201957724950476326586510224673715916605306584145063"
        "4441253",
        "196396116683910993595863068642721163175826841566448628278069269547049949"
        "948718610346946160416690365958206870658902269454382255440698111168442353"
        "5524192",
        "429450322550600283289891166311775461461030276309914725166992747749473739"
        "737643236568408402032463028150942488266038351241904353417501229826560720"
        "600164",
    };

    bigintdyn::xmubintvec modsub3;
    modsub3.SetModulus(a3);
    modsub3 = {
        "512597535603578636284620600471706441361256218177317597892343972007351046"
        "282937957699448030289016340695226985347494856694864680738501332532337154"
        "369965",
        "125814499093691120338032690878216779743441846858596144716676817186950930"
        "017626310430792135287385954199071188193595635518643737339354403609922433"
        "0319773",
        "805842730693986557467234043205212783543391008567040812905713540778130676"
        "580166107684104083420854024129298497671985888277617739050093011724484112"
        "870671",
        "279930903226674256293076926107048240856889900025849547631231440971971458"
        "024347172924758647932862018727694524150442992033634530795016492509989449"
        "3715533",
        "264768526013493480880410359731886034312242440742790632766905927723999721"
        "803251784267560932081164172028500389468048188373546813123599769653444342"
        "8488350",
        "693199162376459329128054716987553648346475871132117743341660758355345058"
        "542390369742037372302879022664441864154051826106098140959002251215605319"
        "777078",
        "239179774937660057944119797704707816079108412244563858287241292226819675"
        "132815629569566548321767056984321589237526722408984867444636498629084586"
        "3213758",
        "165016581053646305583802200792684936229797960441655784909448934591271278"
        "356760823782530076253342418118532753950587932901212416719129878255565055"
        "545816",
    };

    bigintdyn::xmubintvec modmul3;
    modmul3.SetModulus(a3);
    modmul3 = {
        "103105474514584305682070594578091411828214431081734131021002064062543199"
        "859194040323354510935027293386806050940515736000038934510137289882203635"
        "9679625",
        "398939903363276547750862012224727493964400316336891077935622928183415590"
        "915516500989491410274123740312316424923905334367828029795276021286742965"
        "89001",
        "128157536467338078724788710077393334021754395081595358835203134035411001"
        "404034716438745017724614395885263614546637963247929653182803560261871694"
        "3463922",
        "887662687695833270748810935860224263697693264279486582140404211021156292"
        "460539799921705475485984353404390294379189297326940425588139558557740202"
        "2234",
        "121622288690560069684657414574449533118979023028605797994286236697556812"
        "723191920412097631509792334907416137338053145833489496814685845920501903"
        "5261534",
        "753004725575957473234700352714317139479193934162886068369016394155680048"
        "439319699359431951178436867519868720662245420487511271148333130090416613"
        "227734",
        "278170041094772470035356848898777742997324683492034661632014395564524394"
        "988953631504335262863419941280679588304106553954968793753650103996193140"
        "1092055",
        "477574462920419903543345320561430691498452711801747910227743781056369739"
        "411065806345235440677935972019383967954633150768168291144898135169751571"
        "023658",
    };

    bigintdyn::xmubintvec c3;
    bigintdyn::xmubintvec d3;
    // now Mod operations
    c3 = a3.ModAdd(b3);
    EXPECT_EQ(c3, modadd3) << "Failure big number vector vector ModAdd()";

    c3 = a3 + b3;
    EXPECT_EQ(c3, modadd3) << "Failure big number vector vector +";

    d3 = a3;
    d3 += b3;
    EXPECT_EQ(d3, modadd3) << "Failure big number vector vector +=";

    c3 = a3.ModSub(b3);
    EXPECT_EQ(c3, modsub3) << "Failure big number vector vector ModSub()";

    c3 = a3 - b3;
    EXPECT_EQ(c3, modsub3) << "Failure big number vector vector -";

    d3 = a3;
    d3 -= b3;
    EXPECT_EQ(d3, modsub3) << "Failure big number vector vector -=";

    c3 = a3.ModMul(b3);
    EXPECT_EQ(c3, modmul3) << "Failure big number vector vector ModMul()";

    c3 = a3 * b3;
    EXPECT_EQ(c3, modmul3) << "Failure big number vector vector *";

    d3 = a3;
    d3 *= b3;
    EXPECT_EQ(d3, modmul3) << "Failure big number vector vector *=";
}

#endif
