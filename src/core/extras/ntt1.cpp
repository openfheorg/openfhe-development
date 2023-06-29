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
  Example of NTT operations
  This is a main() file built to test and time NTT operations. D. Cousins
 */

#define PROFILE  // need to define in order to turn on timing
#define TEST1
// #define TEST2
// #define TEST3

#include <chrono>
#include <exception>
#include <fstream>
#include <iostream>
#include <vector>
#include "openfhecore.h"
#include "time.h"

using namespace lbcrypto;

// define the main sections of the test
void test_NTT(void);  // test code

// main()   need this for Kurts' makefile to ignore this.
int main(int argc, char* argv[]) {
    test_NTT();
    return 0;
}

// Testing macro runs the desired code
// res = fn
// an a loop nloop times, timed with timer t with res compared to testval

#define TESTIT(t, res, fn, testval, nloop)                                                                  \
    do {                                                                                                    \
        try {                                                                                               \
            TIC(t);                                                                                         \
            for (usint j = 0; j < nloop; j++) {                                                             \
                res = (fn);                                                                                 \
            }                                                                                               \
            time2 = TOC(t);                                                                                 \
            OPENFHE_DEBUG(#t << ": " << nloop << " loops " << #res << " = " << #fn << " computation time: " \
                             << "\t" << time2 << " us");                                                    \
            if (res != testval) {                                                                           \
                std::cout << "Bad " << #res << " = " << #fn << std::endl;                                   \
                /*vec_diff(res, testval);*/                                                                 \
            }                                                                                               \
        }                                                                                                   \
        catch (exception & e) {                                                                             \
            std::cout << #res << " = " << #fn << " caught exception " << e.what() << std::endl;             \
        }                                                                                                   \
    } while (0);

// helper function that bulds BigVector from a vector of strings
BigVector BBVfromStrvec(std::vector<std::string>& s) {
    BigVector a(s.size());
    for (usint i = 0; i < s.size(); i++) {
        a[i] = s[i];
    }
    return a;
}

// function to compare two BigVectors and print differing indicies
void vec_diff(BigVector& a, BigVector& b) {
    for (usint i = 0; i < a.GetLength(); ++i) {
        if (a.at(i) != b.at(i)) {
            std::cout << "i: " << i << std::endl;
            std::cout << "first vector " << std::endl;
            std::cout << a.at(i);
            std::cout << std::endl;
            std::cout << "second vector " << std::endl;
            std::cout << b.at(i);
            std::cout << std::endl;
        }
    }
}

// function to compare two Poly and print differing values
bool clonetest(Poly& a, Poly& b, std::string name) {
    if (a != b) {
        std::cout << name << " FAILED " << std::endl;
        std::cout << "a:" << a << std::endl;
        std::cout << "b:" << b << std::endl;
        return true;
    }
    else {
        return false;
    }
}

// main NTT test suite.
void test_NTT() {
    // Code to test NTT at three different numbers of limbs.

    int nloop = 100;  // number of times to run each test for timing.

    TimeVar t1, t_total;  // timers for TIC() TOC()
    // captures the time
    double time1ar, time1af;
    double time2ar, time2af;
    double time3ar, time3af;

    double time1br, time1bf;
    double time2br, time2bf;
    double time3br, time3bf;

    std::cout << "testing NTT backend " << MATHBACKEND << std::endl;

    TIC(t_total);
    // there are three test cases, 1) small modulus 2) approx 48 bits.
    // 3) large numbers and two examples of each

    // note this fails BigInteger q1 = {"163841"};
    BigInteger q1("163841");

    // for each vector, define a, b inputs as vectors of strings
    std::vector<std::string> a1strvec = {
        "127753", "077706", "017133", "022582", "112132", "027625", "126773", "008924",
        "125972", "002551", "113837", "112045", "100953", "077352", "132013", "057029",
    };

    // this fails too!!! BigVector a1(a1string);
    // so I wrote this function
    BigVector a1 = BBVfromStrvec(a1strvec);
    a1.SetModulus(q1);

    // b:
    std::vector<std::string> b1strvec = {
        "066773", "069572", "142134", "141115", "123182", "155822", "128147", "094818",
        "135782", "030844", "088634", "099407", "053647", "111689", "028502", "026401",
    };

    BigVector b1 = BBVfromStrvec(b1strvec);
    b1.SetModulus(q1);

    // test case 2
    BigInteger q2("00004057816419532801");

    std::vector<std::string> a2strvec = {
        "00000185225172798255", "00000098879665709163", "00003497410031351258", "00004012431933509255",
        "00001543020758028581", "00000135094568432141", "00003976954337141739", "00004030348521557120",
        "00000175940803531155", "00000435236277692967", "00003304652649070144", "00002032520019613814",
        "00000375749152798379", "00003933203511673255", "00002293434116159938", "00001201413067178193",
    };

    BigVector a2 = BBVfromStrvec(a2strvec);
    a2.SetModulus(q2);

    std::vector<std::string> b2strvec = {
        "00000698898215124963", "00000039832572186149", "00001835473200214782", "00001041547470449968",
        "00001076152419903743", "00000433588874877196", "00002336100673132075", "00002990190360138614",
        "00000754647536064726", "00000702097990733190", "00002102063768035483", "00000119786389165930",
        "00003976652902630043", "00003238750424196678", "00002978742255253796", "00002124827461185795",
    };

    BigVector b2 = BBVfromStrvec(b2strvec);
    b2.SetModulus(q2);

    // test case 3

    // q3: very large numbers.
    BigInteger q3(
        "327339060789614187001318969682759915221664204604306478948329136809613379"
        "640467455488327009232590415715088668412756007100921725654588539305332852"
        "7589431");

    std::vector<std::string> a3strvec = {
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

    BigVector a3 = BBVfromStrvec(a3strvec);
    a3.SetModulus(q3);

    std::vector<std::string> b3strvec = {
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

    BigVector b3 = BBVfromStrvec(b3strvec);
    b3.SetModulus(q3);

#if 1
    usint m = 32;

    //  BigInteger modulus(q1);

    //  NextQ(modulus, BigInteger("2"), m1, BigInteger("4"), BigInteger("4"));
    #ifdef TEST1
    BigInteger rootOfUnity1(RootOfUnity<BigInteger>(m, q1));
    ILParams params1(m, q1, rootOfUnity1);
    auto x1p = std::make_shared<ILParams>(params1);

    Poly x1a(x1p, Format::COEFFICIENT);
    // a1.SetModulus(modulus); //note setting modulus does not perform a modulus.
    // a1.Mod(modulus);
    x1a.SetValues(a1, Format::COEFFICIENT);

    Poly x1b(x1p, Format::COEFFICIENT);
    // b1.SetModulus(modulus);
    // b1.Mod(modulus);
    x1b.SetValues(b1, Format::COEFFICIENT);

    Poly x1aClone(x1a);
    Poly x1bClone(x1b);
    #endif
    #ifdef TEST2
    BigInteger rootOfUnity2(RootOfUnity<BigInteger>(m, q2));
    ILParams params2(m, q2, rootOfUnity2);
    auto x2p = std::make_shared<ILParams>(params2);

    Poly x2a(x2p, Format::COEFFICIENT);
    // a2.SetModulus(modulus); //note setting modulus does not perform a modulus.
    // a2.Mod(modulus);
    x2a.SetValues(a2, Format::COEFFICIENT);

    Poly x2b(x2p, Format::COEFFICIENT);
    // b2.SetModulus(modulus);
    // b2.Mod(modulus);
    x2b.SetValues(b2, Format::COEFFICIENT);

    Poly x2aClone(x2a);
    Poly x2bClone(x2b);
    #endif
    #ifdef TEST3
    NextQ(q3, BigInteger("2"), m, BigInteger("4"), BigInteger("4"));
    std::cout << "q3 : " << q3.ToString() << std::endl;

    BigInteger rootOfUnity3(RootOfUnity<BigInteger>(m, q3));
    std::cout << "rootOfUnity3 : " << rootOfUnity3.ToString() << std::endl;
    ILParams params3(m, q3, rootOfUnity3);
    auto x3p = std::make_shared<ILParams>(params3);

    Poly x3a(x3p, Format::COEFFICIENT);
    // a3.SetModulus(modulus); //note setting modulus does not perform a modulus.
    // a3.Mod(modulus);
    x3a.SetValues(a3, Format::COEFFICIENT);

    Poly x3b(x3p, Format::COEFFICIENT);
    // b3.SetModulus(modulus);
    // b3.Mod(modulus);
    x3b.SetValues(b3, Format::COEFFICIENT);

    Poly x3aClone(x3a);
    Poly x3bClone(x3b);
    #endif

    time1af = 0.0;
    time1bf = 0.0;

    time2af = 0.0;
    time2bf = 0.0;

    time3af = 0.0;
    time3bf = 0.0;

    time1ar = 0.0;
    time1br = 0.0;

    time2ar = 0.0;
    time2br = 0.0;

    time3ar = 0.0;
    time3br = 0.0;

    bool failed = false;
    int ix;
    std::cout << "Startng timing" << std::endl;

    for (ix = 0; ix < nloop; ix++) {
        if (ix % 100 == 0)
            std::cout << ix << std::endl;
    #ifdef TEST1
        // forward
        TIC(t1);
        x1a.SwitchFormat();
        time1af += TOC_US(t1);

        TIC(t1);
        x1b.SwitchFormat();
        time1bf += TOC_US(t1);
    #endif
    #ifdef TEST2
        TIC(t1);
        x2a.SwitchFormat();
        time2af += TOC_US(t1);

        TIC(t1);
        x2b.SwitchFormat();
        time2bf += TOC_US(t1);
    #endif
    #ifdef TEST3
        TIC(t1);
        x3a.SwitchFormat();
        time3af += TOC_US(t1);

        TIC(t1);
        x3b.SwitchFormat();
        time3bf += TOC_US(t1);
    #endif
    #ifdef TEST1  // reverse
        TIC(t1);
        x1a.SwitchFormat();
        time1ar += TOC_US(t1);

        TIC(t1);
        x1b.SwitchFormat();
        time1br += TOC_US(t1);
    #endif
    #ifdef TEST2
        TIC(t1);
        x2a.SwitchFormat();
        time2ar += TOC_US(t1);

        TIC(t1);
        x2b.SwitchFormat();
        time2br += TOC_US(t1);
    #endif
    #ifdef TEST3
        TIC(t1);
        x3a.SwitchFormat();
        time3ar += TOC_US(t1);

        TIC(t1);
        x3b.SwitchFormat();
        time3br += TOC_US(t1);
    #endif
    #ifdef TEST1
        failed |= clonetest(x1a, x1aClone, "x1a");
        failed |= clonetest(x1b, x1bClone, "x1b");
    #endif
    #ifdef TEST2
        failed |= clonetest(x2a, x2aClone, "x2a");
        failed |= clonetest(x2b, x2bClone, "x2b");
    #endif
    #ifdef TEST3
        failed |= clonetest(x3a, x3aClone, "x3a");
        failed |= clonetest(x3b, x3bClone, "x3b");
    #endif
    }

    if (failed) {
        std::cout << "failure in loop number " << ix << std::endl;
    }
    else {
        time1af /= static_cast<double>(nloop);
        time1bf /= static_cast<double>(nloop);
        time2af /= static_cast<double>(nloop);
        time2bf /= static_cast<double>(nloop);
        time3af /= static_cast<double>(nloop);
        time3bf /= static_cast<double>(nloop);

        time1ar /= static_cast<double>(nloop);
        time1br /= static_cast<double>(nloop);
        time2ar /= static_cast<double>(nloop);
        time2br /= static_cast<double>(nloop);
        time3ar /= static_cast<double>(nloop);
        time3br /= static_cast<double>(nloop);

        std::cout << nloop << " loops" << std::endl;
        std::cout << "t1af: "
                  << "\t" << time1af << " us" << std::endl;
        std::cout << "t1bf: "
                  << "\t" << time1bf << " us" << std::endl;

        std::cout << "t2af: "
                  << "\t" << time2af << " us" << std::endl;
        std::cout << "t2bf: "
                  << "\t" << time2bf << " us" << std::endl;

        std::cout << "t3af: "
                  << "\t" << time3af << " us" << std::endl;
        std::cout << "t3bf: "
                  << "\t" << time3bf << " us" << std::endl;

        std::cout << "t1ar: "
                  << "\t" << time1ar << " us" << std::endl;
        std::cout << "t1br: "
                  << "\t" << time1br << " us" << std::endl;

        std::cout << "t2ar: "
                  << "\t" << time2ar << " us" << std::endl;
        std::cout << "t2br: "
                  << "\t" << time2br << " us" << std::endl;

        std::cout << "t3ar: "
                  << "\t" << time3ar << " us" << std::endl;
        std::cout << "t3br: "
                  << "\t" << time3br << " us" << std::endl;
    }
#endif
    return;
}
