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
  Implementation file for Boolean Circuit FHE context class
 */

#include "binfhecontext.h"

#include <map>
#include <string>
#include <unordered_map>

static constexpr double STD_DEV = 3.19;

namespace lbcrypto {

// RingGSWCryptoParams never sees the LWE dimension, so the map and n meet only here
static void VerifyGadgetBaseMapCoverage(const std::map<uint32_t, uint32_t>& baseGMap, uint32_t n) {
    uint32_t count{0};
    for (const auto& item : baseGMap)
        count += item.second;
    if (count != n)
        OPENFHE_THROW("Gadget base map should cover the LWE dimension.");
}

void BinFHEContext::GenerateBinFHEContext(uint32_t n, uint32_t N, NativeInteger q, NativeInteger Q, double std,
                                          uint32_t baseKS, uint32_t baseG, uint32_t baseR, SecretKeyDist keyDist,
                                          BINFHE_METHOD method, uint32_t numAutoKeys) {
    auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, Q, std, baseKS, keyDist);
    auto rgswparams =
        std::make_shared<RingGSWCryptoParams>(N, Q, q, baseG, baseR, method, std, keyDist, true, numAutoKeys);
    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

void BinFHEContext::GenerateBinFHEContext(BINFHE_PARAMSET s, bool arbFunc, uint32_t logQ, uint32_t N,
                                          BINFHE_METHOD method, bool timeOptimization) {
    if (method != GINX)
        OPENFHE_THROW("CGGI is the only supported method");
    if (s != STD128 && s != TOY)
        OPENFHE_THROW("STD128 and TOY are the only supported sets");
    if (logQ > 29)
        OPENFHE_THROW("logQ > 29 is not supported");
    if (logQ < 11)
        OPENFHE_THROW("logQ < 11 is not supported");

    isMethodCompatible(method, s);

    auto logQprime = 54;
    uint32_t baseG = 0;
    if (logQ > 25) {
        baseG = 1 << 14;
    }
    else if (logQ > 16) {
        baseG = 1 << 18;
    }
    else if (logQ > 11) {
        baseG = 1 << 27;
    }
    else {  // if (logQ == 11)
        baseG     = 1 << 5;
        logQprime = 27;
    }

    // choose minimum ringD satisfying sl and Q
    // if specified some larger N, security is also satisfied
    auto minRingDim  = StdLatticeParm::FindRingDim(HEStd_ternary, HEStd_128_classic, logQprime);
    uint32_t ringDim = N > minRingDim ? N : minRingDim;

    // find prime Q for NTT
    NativeInteger Q = LastPrime<NativeInteger>(logQprime, 2 * ringDim);

    // q = 2*ringDim by default for maximum plaintext space, if needed for arbitrary function evaluation, q = ringDim
    uint32_t q = arbFunc ? ringDim : 2 * ringDim;

    uint64_t qKS = uint64_t(1) << 35;

    uint32_t n      = (s == TOY) ? 32 : 1305;
    auto lweparams  = std::make_shared<LWECryptoParams>(n, ringDim, q, Q, qKS, STD_DEV, 32);
    auto rgswparams = std::make_shared<RingGSWCryptoParams>(ringDim, Q, q, baseG, 23, method, STD_DEV, UNIFORM_TERNARY,
                                                            ((logQ != 11) && timeOptimization));

    m_params           = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme     = std::make_shared<BinFHEScheme>(method);
    m_timeOptimization = timeOptimization;
}

void BinFHEContext::GenerateBinFHEContext(BINFHE_PARAMSET s, BINFHE_METHOD method) {
    enum { PRIME = 0 };  // value for modKS if you want to use the intermediate prime for modulus for key switching

    isMethodCompatible(method, s);

    // clang-format off
    static const std::unordered_map<BINFHE_PARAMSET, BinFHEContextParams> paramsMap{
    //  { BINFHE_PARAMSET         { bits, cycOrder, latParam, modq,   modKS, Bks,        Bg, Brk, autoKeys,         keyDist, stdDev, gadgetBaseMap } },
        { TOY,                    {   27,     1024,       64,  512,   PRIME,  25,       512,  23,        9, UNIFORM_TERNARY,   3.19, {{512, 64}} } },
        { TOY_MULTI_BASE,         {   27,     1024,       64,  512,   PRIME,  25,       512,  23,        9, UNIFORM_TERNARY,   3.19, {{128, 32}, {512, 32}} } },
        { MEDIUM,                 {   28,     2048,      422, 1024,   16384, 128,      1024,  32,       10, UNIFORM_TERNARY,   3.19, {{1024, 422}} } },
        { STD128,                 {   27,     2048,      554, 2048,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 304}, {512, 250}} } },
        { STD128_3,               {   27,     2048,      592, 2048,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 575}, {512, 17}} } },
        { STD128_4,               {   27,     2048,      630, 2048,  131072, 512,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 137}, {32, 493}} } },
        { STD128Q,                {   25,     2048,      598, 2048,   32768, 256,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 378}, {128, 220}} } },
        { STD128Q_3,              {   25,     2048,      639, 2048,   65536, 256,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 288}, {32, 351}} } },
        { STD128Q_4,              {   28,     4096,      680, 4096,  131072, 512,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 119}, {128, 561}} } },
        { STD192,                 {   28,     4096,      820, 4096,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 659}, {1024, 161}} } },
        { STD192_3,               {   28,     4096,      874, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 857}, {1024, 17}} } },
        { STD192_4,               {   28,     4096,      928, 4096,  131072, 512,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 563}, {128, 365}} } },
        { STD192Q,                {   28,     4096,      889, 4096,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 733}, {1024, 156}} } },
        { STD192Q_3,              {   28,     4096,      947, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 935}, {1024, 12}} } },
        { STD192Q_4,              {   28,     4096,     1004, 4096,  131072, 512,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 700}, {128, 304}} } },
        { STD256,                 {   28,     4096,     1077, 4096,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 932}, {1024, 145}} } },
        { STD256_3,               {   28,     4096,     1146, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 1146}} } },
        { STD256_4,               {   28,     4096,     1214, 4096,  131072, 512,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 1076}, {128, 138}} } },
        { STD256Q,                {   26,     4096,     1169, 4096,   32768, 256,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 182}, {64, 987}} } },
        { STD256Q_3,              {   26,     4096,     1243, 4096,   65536, 256,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 584}, {32, 659}} } },
        { STD256Q_4,              {   26,     4096,     1391, 4096,  262144, 512,         8,  64,       10, UNIFORM_TERNARY,   3.19, {{8, 182}, {16, 1209}} } },
        { LPF_STD128,             {   27,     2048,      554, 2048,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 523}, {512, 31}} } },
        { LPF_STD128_3,           {   27,     2048,      630, 2048,  131072, 512,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 166}, {64, 464}} } },
        { LPF_STD128_4,           {   28,     4096,      668, 4096,  262144, 512,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 582}, {128, 86}} } },
        { LPF_STD128Q,            {   25,     2048,      598, 2048,   32768, 256,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 112}, {32, 486}} } },
        { LPF_STD128Q_3,          {   25,     2048,      680, 2048,  131072, 512,         4,  64,       10, UNIFORM_TERNARY,   3.19, {{4, 45}, {8, 635}} } },
        { LPF_STD128Q_4,          {   28,     4096,      720, 4096,  262144, 512,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 675}, {128, 45}} } },
        { LPF_STD192,             {   28,     4096,      874, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 782}, {1024, 92}} } },
        { LPF_STD192_3,           {   28,     4096,      928, 4096,  131072, 512,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 338}, {128, 590}} } },
        { LPF_STD192_4,           {   28,     4096,      982, 4096,  262144, 512,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 718}, {64, 264}} } },
        { LPF_STD192Q,            {   28,     4096,      947, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 859}, {1024, 88}} } },
        { LPF_STD192Q_3,          {   28,     4096,     1004, 4096,  131072, 512,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 475}, {128, 529}} } },
        { LPF_STD192Q_4,          {   28,     4096,     1062, 4096,  262144, 512,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 999}, {64, 63}} } },
        { LPF_STD256,             {   28,     4096,     1146, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 1071}, {1024, 75}} } },
        { LPF_STD256_3,           {   28,     4096,     1214, 4096,  131072, 512,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 851}, {128, 363}} } },
        { LPF_STD256_4,           {   28,     4096,     1352, 4096,  524288, 128,         8,  64,       10, UNIFORM_TERNARY,   3.19, {{8, 128}, {16, 1224}} } },
        { LPF_STD256Q,            {   26,     4096,     1243, 4096,   65536, 256,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 832}, {64, 411}} } },
        { LPF_STD256Q_3,          {   26,     4096,     1317, 4096,  131072, 512,         8,  64,       10, UNIFORM_TERNARY,   3.19, {{8, 36}, {16, 1281}} } },
        { STD128_LMKCDEY,         {   27,     2048,      554, 2048,   32768, 256,       512,  64,       40, UNIFORM_TERNARY,   3.19, {{512, 552}, {16384, 2}} } },
        { STD128_3_LMKCDEY,       {   27,     2048,      592, 2048,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 440}, {512, 152}} } },
        { STD128_4_LMKCDEY,       {   27,     2048,      630, 2048,  131072, 512,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 97}, {64, 533}} } },
        { STD128Q_LMKCDEY,        {   25,     2048,      598, 2048,   32768, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 565}, {512, 33}} } },
        { STD128Q_3_LMKCDEY,      {   25,     2048,      639, 2048,   65536, 256,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 532}, {128, 107}} } },
        { STD128Q_4_LMKCDEY,      {   28,     4096,      680, 4096,  131072, 512,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 626}, {1024, 54}} } },
        { STD192_LMKCDEY,         {   28,     4096,      768, 4096,   65536, 256,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 280}, {1024, 488}} } },
        { STD192_3_LMKCDEY,       {   28,     4096,      874, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 732}, {1024, 142}} } },
        { STD192_4_LMKCDEY,       {   28,     4096,      928, 4096,  131072, 512,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 897}, {1024, 31}} } },
        { STD192Q_LMKCDEY,        {   28,     4096,      832, 4096,   65536, 256,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 394}, {1024, 438}} } },
        { STD192Q_3_LMKCDEY,      {   28,     4096,      947, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 812}, {1024, 135}} } },
        { STD192Q_4_LMKCDEY,      {   28,     4096,     1004, 4096,  131072, 512,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 980}, {1024, 24}} } },
        { STD256_LMKCDEY,         {   28,     4096,     1009, 4096,   65536, 256,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 712}, {1024, 297}} } },
        { STD256_3_LMKCDEY,       {   28,     4096,     1146, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 1029}, {1024, 117}} } },
        { STD256_4_LMKCDEY,       {   28,     4096,     1214, 4096,  131072, 512,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 1210}, {1024, 4}} } },
        { STD256Q_LMKCDEY,        {   28,     4096,     1120, 4096,   65536, 256,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 913}, {1024, 207}} } },
        { STD256Q_3_LMKCDEY,      {   26,     4096,     1243, 4096,   65536, 256,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 522}, {64, 721}} } },
        { STD256Q_4_LMKCDEY,      {   26,     4096,     1317, 4096,  131072, 512,        16,  64,       40, UNIFORM_TERNARY,   3.19, {{16, 607}, {32, 710}} } },
        { LPF_STD128_LMKCDEY,     {   27,     2048,      554, 2048,   32768, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 366}, {512, 188}} } },
        { LPF_STD128_3_LMKCDEY,   {   27,     2048,      630, 2048,  131072, 512,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 121}, {128, 509}} } },
        { LPF_STD128_4_LMKCDEY,   {   28,     4096,      668, 4096,  262144, 512,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 665}, {1024, 3}} } },
        { LPF_STD128Q_LMKCDEY,    {   25,     2048,      598, 2048,   32768, 256,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 450}, {128, 148}} } },
        { LPF_STD128Q_3_LMKCDEY,  {   25,     2048,      680, 2048,  131072, 512,        16,  64,       40, UNIFORM_TERNARY,   3.19, {{16, 659}, {32, 21}} } },
        { LPF_STD128Q_4_LMKCDEY,  {   28,     4096,      720, 4096,  262144, 512,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 44}, {128, 676}} } },
        { LPF_STD192_LMKCDEY,     {   28,     4096,      874, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 493}, {1024, 381}} } },
        { LPF_STD192_3_LMKCDEY,   {   28,     4096,      928, 4096,  131072, 512,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 872}, {1024, 56}} } },
        { LPF_STD192_4_LMKCDEY,   {   28,     4096,      982, 4096,  262144, 512,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 772}, {128, 210}} } },
        { LPF_STD192Q_LMKCDEY,    {   28,     4096,      947, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 572}, {1024, 375}} } },
        { LPF_STD192Q_3_LMKCDEY,  {   28,     4096,     1004, 4096,  131072, 512,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 955}, {1024, 49}} } },
        { LPF_STD192Q_4_LMKCDEY,  {   28,     4096,     1062, 4096,  262144, 512,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 996}, {128, 66}} } },
        { LPF_STD256_LMKCDEY,     {   28,     4096,     1146, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 789}, {1024, 357}} } },
        { LPF_STD256_3_LMKCDEY,   {   28,     4096,     1214, 4096,  131072, 512,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 1185}, {1024, 29}} } },
        { LPF_STD256_4_LMKCDEY,   {   28,     4096,     1352, 4096,  524288, 128,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 1283}, {64, 69}} } },
        { LPF_STD256Q_LMKCDEY,    {   26,     4096,     1243, 4096,   65536, 256,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 699}, {128, 544}} } },
        { LPF_STD256Q_3_LMKCDEY,  {   26,     4096,     1317, 4096,  131072, 512,        16,  64,       40, UNIFORM_TERNARY,   3.19, {{16, 19}, {32, 1298}} } },
        { STD128_AP,              {   27,     2048,      554, 2048,   32768, 256,       128, 128,       10, UNIFORM_TERNARY,   3.19, {{128, 11}, {512, 543}} } },
        { STD128_3_AP,            {   27,     2048,      592, 2048,   65536, 256,       128, 128,       10, UNIFORM_TERNARY,   3.19, {{128, 512}, {512, 80}} } },
        { STD128_4_AP,            {   27,     2048,      630, 2048,  131072, 512,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 408}, {64, 222}} } },
        { STD128Q_AP,             {   25,     2048,      598, 2048,   32768, 256,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 73}, {128, 525}} } },
        { STD128Q_3_AP,           {   25,     2048,      639, 2048,   65536, 256,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 605}, {128, 34}} } },
        { STD128Q_4_AP,           {   28,     4096,      680, 4096,  131072, 512,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 673}, {1024, 7}} } },
        { STD192_AP,              {   28,     4096,      874, 1024,   65536, 256,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 653}, {1024, 221}} } },
        { STD192_3_AP,            {   28,     4096,      928, 2048,  131072, 512,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 896}, {1024, 32}} } },
        { STD192_4_AP,            {   28,     4096,      928, 4096,  131072, 512,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 265}, {128, 663}} } },
        { STD192Q_AP,             {   28,     4096,      947, 1024,   65536, 256,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 766}, {1024, 181}} } },
        { STD192Q_3_AP,           {   28,     4096,     1004, 2048,  131072,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 992}, {1024, 12}} } },
        { STD192Q_4_AP,           {   28,     4096,     1004, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 655}, {128, 349}} } },
        { STD256_AP,              {   28,     4096,     1146, 1024,   65536, 256,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 1075}, {1024, 71}} } },
        { STD256_3_AP,            {   28,     4096,     1146, 4096,   65536, 256,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 1123}, {1024, 23}} } },
        { STD256_4_AP,            {   28,     4096,     1214, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 1074}, {128, 140}} } },
        { STD256Q_AP,             {   28,     4096,     1120, 4096,   65536, 256,       128,  32,       10,        GAUSSIAN,   3.19, {{128, 1055}, {1024, 65}} } },
        { STD256Q_3_AP,           {   26,     4096,     1243, 4096,   65536, 256,        16,   8,       10, UNIFORM_TERNARY,   3.19, {{16, 458}, {32, 785}} } },
        { STD256Q_4_AP,           {   26,     4096,     1391, 4096,  262144,  64,         8,   8,       10, UNIFORM_TERNARY,   3.19, {{8, 103}, {16, 1288}} } },
        { LPF_STD128_AP,          {   27,     2048,      554, 2048,   32768, 256,       128, 128,       10, UNIFORM_TERNARY,   3.19, {{128, 450}, {512, 104}} } },
        { LPF_STD128_3_AP,        {   27,     2048,      630, 2048,  131072, 512,        64, 128,       10, UNIFORM_TERNARY,   3.19, {{64, 424}, {128, 206}} } },
        { LPF_STD128_4_AP,        {   28,     4096,      668, 4096,  262144, 512,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 445}, {128, 223}} } },
        { LPF_STD128Q_AP,         {   25,     2048,      598, 2048,   32768, 256,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 536}, {128, 62}} } },
        { LPF_STD128Q_3_AP,       {   25,     2048,      680, 2048,  131072, 512,         8,  32,       10, UNIFORM_TERNARY,   3.19, {{8, 488}, {16, 192}} } },
        { LPF_STD128Q_4_AP,       {   28,     4096,      720, 4096,  262144, 512,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 548}, {128, 172}} } },
        { LPF_STD192_AP,          {   28,     4096,      874, 2048,   65536, 256,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 768}, {1024, 106}} } },
        { LPF_STD192_3_AP,        {   28,     4096,      928, 4096,  131072, 512,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 927}, {1024, 1}} } },
        { LPF_STD192_4_AP,        {   28,     4096,      982, 4096,  262144,  64,        32,  32,       10, UNIFORM_TERNARY,   3.19, {{32, 654}, {64, 328}} } },
        { LPF_STD192Q_AP,         {   28,     4096,      947, 2048,   65536, 256,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 852}, {1024, 95}} } },
        { LPF_STD192Q_3_AP,       {   28,     4096,     1004, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 330}, {128, 674}} } },
        { LPF_STD192Q_4_AP,       {   28,     4096,     1120, 4096,  524288,  32,        32,  32,       10, UNIFORM_TERNARY,   3.19, {{32, 732}, {64, 388}} } },
        { LPF_STD256_AP,          {   28,     4096,     1146, 2048,   65536, 256,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 1079}, {1024, 67}} } },
        { LPF_STD256_3_AP,        {   28,     4096,     1214, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 749}, {128, 465}} } },
        { LPF_STD256_4_AP,        {   28,     4096,     1352, 4096,  524288, 128,        16,   8,       10, UNIFORM_TERNARY,   3.19, {{16, 1326}, {32, 26}} } },
        { LPF_STD256Q_AP,         {   26,     4096,     1243, 4096,   65536, 256,        32,   8,       10, UNIFORM_TERNARY,   3.19, {{32, 726}, {64, 517}} } },
        { LPF_STD256Q_3_AP,       {   26,     4096,     1391, 4096,  262144,  64,        16,   8,       10, UNIFORM_TERNARY,   3.19, {{16, 1219}, {32, 172}} } },
        { SIGNED_MOD_TEST,        {   28,     2048,      512, 1024,   PRIME,  25,       128,  23,       10, UNIFORM_TERNARY,   3.19, {{128, 512}} } },
    };
    // clang-format on

    auto search = paramsMap.find(s);
    if (paramsMap.end() == search)
        OPENFHE_THROW("unknown parameter set");

    auto& params = search->second;

    auto Q         = LastPrime<NativeInteger>(params.numberBits, params.cyclOrder);
    auto ringDim   = params.cyclOrder >> 1;
    auto lweparams = std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q,
                                                       (params.modKS == PRIME ? Q : params.modKS), params.stdDev,
                                                       params.baseKS, params.keyDist);
    VerifyGadgetBaseMapCoverage(params.gadgetBaseMap, params.latticeParam);

    auto rgswparams = std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase,
                                                            params.gadgetBaseMap, params.baseRK, method, params.stdDev,
                                                            params.keyDist, false, params.numAutoKeys);
    m_params        = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);

    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

void BinFHEContext::GenerateBinFHEContext(const BinFHEContextParams& params, BINFHE_METHOD method) {
    enum { PRIME = 0 };  // value for modKS if you want to use the intermediate prime for modulus for key switching

    auto Q         = LastPrime<NativeInteger>(params.numberBits, params.cyclOrder);
    auto ringDim   = params.cyclOrder >> 1;
    auto lweparams = std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q,
                                                       (params.modKS == PRIME ? Q : params.modKS), params.stdDev,
                                                       params.baseKS, params.keyDist);
    std::shared_ptr<RingGSWCryptoParams> rgswparams;
    if (params.gadgetBaseMap.empty()) {
        rgswparams =
            std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase, params.baseRK, method,
                                                  params.stdDev, params.keyDist, false, params.numAutoKeys);
    }
    else {
        VerifyGadgetBaseMapCoverage(params.gadgetBaseMap, params.latticeParam);

        rgswparams = std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase,
                                                           params.gadgetBaseMap, params.baseRK, method, params.stdDev,
                                                           params.keyDist, false, params.numAutoKeys);
    }
    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

LWEPrivateKey BinFHEContext::KeyGen() const {
    auto&& LWEParams = m_params->GetLWEParams();
    if (LWEParams->GetKeyDist() == GAUSSIAN)
        return m_LWEscheme->KeyGenGaussian(LWEParams->Getn(), LWEParams->GetqKS());
    return m_LWEscheme->KeyGen(LWEParams->Getn(), LWEParams->GetqKS());
}

LWEPrivateKey BinFHEContext::KeyGenN() const {
    auto&& LWEParams = m_params->GetLWEParams();
    if (LWEParams->GetKeyDist() == GAUSSIAN)
        return m_LWEscheme->KeyGenGaussian(LWEParams->GetN(), LWEParams->GetQ());
    return m_LWEscheme->KeyGen(LWEParams->GetN(), LWEParams->GetQ());
}

LWEKeyPair BinFHEContext::KeyGenPair() const {
    return m_LWEscheme->KeyGenPair(m_params->GetLWEParams());
}

LWEPublicKey BinFHEContext::PubKeyGen(ConstLWEPrivateKey& sk) const {
    if (sk == nullptr)
        OPENFHE_THROW("PrivateKey is empty");
    return m_LWEscheme->PubKeyGen(m_params->GetLWEParams(), sk);
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey& sk, LWEPlaintext m, BINFHE_OUTPUT output,
                                     LWEPlaintextModulus p, NativeInteger mod) const {
    if (sk == nullptr)
        OPENFHE_THROW("PrivateKey is empty");
    auto&& LWEParams = m_params->GetLWEParams();
    auto ct          = m_LWEscheme->Encrypt(LWEParams, sk, m, p, (mod == 0 ? LWEParams->Getq() : mod));

    // BINFHE_OUTPUT is kept as it is for backward compatibility but
    // this logic is obsolete now and commented out
    // if ((output != FRESH) && (p == 4)) {
    //    ct = m_binfhescheme->Bootstrap(m_params, m_BTKey, ct);
    //}
    return ct;
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPublicKey& pk, LWEPlaintext m, BINFHE_OUTPUT output, LWEPlaintextModulus p,
                                     NativeInteger mod) const {
    if (pk == nullptr)
        OPENFHE_THROW("PublicKey is empty");
    auto&& LWEParams = m_params->GetLWEParams();
    auto ct          = m_LWEscheme->EncryptN(LWEParams, pk, m, p, (mod == 0 ? LWEParams->GetQ() : mod));

    // Switch from ct of modulus Q and dimension N to smaller q and n
    // This is done by default while calling Encrypt but the output could
    // be set to LARGE_DIM to skip this switching
    if (output == SMALL_DIM) {
#if NATIVEINT != 32
        if (m_BTKey.KSkey32 != nullptr)
            ct = m_LWEscheme->SwitchCTtoqn(LWEParams, m_BTKey.KSkey32, ct);
        else
#endif
            ct = SwitchCTtoqn(m_BTKey.KSkey, ct);
        ct->SetptModulus(p);
    }
    return ct;
}

LWECiphertext BinFHEContext::SwitchCTtoqn(ConstLWESwitchingKey& ksk, ConstLWECiphertext& ct) const {
    if (ksk == nullptr)
        OPENFHE_THROW("SwitchingKey is empty");
    if (ct == nullptr)
        OPENFHE_THROW("Ciphertext is empty");
    auto&& LWEParams = m_params->GetLWEParams();
    if (ct->GetLength() != LWEParams->GetN() || ct->GetModulus() != LWEParams->GetQ())
        OPENFHE_THROW("ciphertext must have large dimension N and modulus Q");
    return m_LWEscheme->SwitchCTtoqn(LWEParams, ksk, ct);
}

void BinFHEContext::Decrypt(ConstLWEPrivateKey& sk, ConstLWECiphertext& ct, LWEPlaintext* result,
                            LWEPlaintextModulus p) const {
    if (sk == nullptr)
        OPENFHE_THROW("PrivateKey is empty");
    if (ct == nullptr)
        OPENFHE_THROW("Ciphertext is empty");
    m_LWEscheme->Decrypt(m_params->GetLWEParams(), sk, ct, result, p);
}

LWESwitchingKey BinFHEContext::KeySwitchGen(ConstLWEPrivateKey& sk, ConstLWEPrivateKey& skN) const {
    if (sk == nullptr)
        OPENFHE_THROW("New PrivateKey is empty");
    if (skN == nullptr)
        OPENFHE_THROW("Old PrivateKey is empty");

    return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
}

void BinFHEContext::BTKeyGen(ConstLWEPrivateKey& sk, KEYGEN_MODE keygenMode, bool internal32) {
    if (sk == nullptr)
        OPENFHE_THROW("PrivateKey is empty");
    auto&& RGSWParams = m_params->GetRingGSWParams();
    auto temp         = RGSWParams->GetBaseG();

    // the map is keyed by gadget base alone, but what it caches is only valid for the secret
    // key it was generated from; take a cached entry only when this call just regenerated it
    if (m_timeOptimization) {
        for (auto&& [k, v] : RGSWParams->GetGPowerMap()) {
            RGSWParams->Change_BaseG(k);
            m_BTKey_map[k] = m_binfhescheme->KeyGen(m_params, sk, keygenMode, internal32);
        }
        RGSWParams->Change_BaseG(temp);
        m_BTKey = m_BTKey_map[temp];
    }
    else {
        m_BTKey           = m_binfhescheme->KeyGen(m_params, sk, keygenMode, internal32);
        m_BTKey_map[temp] = m_BTKey;
    }

#if NATIVEINT != 32
    ReleaseMonomialsIfAll32();
#endif
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, ConstLWECiphertext& ct1, ConstLWECiphertext& ct2,
                                         bool extended) const {
    if (ct1 == nullptr)
        OPENFHE_THROW("Ciphertext1 is empty");
    if (ct2 == nullptr)
        OPENFHE_THROW("Ciphertext2 is empty");
    return m_binfhescheme->EvalBinGate(m_params, gate, m_BTKey, ct1, ct2, extended);
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, const std::vector<LWECiphertext>& ctvector,
                                         bool extended) const {
    return m_binfhescheme->EvalBinGate(m_params, gate, m_BTKey, ctvector, extended);
}

LWECiphertext BinFHEContext::Bootstrap(ConstLWECiphertext& ct, bool extended) const {
    if (ct == nullptr)
        OPENFHE_THROW("Ciphertext is empty");
    return m_binfhescheme->Bootstrap(m_params, m_BTKey, ct, extended);
}

LWECiphertext BinFHEContext::EvalNOT(ConstLWECiphertext& ct) const {
    if (ct == nullptr)
        OPENFHE_THROW("Ciphertext is empty");
    return m_binfhescheme->EvalNOT(m_params, ct);
}

LWECiphertext BinFHEContext::EvalConstant(bool value) const {
    return m_LWEscheme->NoiselessEmbedding(m_params->GetLWEParams(), value);
}

LWECiphertext BinFHEContext::EvalFunc(ConstLWECiphertext& ct, const std::vector<NativeInteger>& LUT) const {
    if (ct == nullptr)
        OPENFHE_THROW("Ciphertext is empty");
    return m_binfhescheme->EvalFunc(m_params, m_BTKey, ct, LUT, GetBeta());
}

LWECiphertext BinFHEContext::EvalFloor(ConstLWECiphertext& ct, uint32_t roundbits) const {
    //    auto q = m_params->GetLWEParams()->Getq().ConvertToInt();
    //    if (roundbits != 0) {
    //        NativeInteger newp = this->GetMaxPlaintextSpace();
    //        SetQ(q / newp * (1 << roundbits));
    //    }
    //    SetQ(q);
    //    return res;
    if (ct == nullptr)
        OPENFHE_THROW("Ciphertext is empty");
    return m_binfhescheme->EvalFloor(m_params, m_BTKey, ct, GetBeta(), roundbits);
}

LWECiphertext BinFHEContext::EvalSign(ConstLWECiphertext& ct, bool schemeSwitch) {
    if (ct == nullptr)
        OPENFHE_THROW("Ciphertext is empty");
    return m_binfhescheme->EvalSign(std::make_shared<BinFHECryptoParams>(*m_params), m_BTKey_map, ct, GetBeta(),
                                    schemeSwitch);
}

std::vector<LWECiphertext> BinFHEContext::EvalDecomp(ConstLWECiphertext& ct) {
    if (ct == nullptr)
        OPENFHE_THROW("Ciphertext is empty");
    return m_binfhescheme->EvalDecomp(m_params, m_BTKey_map, ct, GetBeta());
}

std::vector<NativeInteger> BinFHEContext::GenerateLUTviaFunction(NativeInteger (*f)(NativeInteger m, NativeInteger p),
                                                                 NativeInteger p) {
    if (!IsPowerOfTwo(p.ConvertToInt<BasicInteger>()))
        OPENFHE_THROW("plaintext p not power of two");

    NativeInteger q{GetParams()->GetLWEParams()->Getq()};
    NativeInteger x{0};

    std::vector<NativeInteger> vec(q.ConvertToInt(), q / p);
    for (size_t i = 0; i < vec.size(); ++i, x += p) {
        vec[i] *= f(x / q, p);  // x/q = (i*p)/q = i/(q/p)
        if (vec[i] >= q)        // (f(x/q, p) >= p) --> (f(x/q, p)*(q/p) >= q)
            OPENFHE_THROW("input function should output in Z_{p_output}");
    }
    return vec;
}

}  // namespace lbcrypto
