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
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

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
        { STD128,                 {   27,     2048,      554, 2048,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 303}, {512, 251}} } },
        { STD128_3,               {   27,     2048,      592, 2048,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 575}, {512, 17}} } },
        { STD128_4,               {   27,     2048,      630, 2048,  131072, 512,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 134}, {32, 496}} } },
        { STD128Q,                {   25,     2048,      598, 2048,   32768, 256,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 377}, {128, 221}} } },
        { STD128Q_3,              {   25,     2048,      639, 2048,   65536, 256,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 287}, {32, 352}} } },
        { STD128Q_4,              {   28,     4096,      680, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 273}, {128, 407}} } },
        { STD192,                 {   28,     4096,      820, 4096,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 658}, {1024, 162}} } },
        { STD192_3,               {   28,     4096,      874, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 857}, {1024, 17}} } },
        { STD192_4,               {   28,     4096,      928, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 718}, {128, 210}} } },
        { STD192Q,                {   28,     4096,      889, 4096,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 732}, {1024, 157}} } },
        { STD192Q_3,              {   28,     4096,      947, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 935}, {1024, 12}} } },
        { STD192Q_4,              {   28,     4096,     1004, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 855}, {128, 149}} } },
        { STD256,                 {   28,     4096,     1077, 4096,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 931}, {1024, 146}} } },
        { STD256_3,               {   28,     4096,     1214, 4096,  131072,  64,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 1190}, {1024, 24}} } },
        { STD256_4,               {   28,     4096,     1283, 4096,  262144, 128,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 1137}, {128, 146}} } },
        { STD256Q,                {   26,     4096,     1169, 4096,   32768, 256,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 173}, {64, 996}} } },
        { STD256Q_3,              {   26,     4096,     1317, 4096,  131072,  64,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 41}, {32, 1276}} } },
        { STD256Q_4,              {   26,     4096,     1391, 4096,  262144,  64,         8,  64,       10, UNIFORM_TERNARY,   3.19, {{8, 289}, {16, 1102}} } },
        { LPF_STD128,             {   27,     2048,      554, 2048,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 523}, {512, 31}} } },
        { LPF_STD128_3,           {   27,     2048,      630, 2048,  131072, 512,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 165}, {64, 465}} } },
        { LPF_STD128_4,           {   28,     4096,      668, 4096,  262144,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 621}, {128, 47}} } },
        { LPF_STD128Q,            {   25,     2048,      598, 2048,   32768, 256,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 106}, {32, 492}} } },
        { LPF_STD128Q_3,          {   25,     2048,      680, 2048,  131072, 512,         4,  64,       10, UNIFORM_TERNARY,   3.19, {{4, 43}, {8, 637}} } },
        { LPF_STD128Q_4,          {   28,     4096,      720, 4096,  262144,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 715}, {128, 5}} } },
        { LPF_STD192,             {   28,     4096,      874, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 782}, {1024, 92}} } },
        { LPF_STD192_3,           {   28,     4096,      928, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 493}, {128, 435}} } },
        { LPF_STD192_4,           {   28,     4096,      982, 4096,  262144,  64,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 893}, {64, 89}} } },
        { LPF_STD192Q,            {   28,     4096,      947, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 859}, {1024, 88}} } },
        { LPF_STD192Q_3,          {   28,     4096,     1004, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 629}, {128, 375}} } },
        { LPF_STD192Q_4,          {   28,     4096,     1062, 4096,  262144,  64,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 359}, {32, 703}} } },
        { LPF_STD256,             {   28,     4096,     1146, 4096,   65536,  64,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 1091}, {1024, 55}} } },
        { LPF_STD256_3,           {   28,     4096,     1214, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 1006}, {128, 208}} } },
        { LPF_STD256_4,           {   28,     4096,     1352, 4096,  524288, 128,         8,  64,       10, UNIFORM_TERNARY,   3.19, {{8, 110}, {16, 1242}} } },
        { LPF_STD256Q,            {   26,     4096,     1243, 4096,   65536,  64,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 997}, {64, 246}} } },
        { LPF_STD256Q_3,          {   26,     4096,     1391, 4096,  262144,  64,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 1294}, {32, 97}} } },
        { LPF_STD256Q_4,          {   28,     8192,     1465, 8192,  524288,  32,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 1201}, {64, 264}} } },
        { STD128_LMKCDEY,         {   27,     2048,      554, 2048,   32768, 256,       512,  64,       40, UNIFORM_TERNARY,   3.19, {{512, 552}, {16384, 2}} } },
        { STD128_3_LMKCDEY,       {   27,     2048,      592, 2048,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 440}, {512, 152}} } },
        { STD128_4_LMKCDEY,       {   27,     2048,      668, 2048,  262144, 512,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 586}, {128, 82}} } },
        { STD128Q_LMKCDEY,        {   25,     2048,      598, 2048,   32768, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 565}, {512, 33}} } },
        { STD128Q_3_LMKCDEY,      {   25,     2048,      639, 2048,   65536, 256,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 532}, {128, 107}} } },
        { STD128Q_4_LMKCDEY,      {   28,     4096,      680, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 642}, {1024, 38}} } },
        { STD192_LMKCDEY,         {   28,     4096,      716, 4096,   32768, 256,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 633}, {1024, 83}} } },
        { STD192_3_LMKCDEY,       {   28,     4096,      874, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 731}, {1024, 143}} } },
        { STD192_4_LMKCDEY,       {   28,     4096,      928, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 914}, {1024, 14}} } },
        { STD192Q_LMKCDEY,        {   28,     4096,      778, 4096,   32768, 256,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 745}, {1024, 33}} } },
        { STD192Q_3_LMKCDEY,      {   28,     4096,      947, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 811}, {1024, 136}} } },
        { STD192Q_4_LMKCDEY,      {   28,     4096,     1004, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 997}, {1024, 7}} } },
        { STD256_LMKCDEY,         {   28,     4096,     1009, 4096,   65536,  64,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 779}, {1024, 230}} } },
        { STD256_3_LMKCDEY,       {   28,     4096,     1146, 4096,   65536,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 1095}, {1024, 51}} } },
        { STD256_4_LMKCDEY,       {   28,     4096,     1283, 4096,  262144,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 1263}, {1024, 20}} } },
        { STD256Q_LMKCDEY,        {   28,     4096,     1120, 4096,   65536,  64,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 980}, {1024, 140}} } },
        { STD256Q_3_LMKCDEY,      {   26,     4096,     1317, 4096,  131072,  64,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 1288}, {128, 29}} } },
        { STD256Q_4_LMKCDEY,      {   26,     4096,     1317, 4096,  131072,  64,        16,  64,       40, UNIFORM_TERNARY,   3.19, {{16, 1014}, {32, 303}} } },
        { LPF_STD128_LMKCDEY,     {   27,     2048,      554, 2048,   32768, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 364}, {512, 190}} } },
        { LPF_STD128_3_LMKCDEY,   {   27,     2048,      630, 2048,  131072, 512,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 120}, {128, 510}} } },
        { LPF_STD128_4_LMKCDEY,   {   28,     4096,      706, 4096,  524288, 128,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 701}, {1024, 5}} } },
        { LPF_STD128Q_LMKCDEY,    {   25,     2048,      598, 2048,   32768, 256,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 448}, {128, 150}} } },
        { LPF_STD128Q_3_LMKCDEY,  {   25,     2048,      680, 2048,  131072, 512,        16,  64,       40, UNIFORM_TERNARY,   3.19, {{16, 658}, {32, 22}} } },
        { LPF_STD128Q_4_LMKCDEY,  {   28,     4096,      760, 4096,  524288, 128,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 760}} } },
        { LPF_STD192_LMKCDEY,     {   28,     4096,      874, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 492}, {1024, 382}} } },
        { LPF_STD192_3_LMKCDEY,   {   28,     4096,      928, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 889}, {1024, 39}} } },
        { LPF_STD192_4_LMKCDEY,   {   28,     4096,      982, 4096,  262144,  64,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 899}, {128, 83}} } },
        { LPF_STD192Q_LMKCDEY,    {   28,     4096,      947, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 572}, {1024, 375}} } },
        { LPF_STD192Q_3_LMKCDEY,  {   28,     4096,     1004, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 972}, {1024, 32}} } },
        { LPF_STD192Q_4_LMKCDEY,  {   28,     4096,     1120, 4096,  524288, 128,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 990}, {128, 130}} } },
        { LPF_STD256_LMKCDEY,     {   28,     4096,     1146, 4096,   65536,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 854}, {1024, 292}} } },
        { LPF_STD256_3_LMKCDEY,   {   28,     4096,     1214, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 1202}, {1024, 12}} } },
        { LPF_STD256_4_LMKCDEY,   {   28,     4096,     1352, 4096,  524288, 128,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 1276}, {64, 76}} } },
        { LPF_STD256Q_LMKCDEY,    {   26,     4096,     1243, 4096,   65536,  64,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 900}, {128, 343}} } },
        { LPF_STD256Q_3_LMKCDEY,  {   26,     4096,     1391, 4096,  262144,  64,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 1279}, {64, 112}} } },
        { LPF_STD256Q_4_LMKCDEY,  {   28,     8192,     1465, 8192,  524288,  32,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 1243}, {128, 222}} } },
        { STD128_AP,              {   27,     2048,      554, 2048,   32768, 256,       128, 128,       10, UNIFORM_TERNARY,   3.19, {{128, 10}, {512, 544}} } },
        { STD128_3_AP,            {   27,     2048,      592, 2048,   65536, 256,       128, 128,       10, UNIFORM_TERNARY,   3.19, {{128, 512}, {512, 80}} } },
        { STD128_4_AP,            {   27,     2048,      668, 2048,  262144,  64,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 304}, {64, 364}} } },
        { STD128Q_AP,             {   25,     2048,      598, 2048,   32768, 256,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 72}, {128, 526}} } },
        { STD128Q_3_AP,           {   25,     2048,      639, 2048,   65536, 256,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 605}, {128, 34}} } },
        { STD128Q_4_AP,           {   28,     4096,      680, 4096,  131072,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 680}} } },
        { STD192_AP,              {   28,     4096,      874, 1024,   65536, 256,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 653}, {1024, 221}} } },
        { STD192_3_AP,            {   28,     4096,      928, 2048,  131072,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 904}, {1024, 24}} } },
        { STD192_4_AP,            {   28,     4096,      928, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 488}, {128, 440}} } },
        { STD192Q_AP,             {   28,     4096,      947, 1024,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 808}, {1024, 139}} } },
        { STD192Q_3_AP,           {   28,     4096,     1004, 2048,  131072,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 991}, {1024, 13}} } },
        { STD192Q_4_AP,           {   28,     4096,     1062, 4096,  262144,  32,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 282}, {128, 780}} } },
        { STD256_AP,              {   28,     4096,     1146, 1024,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 1117}, {1024, 29}} } },
        { STD256_3_AP,            {   28,     4096,     1214, 4096,  131072,  32,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 1160}, {1024, 54}} } },
        { STD256_4_AP,            {   28,     4096,     1214, 4096,  131072,  64,        64,   8,       10, UNIFORM_TERNARY,   3.19, {{64, 1192}, {128, 22}} } },
        { STD256Q_AP,             {   28,     4096,     1120, 4096,   65536,  64,       128,  32,       10,        GAUSSIAN,   3.19, {{128, 1085}, {1024, 35}} } },
        { STD256Q_3_AP,           {   26,     4096,     1317, 4096,  131072,  64,        32,   8,       10, UNIFORM_TERNARY,   3.19, {{32, 1265}, {64, 52}} } },
        { STD256Q_4_AP,           {   26,     4096,     1391, 4096,  262144,  32,         8,   8,       10, UNIFORM_TERNARY,   3.19, {{8, 200}, {16, 1191}} } },
        { LPF_STD128_AP,          {   27,     2048,      554, 2048,   32768, 256,       128, 128,       10, UNIFORM_TERNARY,   3.19, {{128, 449}, {512, 105}} } },
        { LPF_STD128_3_AP,        {   27,     2048,      630, 2048,  131072, 512,        64, 128,       10, UNIFORM_TERNARY,   3.19, {{64, 424}, {128, 206}} } },
        { LPF_STD128_4_AP,        {   28,     4096,      668, 4096,  262144,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 501}, {128, 167}} } },
        { LPF_STD128Q_AP,         {   25,     2048,      598, 2048,   32768, 256,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 534}, {128, 64}} } },
        { LPF_STD128Q_3_AP,       {   25,     2048,      680, 2048,  131072, 512,         8,  32,       10, UNIFORM_TERNARY,   3.19, {{8, 487}, {16, 193}} } },
        { LPF_STD128Q_4_AP,       {   28,     4096,      720, 4096,  262144,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 605}, {128, 115}} } },
        { LPF_STD192_AP,          {   28,     4096,      874, 2048,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 801}, {1024, 73}} } },
        { LPF_STD192_3_AP,        {   28,     4096,      928, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 164}, {128, 764}} } },
        { LPF_STD192_4_AP,        {   28,     4096,      982, 4096,  262144,  64,        32,   8,       10, UNIFORM_TERNARY,   3.19, {{32, 834}, {64, 148}} } },
        { LPF_STD192Q_AP,         {   28,     4096,      947, 2048,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 884}, {1024, 63}} } },
        { LPF_STD192Q_3_AP,       {   28,     4096,     1004, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 315}, {128, 689}} } },
        { LPF_STD192Q_4_AP,       {   28,     4096,     1062, 4096,  262144,  64,        16,   8,       10, UNIFORM_TERNARY,   3.19, {{16, 222}, {32, 840}} } },
        { LPF_STD256_AP,          {   28,     4096,     1146, 2048,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 1112}, {1024, 34}} } },
        { LPF_STD256_3_AP,        {   28,     4096,     1214, 4096,  131072,  64,        64,   8,       10, UNIFORM_TERNARY,   3.19, {{64, 942}, {128, 272}} } },
        { LPF_STD256_4_AP,        {   28,     4096,     1352, 4096,  524288,  32,         8,   8,       10, UNIFORM_TERNARY,   3.19, {{8, 288}, {16, 1064}} } },
        { LPF_STD256Q_AP,         {   26,     4096,     1243, 4096,   65536,  64,        32,   8,       10, UNIFORM_TERNARY,   3.19, {{32, 908}, {64, 335}} } },
        { LPF_STD256Q_3_AP,       {   26,     4096,     1391, 4096,  262144,  32,        16,   8,       10, UNIFORM_TERNARY,   3.19, {{16, 1248}, {32, 143}} } },
        { LPF_STD256Q_4_AP,       {   51,     8192,     1391, 8192,  262144,  32,  67108864,   8,       10, UNIFORM_TERNARY,   3.19, {{67108864, 1391}} } },
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
