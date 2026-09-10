// BSD 2-Clause License; see LICENSE.
// Paper driver: one configuration per process, explicit modes and machine-readable results.
#include "fbt-benchmark.h"
#include "scheme/ckksrns/ckksrns-fbt-instrumentation.h"
#include "schemelet/rlwe-mp.h"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

using namespace lbcrypto;
using Method = DiscreteCKKSInterpolationMethod;
using Clock  = std::chrono::steady_clock;

namespace {
struct Options {
    std::string mode       = "verify";
    std::string methodName = "BKSS";
    Method method          = Method::BKSS_NEW;
    uint32_t p = 16, order = 1, ringDim = 256, slots = 256, sf = 59;
    std::vector<uint32_t> levelBudget{1, 1};
    std::vector<uint32_t> noiseBases{10};
    bool unsafe = false;
};

uint32_t Number(const std::string& text) {
    size_t used = 0;
    auto result = std::stoul(text, &used);
    if (used != text.size() || text.empty() || text[0] == '-' || result > UINT32_MAX)
        throw std::invalid_argument("Invalid unsigned integer: " + text);
    return static_cast<uint32_t>(result);
}

std::vector<uint32_t> Numbers(const std::string& text) {
    std::vector<uint32_t> result;
    std::istringstream stream(text);
    std::string item;
    while (std::getline(stream, item, ','))
        result.push_back(Number(item));
    if (result.empty() || text.back() == ',')
        throw std::invalid_argument("Empty numeric list entry");
    return result;
}

bool PowerOfTwo(uint32_t n) {
    return n && !(n & (n - 1));
}

Options Parse(int argc, char** argv) {
    Options o;
    const std::map<std::string, Method> methods{{"AKP", Method::AKP},
                                                {"AKP25", Method::AKP},
                                                {"BKSS", Method::BKSS_NEW},
                                                {"BKSS_NEW", Method::BKSS_NEW},
                                                {"BKSS24_NEW", Method::BKSS_NEW},
                                                {"BKSS_LEGACY", Method::BKSS},
                                                {"BKSS24", Method::BKSS},
                                                {"SPARSE_THI", Method::SPARSE_THI},
                                                {"FULL_THI", Method::FULL_THI},
                                                {"CKKL", Method::FULL_THI}};
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--help") {
            std::cout
                << "fbt-benchmark --mode=verify|precision|benchmark --method=AKP|BKSS|BKSS_LEGACY|FULL_THI|SPARSE_THI\n"
                   "  --p=16 --order=1 --ring-dim=256 --slots=256 --sf=59\n"
                   "  --level-budget=1,1 --noise-base=10[,20,...] --unsafe\n"
                   "BKSS uses BKSS_NEW. Benchmark: 1 warm-up + 5 measured runs.\n"
                   "Precision: one encryption per noise point; no timing interpretation.\n"
                   "Small rings require --unsafe. Paper parameters are in artifacts/reproduce.py.\n";
            std::exit(0);
        }
        if (arg == "--unsafe") {
            o.unsafe = true;
            continue;
        }
        const auto equals = arg.find('=');
        if (equals == std::string::npos)
            throw std::invalid_argument("Expected --option=value: " + arg);
        auto name = arg.substr(0, equals), value = arg.substr(equals + 1);
        if (name == "--mode")
            o.mode = value;
        else if (name == "--method") {
            o.method     = methods.at(value);
            o.methodName = o.method == Method::AKP      ? "AKP" :
                           o.method == Method::BKSS_NEW ? "BKSS" :
                           o.method == Method::BKSS     ? "BKSS_LEGACY" :
                           o.method == Method::FULL_THI ? "FULL_THI" :
                                                          "SPARSE_THI";
        }
        else if (name == "--p")
            o.p = Number(value);
        else if (name == "--order")
            o.order = Number(value);
        else if (name == "--ring-dim")
            o.ringDim = Number(value);
        else if (name == "--slots")
            o.slots = Number(value);
        else if (name == "--sf")
            o.sf = Number(value);
        else if (name == "--level-budget")
            o.levelBudget = Numbers(value);
        else if (name == "--noise-base")
            o.noiseBases = Numbers(value);
        else
            throw std::invalid_argument("Unknown option: " + name);
    }
    if (o.mode != "verify" && o.mode != "precision" && o.mode != "benchmark")
        throw std::invalid_argument("Unknown mode: " + o.mode);
    if (!PowerOfTwo(o.p) || o.p < 4 || o.p > 1024 || !PowerOfTwo(o.ringDim) || o.ringDim < 256 ||
        !PowerOfTwo(o.slots) || o.slots > o.ringDim || o.slots < o.p)
        throw std::invalid_argument("Require power-of-two p in [4,1024], ring >= 256, and p <= slots <= ring");
    if (o.sf < 40 || o.sf > 59 || o.order < 1 || o.order > 5 || o.levelBudget.size() != 2 || o.levelBudget[0] == 0 ||
        o.levelBudget[1] == 0)
        throw std::invalid_argument("Unsupported scale, order or level budget");
    for (auto noise : o.noiseBases)
        if (noise >= o.sf)
            throw std::invalid_argument("Noise base must be smaller than sf");
    if (o.mode != "precision" && o.noiseBases.size() != 1)
        throw std::invalid_argument("Only precision mode accepts multiple noise points");
    return o;
}

struct Record {
    uint32_t run, noiseBase, maxError, keySwitches, levels;
    bool warmup;
    double totalMs, lutMs, inputNoise, lutNoise;
};

int Run(const Options& o) {
    const auto lut = [p = o.p](int64_t x) {
        return x > p / 2 ? x - p : x;
    };
    const auto coefficients = GetHermiteTrigCoefficients(lut, o.p, o.order, o.p, o.method);
    const auto depth =
        FHECKKSRNS::GetFBTDepth(o.levelBudget, coefficients, BigInteger(o.p), o.order, SPARSE_TERNARY, 1, o.method);
    const bool full      = o.slots == o.ringDim;
    const auto ckksSlots = full ? o.slots / 2 : o.slots;
    CCParams<CryptoContextCKKSRNS> params;
    params.SetSecretKeyDist(SPARSE_TERNARY);
    params.SetSecurityLevel(o.unsafe ? HEStd_NotSet : HEStd_128_classic);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetScalingModSize(o.sf);
    params.SetFirstModSize(o.sf);
    params.SetNumLargeDigits(3);
    params.SetBatchSize(ckksSlots);
    params.SetRingDim(o.ringDim);
    params.SetMultiplicativeDepth(depth);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    auto keys          = cc->KeyGen();
    const BigInteger q = BigInteger(1) << o.sf;
    cc->EvalFBTSetup(coefficients, ckksSlots, BigInteger(o.p), BigInteger(o.p), q, keys.publicKey, {0, 0},
                     o.levelBudget, 0, 0, o.order, o.method);
    cc->EvalBootstrapKeyGen(keys.secretKey, ckksSlots);
    cc->EvalMultKeyGen(keys.secretKey);
    const auto ep = SchemeletRLWEMP::GetElementParams(keys.secretKey, depth);
    std::vector<int64_t> input(o.slots);
    for (size_t i = 0; i < input.size(); ++i)
        input[i] = i % o.p;

    std::cout << "CONFIG mode=" << o.mode << " method=" << o.methodName
              << " implementation=" << (o.method == Method::BKSS_NEW ? "BKSS_NEW" : o.methodName) << " p=" << o.p
              << " order=" << o.order << " ring_dim=" << o.ringDim << " slots=" << o.slots << " sf=" << o.sf
              << " level_budget=" << o.levelBudget[0] << ',' << o.levelBudget[1] << " mul_depth=" << depth
              << " eval_exp_degree=58 scaling=FIXEDMANUAL key_dist=SPARSE_TERNARY"
              << " unsafe=" << o.unsafe << " warmups=" << (o.mode == "benchmark" ? 1 : 0)
              << " measured_runs=" << (o.mode == "benchmark" ? 5 : 1) << std::endl;
    std::vector<Record> records;
    uint32_t failures = 0;
    for (auto noiseBase : o.noiseBases) {
        for (uint32_t run = 0; run < (o.mode == "benchmark" ? 6U : 1U); ++run) {
            std::map<std::string, Clock::time_point> times;
            std::map<std::string, uint32_t> stageLevels;
            double inputNoise = -INFINITY, lutNoise = -INFINITY;
            uint32_t keySwitches                = 0;
            FBTInstrumentation::preEvalExpNoise = std::ldexp(1.0, int(noiseBase) - int(o.sf));
            FBTInstrumentation::observer        = [&](ConstCiphertext<DCRTPoly> ct, const std::string& stage) {
                times[stage]       = Clock::now();
                stageLevels[stage] = ct->GetLevel();
                if (stage == "LUT" || stage == "LUT1")
                    keySwitches = FBTInstrumentation::keySwitchCount;
                if (o.mode != "precision")
                    return;
                if (stage.find("CoeffsToSlots") == 0)
                    inputNoise = std::max(
                        inputNoise, fbt_artifact::MeasureSlotNoise(ct, keys.secretKey, o.p, o.slots, !full, 25.0));
                if (stage.find("LUT") == 0)
                    lutNoise = std::max(lutNoise,
                                               fbt_artifact::MeasureSlotNoise(ct, keys.secretKey, o.p, o.slots, !full, 1.0));
            };
            const BigInteger qInit = BigInteger(1) << 60;
            auto rlwe              = SchemeletRLWEMP::EncryptCoeff(input, qInit, BigInteger(o.p), keys.secretKey, ep);
            SchemeletRLWEMP::ModSwitch(rlwe, q, qInit);
            auto ciphertext  = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, rlwe, keys.publicKey, q, ckksSlots, depth);
            const auto start = Clock::now();
            auto output =
                cc->EvalFBT(ciphertext, coefficients, GetMSB(o.p) - 1, ep->GetModulus(), o.p, 0, o.order, o.method);
            const auto end = Clock::now();
            auto result    = SchemeletRLWEMP::ConvertCKKSToRLWE(output, q);
            auto decoded =
                SchemeletRLWEMP::DecryptCoeff(result, q, BigInteger(o.p), keys.secretKey, ep, ckksSlots, o.slots);
            uint32_t maxError = 0;
            if (decoded.size() != input.size())
                throw std::runtime_error("Unexpected decoded length");
            for (size_t i = 0; i < input.size(); ++i)
                maxError = std::max(maxError, uint32_t(std::abs(decoded[i] - lut(input[i]))) % o.p);
            if (maxError)
                ++failures;
            const auto expStage = full ? "Exp1" : "Exp", lutStage = full ? "LUT1" : "LUT";
            const auto totalMs = std::chrono::duration<double, std::milli>(end - start).count();
            const auto lutMs =
                std::chrono::duration<double, std::milli>(times.at(lutStage) - times.at(expStage)).count();
            records.push_back({run, noiseBase, maxError, keySwitches,
                               stageLevels.at(lutStage) - stageLevels.at(expStage), o.mode == "benchmark" && run == 0,
                               totalMs, lutMs, inputNoise, lutNoise});
            std::cerr << "Completed run=" << run << " noise_base=" << noiseBase << " max_error=" << maxError << '\n';
        }
    }
    FBTInstrumentation::observer        = nullptr;
    FBTInstrumentation::preEvalExpNoise = 0;
    std::cout
        << std::setprecision(17)
        << "CSV_BEGIN\nrun,warmup,noise_base,max_error,key_switches,lut_levels,total_ms,lut_ms,input_noise,lut_noise\n";
    for (const auto& r : records)
        std::cout << r.run << ',' << r.warmup << ',' << r.noiseBase << ',' << r.maxError << ',' << r.keySwitches << ','
                  << r.levels << ',' << r.totalMs << ',' << r.lutMs << ',' << r.inputNoise << ',' << r.lutNoise << '\n';
    std::cout << "CSV_END\n";
    cc->ClearStaticMapsAndVectors();
    // Precision sweeps deliberately probe the failure region; each error is retained.
    return o.mode != "precision" && failures ? 1 : 0;
}
}  // namespace

int main(int argc, char** argv) {
    try {
        return Run(Parse(argc, argv));
    }
    catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
