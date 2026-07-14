#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-fhe.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace {

struct FunctionCase {
    std::string name;
    double radius;
    std::reference_wrapper<const std::vector<std::complex<double>>> coefficients;
    std::function<double(double)> target;
};

struct Measurement {
    double precisionBits;
    double maxError;
    double meanError;
    double elapsedMs;
};

enum class MetricKind {
    PrecisionBits,
    MaxError,
    MeanError,
    TimeMs,
};

std::string SecretKeyDistName(SecretKeyDist skd) {
    switch (skd) {
        case SPARSE_TERNARY:
            return "SPARSE_TERNARY";
        case SPARSE_ENCAPSULATED:
            return "SPARSE_ENCAPSULATED";
        case UNIFORM_TERNARY:
            return "UNIFORM_TERNARY";
        default:
            return "UNKNOWN";
    }
}

Measurement MakeNaNMeasurement() {
    const double nan = std::numeric_limits<double>::quiet_NaN();
    return {nan, nan, nan, nan};
}

Measurement ComputeMeasurement(const std::vector<double>& expected, const std::vector<double>& actual, double elapsedMs) {
    if (expected.empty() || actual.empty()) {
        return MakeNaNMeasurement();
    }

    const size_t count = std::min(expected.size(), actual.size());
    double maxError    = 0.0;
    double sumError    = 0.0;
    for (size_t i = 0; i < count; ++i) {
        const double error = std::abs(expected[i] - actual[i]);
        maxError           = std::max(maxError, error);
        sumError += error;
    }

    const double meanError = sumError / static_cast<double>(count);
    const double precisionBits =
        (maxError == 0.0) ? std::numeric_limits<double>::infinity() : -std::log2(maxError);

    return {precisionBits, maxError, meanError, elapsedMs};
}

double GetMetricValue(const Measurement& measurement, MetricKind metric) {
    switch (metric) {
        case MetricKind::PrecisionBits:
            return measurement.precisionBits;
        case MetricKind::MaxError:
            return measurement.maxError;
        case MetricKind::MeanError:
            return measurement.meanError;
        case MetricKind::TimeMs:
            return measurement.elapsedMs;
    }

    return std::numeric_limits<double>::quiet_NaN();
}

void PrintValue(double value, int width, MetricKind metric) {
    if (std::isnan(value)) {
        std::cout << std::setw(width) << "n/a";
    }
    else {
        if (metric == MetricKind::MaxError || metric == MetricKind::MeanError) {
            std::cout << std::setw(width) << std::scientific << std::setprecision(6) << value;
        }
        else {
            std::cout << std::setw(width) << std::fixed << std::setprecision(4) << value;
        }
    }
}

void PrintTable(const std::string& title, const std::vector<SecretKeyDist>& skds,
                const std::vector<FunctionCase>& functions, const std::vector<std::vector<Measurement>>& results,
                MetricKind metric) {
    std::cout << "\n" << title << "\n";
    std::cout << std::left << std::setw(24) << "SecretKeyDist";
    for (const auto& functionCase : functions) {
        std::cout << std::right << std::setw(16) << functionCase.name;
    }
    std::cout << "\n";

    for (size_t i = 0; i < skds.size(); ++i) {
        std::cout << std::left << std::setw(24) << SecretKeyDistName(skds[i]);
        for (size_t j = 0; j < functions.size(); ++j) {
            const double value = GetMetricValue(results[i][j], metric);
            PrintValue(value, 16, metric);
        }
        std::cout << "\n";
    }
}

std::vector<double> BuildNormalizedInput(size_t slots) {
    std::vector<double> input(slots);
    constexpr double left = -0.5;
    constexpr double right = 0.5;
    for (size_t i = 0; i < slots; ++i) {
        input[i] = left + static_cast<double>(i) * (right - left) / static_cast<double>(slots);
    }
    return input;
}

Measurement RunCase(const CryptoContext<DCRTPoly>& cc, const KeyPair<DCRTPoly>& keyPair,
                    ConstCiphertext<DCRTPoly> input, const std::vector<double>& normalizedInput,
                    const FunctionCase& functionCase) {
    std::cout << "  [CASE] start " << functionCase.name << std::endl;
    std::vector<double> expected(normalizedInput.size());
    for (size_t i = 0; i < normalizedInput.size(); ++i) {
        expected[i] = functionCase.target(2.0 * functionCase.radius * normalizedInput[i]);
    }

    auto start = std::chrono::high_resolution_clock::now();
    auto output = cc->EvalFEFuncBootstrap(input, functionCase.coefficients.get());
    auto stop = std::chrono::high_resolution_clock::now();

    Plaintext decrypted;
    cc->Decrypt(keyPair.secretKey, output, &decrypted);
    decrypted->SetLength(expected.size());
    const auto actual = decrypted->GetRealPackedValue();

    double elapsedMs = std::chrono::duration<double, std::milli>(stop - start).count();
    auto measurement = ComputeMeasurement(expected, actual, elapsedMs);
    std::cout << "  [CASE] done  " << functionCase.name << " | precision(bits)=" << measurement.precisionBits
              << " | maxerror=" << measurement.maxError << " | meanerror=" << measurement.meanError
              << " | time(ms)=" << measurement.elapsedMs << std::endl;
    return measurement;
}

}  // namespace

int main() {
    const uint32_t ringDim = 1 << 16;
    const uint32_t numSlots = ringDim / 2;
    const std::vector<uint32_t> levelBudget = {3, 2};
    const std::vector<uint32_t> bsgsDim = {0, 0};
    const usint dcrtBits = 59;
    const usint firstMod = 60;
    const usint depth = levelBudget[0] + levelBudget[1] + 12 + 9;

    const std::vector<SecretKeyDist> secretKeyDists = {
        SPARSE_TERNARY,
        SPARSE_ENCAPSULATED,
        UNIFORM_TERNARY,
    };

    const std::vector<FunctionCase> functions = {
        {"exp[-2,2]", 2.0, FHECKKSRNS::GetFEExpCoefficients(),
         [](double x) { return std::exp(x); }},
        {"sigmoid[-8,8]", 8.0, FHECKKSRNS::GetFESigmoidCoefficients(),
         [](double x) { return 1.0 / (1.0 + std::exp(-x)); }},
        // The hardcoded GELU coefficients come from the FEFBS tanh-based approximation.
        {"gelu_tanh[-8,8]", 8.0, FHECKKSRNS::GetFEGeluCoefficients(),
         [](double x) {
             return 0.5 * x * (1.0 + std::tanh(std::sqrt(2.0 / M_PI) * (x + 0.044715 * std::pow(x, 3))));
         }},
    };

    std::vector<std::vector<Measurement>> results(secretKeyDists.size(),
                                                  std::vector<Measurement>(functions.size(), MakeNaNMeasurement()));

    std::cout << "Running CKKS FEFBS example across 3 key distributions and 3 function coefficient sets.\n";
    std::cout << "Ring dimension: " << ringDim << ", slots: " << numSlots << ", depth: " << depth << "\n";

    for (size_t i = 0; i < secretKeyDists.size(); ++i) {
        const auto skd = secretKeyDists[i];
        try {
            std::cout << "\n[SKD] begin " << SecretKeyDistName(skd) << std::endl;
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetCKKSDataType(COMPLEX);
            parameters.SetSecretKeyDist(skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetRingDim(ringDim);
            parameters.SetNumLargeDigits(3);
            parameters.SetKeySwitchTechnique(HYBRID);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetFirstModSize(firstMod);
            parameters.SetBatchSize(numSlots);
            parameters.SetMultiplicativeDepth(depth);

            CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
            std::cout << "[SKD] context ready" << std::endl;
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            std::cout << "[SKD] EvalFEFuncBootstrapSetup..." << std::endl;
            cc->EvalFEFuncBootstrapSetup(levelBudget, bsgsDim, numSlots);
            std::cout << "[SKD] EvalFEFuncBootstrapSetup done" << std::endl;

            std::cout << "[SKD] KeyGen..." << std::endl;
            auto keyPair = cc->KeyGen();
            std::cout << "[SKD] KeyGen done" << std::endl;

            std::cout << "[SKD] EvalMultKeyGen..." << std::endl;
            cc->EvalMultKeyGen(keyPair.secretKey);
            std::cout << "[SKD] EvalMultKeyGen done" << std::endl;

            std::cout << "[SKD] EvalBootstrapKeyGen..." << std::endl;
            cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);
            std::cout << "[SKD] EvalBootstrapKeyGen done" << std::endl;

            const auto normalizedInput = BuildNormalizedInput(numSlots);
            Plaintext plaintext = cc->MakeCKKSPackedPlaintext(
                normalizedInput, 1, depth - (levelBudget[1] + 1), nullptr, numSlots);
            std::cout << "[SKD] Encrypt..." << std::endl;
            auto input = cc->Encrypt(keyPair.publicKey, plaintext);
            std::cout << "[SKD] Encrypt done" << std::endl;

            for (size_t j = 0; j < functions.size(); ++j) {
                try {
                    results[i][j] = RunCase(cc, keyPair, input, normalizedInput, functions[j]);
                }
                catch (const std::exception& e) {
                    std::cerr << "[WARN] " << SecretKeyDistName(skd) << " / " << functions[j].name
                              << " failed: " << e.what() << "\n";
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[WARN] setup failed for " << SecretKeyDistName(skd) << ": " << e.what() << "\n";
        }
    }

    PrintTable("Precision Table (bits)", secretKeyDists, functions, results, MetricKind::PrecisionBits);
    PrintTable("Max Error Table", secretKeyDists, functions, results, MetricKind::MaxError);
    PrintTable("Mean Error Table", secretKeyDists, functions, results, MetricKind::MeanError);
    PrintTable("Time Table (ms)", secretKeyDists, functions, results, MetricKind::TimeMs);

    return 0;
}
