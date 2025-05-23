#include <mysql.h>
#include <iostream>
#include "openfhe.h"

using namespace lbcrypto;

extern "C" {

// MySQL UDF initialization function (optional)
bool hermes_udf_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    return 0;
}

// Cleanup function (optional)
void hermes_udf_deinit(UDF_INIT* initid) {}

// Main UDF logic
long long hermes_udf(UDF_INIT* initid, UDF_ARGS* args, char* is_null, char* error) {
    try {
        // Step 1: CryptoContext setup
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(65537);
        parameters.SetMultiplicativeDepth(2);
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);  // 💥关键：EvalSum 等需要这个！

        // Step 2: Key generation
        auto kp = cc->KeyGen();
        cc->EvalMultKeyGen(kp.secretKey);
        cc->EvalSumKeyGen(kp.secretKey);  // Needed for inner product

        // Step 3: Plaintext vectors
        std::vector<int64_t> v1 = {3, 4, 5}; // Simulated column 1
        std::vector<int64_t> v2 = {6, 7, 8}; // Simulated column 2

        auto pt1 = cc->MakePackedPlaintext(v1);
        auto pt2 = cc->MakePackedPlaintext(v2);

        // Step 4: Encrypt
        auto ct1 = cc->Encrypt(kp.publicKey, pt1);
        auto ct2 = cc->Encrypt(kp.publicKey, pt2);

        // Step 5: Multiply elementwise
        auto ct_mul = cc->EvalMult(ct1, ct2);

        // Step 6: Sum all slots to get inner product
        auto ct_inner = cc->EvalSum(ct_mul, v1.size());

        // Step 7: Decrypt
        Plaintext pt_result;
        cc->Decrypt(kp.secretKey, ct_inner, &pt_result);
        pt_result->SetLength(1);  // All slots contain the same inner product after EvalSum

        int64_t result = pt_result->GetPackedValue()[0];

        std::cerr << "[hermes_udf] Inner product = " << result << std::endl;

        return result;

    } catch (const std::exception& e) {
        std::cerr << "[hermes_udf] Exception: " << e.what() << std::endl;
        *is_null = 1;
        return 0;
    } catch (...) {
        std::cerr << "[hermes_udf] Unknown error" << std::endl;
        *is_null = 1;
        return 0;
    }
}

}