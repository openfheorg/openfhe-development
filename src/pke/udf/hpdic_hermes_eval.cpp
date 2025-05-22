#include <mysql.h>
#include <iostream>
#include "openfhe.h"

using namespace lbcrypto;

extern "C" {

// MySQL plugin init function (can remain minimal)
bool hermes_udf_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    return 0;
}

void hermes_udf_deinit(UDF_INIT* initid) {}

// Main UDF function
long long hermes_udf(UDF_INIT* initid, UDF_ARGS* args, char* is_null, char* error) {
    // Step 1: CryptoContext setup
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    // Step 2: KeyGen
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);

    // Step 3: Encode and Encrypt input vectors
    std::vector<int64_t> v1 = {3, 4, 5};
    std::vector<int64_t> v2 = {6, 7, 8};
    auto pt1 = cc->MakePackedPlaintext(v1);
    auto pt2 = cc->MakePackedPlaintext(v2);
    auto ct1 = cc->Encrypt(kp.publicKey, pt1);
    auto ct2 = cc->Encrypt(kp.publicKey, pt2);

    // Step 4: Homomorphic operations
    auto ct_add = cc->EvalAdd(ct1, ct2);
    auto ct_mul = cc->EvalMult(ct1, ct2);

    // Step 5: Decrypt
    Plaintext pt_add, pt_mul;
    cc->Decrypt(kp.secretKey, ct_add, &pt_add);
    cc->Decrypt(kp.secretKey, ct_mul, &pt_mul);

    pt_add->SetLength(v1.size());
    pt_mul->SetLength(v1.size());

    // Optional: Print for logging (visible only in syslog or stderr)
    std::cerr << "Addition result: " << pt_add << std::endl;
    std::cerr << "Multiplication result: " << pt_mul << std::endl;

    // Step 6: Return first slot of addition as example
    return pt_add->GetPackedValue()[0];
}

}