#include <mysql.h>
#include <iostream>
#include "openfhe.h"

using namespace lbcrypto;

extern "C" {

bool hermes_udf_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    return 0;
}

void hermes_udf_deinit(UDF_INIT* initid) {}

long long hermes_udf(UDF_INIT* initid, UDF_ARGS* args, char* is_null, char* error) {
    // Step 1: Create BFV context
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);  // Large enough for simple integers
    parameters.SetMultiplicativeDepth(1);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);

    // Step 2: Key generation
    auto kp = cc->KeyGen();

    // Step 3: Encrypt a constant
    Plaintext pt = cc->MakePackedPlaintext(std::vector<int64_t>{123});
    auto ct = cc->Encrypt(kp.publicKey, pt);

    // Step 4: Decrypt
    Plaintext result;
    cc->Decrypt(kp.secretKey, ct, &result);
    result->SetLength(1);

    // Step 5: Return the first slot value to MySQL
    return result->GetPackedValue()[0];
}

}