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
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    return 42;
}

}