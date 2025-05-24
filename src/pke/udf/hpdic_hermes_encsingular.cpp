#include <mysql.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <stdexcept>
#include "openfhe.h"

using namespace lbcrypto;

// === 全局上下文 ===
CryptoContext<DCRTPoly> g_context;
KeyPair<DCRTPoly> g_kp;
bool g_context_initialized = false;

void InitBFVContext() {
    if (g_context_initialized) return;

    std::cerr << "[HERMES] Initializing BFV context..." << std::endl;
    CCParams<CryptoContextBFVRNS> params;
    params.SetPlaintextModulus(65537);
    params.SetMultiplicativeDepth(2);
    g_context = GenCryptoContext(params);
    g_context->Enable(PKE);
    g_context->Enable(LEVELEDSHE);
    g_context->Enable(ADVANCEDSHE);

    g_kp = g_context->KeyGen();
    g_context->EvalMultKeyGen(g_kp.secretKey);
    g_context->EvalSumKeyGen(g_kp.secretKey);

    g_context_initialized = true;
    std::cerr << "[HERMES] BFV context and keys initialized" << std::endl;
}

extern "C" {

bool HERMES_ENC_SINGULAR_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    if (args->arg_count != 1) {
        std::strcpy(message, "HERMES_ENC_SINGULAR expects exactly 1 argument.");
        return 1;
    }

    if (args->arg_type[0] != INT_RESULT && args->arg_type[0] != STRING_RESULT) {
        std::strcpy(message, "HERMES_ENC_SINGULAR only accepts INT or STRING arguments.");
        return 1;
    }

    // 为返回字符串分配空间
    initid->ptr = new char[1024];
    initid->maybe_null = 1;
    initid->max_length = 1024;
    return 0;
}

char* HERMES_ENC_SINGULAR(UDF_INIT* initid, UDF_ARGS* args,
                          char* /*result*/, unsigned long* length,
                          char* is_null, char* error) {
    try {
        InitBFVContext();

        if (!args->args[0]) {
            std::cerr << "[HERMES] NULL input received." << std::endl;
            *is_null = 1;
            return nullptr;
        }

        int64_t val = 0;

        if (args->arg_type[0] == INT_RESULT) {
            val = *reinterpret_cast<long long*>(args->args[0]);
        } else {
            std::string arg_str(args->args[0]);
            std::istringstream iss(arg_str);
            if (!(iss >> val)) {
                std::cerr << "[HERMES] Failed to parse integer from input string: " << arg_str << std::endl;
                *is_null = 1;
                return nullptr;
            }
        }

        std::cerr << "[HERMES] Encrypting value: " << val << std::endl;
        Plaintext pt = g_context->MakePackedPlaintext({val});
        pt->SetLength(1);
        auto ct = g_context->Encrypt(g_kp.publicKey, pt);

        Plaintext decrypted_pt;
        g_context->Decrypt(g_kp.secretKey, ct, &decrypted_pt);
        decrypted_pt->SetLength(1);
        auto packed = decrypted_pt->GetPackedValue();
        int64_t decrypted = packed.empty() ? -999 : packed[0];

        uintptr_t addr = reinterpret_cast<uintptr_t>(ct.get());
        size_t size = sizeof(*ct);

        std::ostringstream oss;
        oss << "0x" << std::hex << addr << " (" << std::dec << decrypted << ", size=" << size << ")";
        std::string out = oss.str();

        char* buffer = static_cast<char*>(initid->ptr);
        size_t copy_len = std::min(out.size(), static_cast<size_t>(1023));
        std::memcpy(buffer, out.c_str(), copy_len);
        buffer[copy_len] = '\0';
        *length = copy_len;

        return buffer;
    } catch (const std::exception& e) {
        std::cerr << "[HERMES] Exception: " << e.what() << std::endl;
        *is_null = 1;
        return nullptr;
    } catch (...) {
        std::cerr << "[HERMES] Unknown fatal error." << std::endl;
        *is_null = 1;
        return nullptr;
    }
}

void HERMES_ENC_SINGULAR_deinit(UDF_INIT* initid) {
    delete[] static_cast<char*>(initid->ptr);
    initid->ptr = nullptr;
}

}  // extern "C"