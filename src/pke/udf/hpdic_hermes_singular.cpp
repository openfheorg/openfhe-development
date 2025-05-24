/*
 * HERMES MySQL UDF Plugin
 * ----------------------------------------------
 * This file implements a set of MySQL user-defined functions (UDFs)
 * that support homomorphic encryption (HE) operations via OpenFHE,
 * including encryption, decryption, and ciphertext aggregation.
 *
 * Author: Dongfang Zhao
 * Institution: University of Washington
 * Last Updated: 2025
 *
 * Overview:
 * This plugin provides a minimal pipeline for performing encrypted
 * computation over single-slot BFV ciphertexts inside MySQL.
 *
 * Key Features:
 * - `HERMES_ENC_SINGULAR_BFV`: Encrypts an integer input into a BFV ciphertext (base64).
 * - `HERMES_DEC_SINGULAR_BFV`: Decrypts a base64-encoded BFV ciphertext back to plaintext.
 * - `HERMES_SUM_BFV`: A true SQL-compliant AGGREGATE FUNCTION that performs homomorphic summation over BFV ciphertexts and returns the plaintext total.
 * - `HERMES_ENC_SINGULAR`: A debugging variant that returns a pointer string and decrypted value preview.
 *
 * Technical Highlights:
 * - Uses OpenFHE (BFV scheme) with plaintext modulus 65537 and multiplicative depth 2.
 * - Implements MySQL’s UDF interface including full six-piece aggregation (init, add, func, clear, reset, deinit).
 * - Supports direct integration with SQL queries including GROUP BY.
 * - Encodes and decodes ciphertexts using OpenFHE's binary serializer and manual base64 encoding.
 *
 * Limitations:
 * - Only supports single-slot packed plaintexts (i.e., vectors of size 1).
 * - Encryption and decryption use static, in-memory keys shared across all UDF calls.
 * - No support yet for key separation or rotation.
 *
 * Recommended Usage:
 *   SELECT HERMES_SUM_BFV(salary_enc_bfv) FROM employee_enc_bfv;
 *   SELECT department, HERMES_SUM_BFV(salary_enc_bfv) FROM employee_enc_bfv GROUP BY department;
 *   INSERT INTO table (...) VALUES (..., HERMES_ENC_SINGULAR_BFV(12345));
 *
 * Note:
 * This code is part of the HERMES project exploring practical encrypted data processing inside relational databases.
 */

#include <mysql.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <stdexcept>
#include "openfhe.h"

using namespace lbcrypto;

// ========== 聚合上下文结构 ==========
struct HermesSumContext {
    Ciphertext<DCRTPoly> acc;
    bool initialized;
};

// ========== Base64 解码 ==========
static std::string decodeBase64(const std::string& in) {
    static const std::string b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T[b64_chars[i]] = i;
    int val = 0, valb = -8;
    for (uint8_t c : in) {
        if (T[c] == -1)
            break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// === 全局上下文 ===
CryptoContext<DCRTPoly> g_context;
KeyPair<DCRTPoly> g_kp;
bool g_context_initialized = false;

void InitBFVContext() {
    if (g_context_initialized)
        return;

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

// ========== INIT ==========
bool HERMES_SUM_BFV_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
        std::strcpy(message, "HERMES_SUM_BFV expects one base64-encoded ciphertext string.");
        return 1;
    }
    auto* ctx          = new HermesSumContext();
    ctx->initialized   = false;
    initid->ptr        = reinterpret_cast<char*>(ctx);
    initid->maybe_null = 1;
    return 0;
}

// ========== ADD ==========
bool HERMES_SUM_BFV_add(UDF_INIT* initid, UDF_ARGS* args, char* is_null, char* error) {
    try {
        InitBFVContext();
        if (!args->args[0])
            return 0;

        std::string encoded(args->args[0], args->lengths[0]);
        std::string bin = decodeBase64(encoded);
        std::stringstream ss(bin);

        Ciphertext<DCRTPoly> ct;
        Serial::Deserialize(ct, ss, SerType::BINARY);

        auto* ctx = reinterpret_cast<HermesSumContext*>(initid->ptr);
        if (!ctx->initialized) {
            ctx->acc         = ct;
            ctx->initialized = true;
        }
        else {
            ctx->acc = g_context->EvalAdd(ctx->acc, ct);
        }
        return 0;
    }
    catch (...) {
        *is_null = 1;
        *error   = 1;
        return 1;
    }
}

// ========== FUNC ==========
long long HERMES_SUM_BFV(UDF_INIT* initid, UDF_ARGS*, char* is_null, char* error) {
    try {
        InitBFVContext();
        auto* ctx = reinterpret_cast<HermesSumContext*>(initid->ptr);
        if (!ctx->initialized) {
            *is_null = 1;
            return 0;
        }
        Plaintext pt;
        g_context->Decrypt(g_kp.secretKey, ctx->acc, &pt);
        pt->SetLength(1);
        auto packed = pt->GetPackedValue();
        return static_cast<long long>(packed.empty() ? 0 : packed[0]);
    }
    catch (...) {
        *is_null = 1;
        *error   = 1;
        return 0;
    }
}

// ========== CLEAR ==========
void HERMES_SUM_BFV_clear(UDF_INIT* initid, char*, char*) {
    auto* ctx        = reinterpret_cast<HermesSumContext*>(initid->ptr);
    ctx->initialized = false;
}

// ========== RESET ==========
bool HERMES_SUM_BFV_reset(UDF_INIT* initid, UDF_ARGS* args, char* is_null, char* error) {
    HERMES_SUM_BFV_clear(initid, is_null, error);
    return HERMES_SUM_BFV_add(initid, args, is_null, error);
}

// ========== DEINIT ==========
void HERMES_SUM_BFV_deinit(UDF_INIT* initid) {
    delete reinterpret_cast<HermesSumContext*>(initid->ptr);
}

bool HERMES_DEC_SINGULAR_BFV_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
        std::strcpy(message, "HERMES_DEC_SINGULAR_BFV requires exactly one base64-encoded string.");
        return 1;
    }

    initid->maybe_null = 1;
    return 0;
}

long long HERMES_DEC_SINGULAR_BFV(UDF_INIT* initid, UDF_ARGS* args, char* is_null, char* error) {
    try {
        InitBFVContext();

        if (!args->args[0]) {
            *is_null = 1;
            return 0;
        }

        // Base64 decode
        std::string encoded(args->args[0]);
        static const std::string b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        auto decode64                      = [](const std::string& in) -> std::string {
            std::string out;
            std::vector<int> T(256, -1);
            for (int i = 0; i < 64; i++)
                T[b64_chars[i]] = i;
            int val = 0, valb = -8;
            for (uint8_t c : in) {
                if (T[c] == -1)
                    break;
                val = (val << 6) + T[c];
                valb += 6;
                if (valb >= 0) {
                    out.push_back(char((val >> valb) & 0xFF));
                    valb -= 8;
                }
            }
            return out;
        };

        std::string decoded = decode64(encoded);
        std::stringstream ss(decoded);

        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ct;
        Serial::Deserialize(ct, ss, SerType::BINARY);

        lbcrypto::Plaintext pt;
        g_context->Decrypt(g_kp.secretKey, ct, &pt);
        pt->SetLength(1);

        auto packed        = pt->GetPackedValue();
        int64_t result_val = (packed.empty() ? 0 : packed[0]);

        return static_cast<long long>(result_val);
    }
    catch (...) {
        *is_null = 1;
        return 0;
    }
}

void HERMES_DEC_SINGULAR_BFV_deinit(UDF_INIT* initid) {
    // 无需释放 ptr，因为没有分配内存
}

bool HERMES_ENC_SINGULAR_BFV_init(UDF_INIT* initid, UDF_ARGS* args, char* message) {
    if (args->arg_count != 1 || args->arg_type[0] != INT_RESULT) {
        std::strcpy(message, "HERMES_ENC_SINGULAR_BFV requires 1 integer argument.");
        return 1;
    }

    initid->maybe_null = 1;
    initid->max_length = 65535;  // TEXT 支持
    initid->ptr        = nullptr;
    return 0;
}

char* HERMES_ENC_SINGULAR_BFV(UDF_INIT* initid, UDF_ARGS* args, char* /*result*/, unsigned long* length, char* is_null,
                              char* error) {
    try {
        InitBFVContext();

        if (!args->args[0]) {
            *is_null = 1;
            return nullptr;
        }

        int64_t val  = *reinterpret_cast<long long*>(args->args[0]);
        Plaintext pt = g_context->MakePackedPlaintext({val});
        pt->SetLength(1);

        auto ct = g_context->Encrypt(g_kp.publicKey, pt);

        // 序列化密文
        std::stringstream ss;
        Serial::Serialize(ct, ss, SerType::BINARY);
        std::string raw = ss.str();

        // Base64 编码
        static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        auto encode64                   = [&](const std::string& input) -> std::string {
            std::string out;
            int val = 0, valb = -6;
            for (uint8_t c : input) {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0) {
                    out.push_back(base64_chars[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6)
                out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
            while (out.size() % 4)
                out.push_back('=');
            return out;
        };

        std::string encoded = encode64(raw);
        char* output        = strdup(encoded.c_str());

        *length  = encoded.size();
        *is_null = 0;
        *error   = 0;
        return output;
    }
    catch (...) {
        *is_null = 1;
        return nullptr;
    }
}

void HERMES_ENC_SINGULAR_BFV_deinit(UDF_INIT* initid) {
    if (initid->ptr) {
        delete[] static_cast<char*>(initid->ptr);
        initid->ptr = nullptr;
    }
}

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
    initid->ptr        = new char[1024];
    initid->maybe_null = 1;
    initid->max_length = 1024;
    return 0;
}

char* HERMES_ENC_SINGULAR(UDF_INIT* initid, UDF_ARGS* args, char* /*result*/, unsigned long* length, char* is_null,
                          char* error) {
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
        }
        else {
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
        auto packed       = decrypted_pt->GetPackedValue();
        int64_t decrypted = packed.empty() ? -999 : packed[0];

        uintptr_t addr = reinterpret_cast<uintptr_t>(ct.get());
        size_t size    = sizeof(*ct);

        std::ostringstream oss;
        oss << "0x" << std::hex << addr << " (" << std::dec << decrypted << ", size=" << size << ")";
        std::string out = oss.str();

        char* buffer    = static_cast<char*>(initid->ptr);
        size_t copy_len = std::min(out.size(), static_cast<size_t>(1023));
        std::memcpy(buffer, out.c_str(), copy_len);
        buffer[copy_len] = '\0';
        *length          = copy_len;

        return buffer;
    }
    catch (const std::exception& e) {
        std::cerr << "[HERMES] Exception: " << e.what() << std::endl;
        *is_null = 1;
        return nullptr;
    }
    catch (...) {
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