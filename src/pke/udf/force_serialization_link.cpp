#include "openfhe.h"
#include "utils/serial.h"

namespace {
    using FnPtr = std::string (*)(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>&);
    [[maybe_unused]] auto dummy_ptr = static_cast<FnPtr>(&lbcrypto::Serial::SerializeToString);
}