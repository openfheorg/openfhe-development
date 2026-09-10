// BSD 2-Clause License; see LICENSE.
// Opt-in research instrumentation. Never enabled in a default library build.
#ifndef OPENFHE_CKKSRNS_FBT_INSTRUMENTATION_H
#define OPENFHE_CKKSRNS_FBT_INSTRUMENTATION_H

#ifdef OPENFHE_FBT_INSTRUMENTATION
    #include "ciphertext.h"
    #include <functional>
    #include <string>

namespace lbcrypto {
struct FBTInstrumentation {
    // State belongs to the calling thread. The observer may decrypt in precision
    // mode; benchmark mode only records timestamps and operation counts.
    static inline thread_local std::function<void(ConstCiphertext<DCRTPoly>, const std::string&)> observer;
    static inline thread_local double preEvalExpNoise  = 0.0;
    static inline thread_local uint32_t keySwitchCount = 0;

    static void Checkpoint(ConstCiphertext<DCRTPoly> ciphertext, const std::string& stage) {
        if (observer)
            observer(ciphertext, stage);
    }
};
}  // namespace lbcrypto
#endif
#endif
