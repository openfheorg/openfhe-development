//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#ifndef SRC_PKE_INCLUDE_SCHEMERNS_RNS_MULTIPARTY_H_
#define SRC_PKE_INCLUDE_SCHEMERNS_RNS_MULTIPARTY_H_

#include <cstdint>
#include <string>

#include "lattice/lat-hal.h"
#include "schemebase/base-multiparty.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface class for LBC Multiparty algorithms based on
 * threshold FHE.  A version of this multiparty scheme built on the BGV scheme
 * is seen here:
 *   - Asharov G., Jain A., López-Alt A., Tromer E., Vaikuntanathan V., Wichs
 * D. (2012) Multiparty Computation with Low Communication, Computation and
 * Interaction via Threshold FHE. In: Pointcheval D., Johansson T. (eds)
 * Advances in Cryptology – EUROCRYPT 2012. EUROCRYPT 2012. Lecture Notes in
 * Computer Science, vol 7237. Springer, Berlin, Heidelberg
 *
 * During offline key generation, this multiparty scheme relies on the clients
 * coordinating their public key generation.  To do this, a single client
 * generates a public-secret key pair. This public key is shared with other
 * keys which use an element in the public key to generate their own public
 * keys. The clients generate a shared key pair using a scheme-specific
 * approach, then generate re-encryption keys.  Re-encryption keys are
 * uploaded to the server. Clients encrypt data with their public keys and
 * send the encrypted data server. The data is re-encrypted.  Computations are
 * then run on the data. The result is sent to each of the clients. One client
 * runs a "Leader" multiparty decryption operation with its own secret key.
 * All other clients run a regular "Main" multiparty decryption with their own
 * secret key. The resulting partially decrypted ciphertext are then fully
 * decrypted with the decryption fusion algorithms.
 */
class MultipartyRNS : public MultipartyBase<DCRTPoly> {
    using ParmType = typename DCRTPoly::Params;
    using IntType = typename DCRTPoly::Integer;
    using DugType = typename DCRTPoly::DugType;
    using DggType = typename DCRTPoly::DggType;
    using TugType = typename DCRTPoly::TugType;

  public:
    virtual ~MultipartyRNS() = default;

    /**
     * Threshold FHE: "Partial" decryption computed by all parties except for the lead one. Returns s*c_1 plus
     * flooding noise: uniform noise expanded from the last towers in NOISE_FLOODING_MULTIPARTY mode, Gaussian
     * noise from the flooding generator in NOISE_FLOODING_DECRYPT mode, or fixed Gaussian noise otherwise.
     *
     * @param ciphertext ciphertext that is being decrypted.
     * @param privateKey secret key share used for decryption.
     * @return the partial decryption.
     */
    Ciphertext<DCRTPoly> MultipartyDecryptMain(ConstCiphertext<DCRTPoly> ciphertext,
                                               const PrivateKey<DCRTPoly> privateKey) const override;

    /**
     * Threshold FHE: Method for decryption operation run by the lead decryption client. Returns c_0 + s*c_1
     * plus flooding noise chosen as in MultipartyDecryptMain().
     *
     * @param ciphertext ciphertext that is being decrypted.
     * @param privateKey secret key share used for decryption.
     * @return the partial decryption.
     */
    Ciphertext<DCRTPoly> MultipartyDecryptLead(ConstCiphertext<DCRTPoly> ciphertext,
                                               const PrivateKey<DCRTPoly> privateKey) const override;

    /**
     * Threshold FHE: Generates a partial evaluation key for homomorphic multiplication by multiplying both
     * vectors of an existing partial evaluation key by the current secret share and adding fresh noise. For
     * HYBRID key switching the secret share is first extended to the basis QP.
     *
     * @param privateKey current secret share.
     * @param evalKey prior evaluation key.
     * @return the new joined key.
     */
    EvalKey<DCRTPoly> MultiMultEvalKey(PrivateKey<DCRTPoly> privateKey, EvalKey<DCRTPoly> evalKey) const override;

    /**
     * Interactive bootstrapping: masked decryption with rounding. For a two-polynomial ciphertext (server) it
     * computes c_0 + c_1*s; for a one-polynomial ciphertext (client) it computes c_0*s. The result is rounded
     * to prevent an overflow when the two masked decryptions are later added.
     *
     * @param privateKey secret key share.
     * @param ciphertext input ciphertext with one or two polynomials.
     * @return the masked decryption as a single-polynomial ciphertext.
     */
    Ciphertext<DCRTPoly> IntBootDecrypt(const PrivateKey<DCRTPoly> privateKey,
                                        ConstCiphertext<DCRTPoly> ciphertext) const override;

    /**
     * Interactive bootstrapping: public-key encryption of the client's masked decryption. The input polynomial
     * (2 RNS limbs) is first extended to the full modulus chain Q, and the encoding metadata of the input
     * ciphertext is copied to the result, with the level reset to 0.
     *
     * @param publicKey joint public key based on Threshold FHE.
     * @param ciphertext input ciphertext holding the masked decryption.
     * @return the resulting encryption.
     */
    Ciphertext<DCRTPoly> IntBootEncrypt(const PublicKey<DCRTPoly> publicKey,
                                        ConstCiphertext<DCRTPoly> ciphertext) const override;

    /**
     * Interactive bootstrapping: adds the encrypted masked decryption and the unencrypted masked decryption
     * (which is first extended to the full modulus chain Q), producing the refreshed ciphertext.
     *
     * @param ciphertext1 encrypted masked decryption.
     * @param ciphertext2 unencrypted masked decryption (a single polynomial with 2 RNS limbs).
     * @return the refreshed ciphertext.
     */
    Ciphertext<DCRTPoly> IntBootAdd(ConstCiphertext<DCRTPoly> ciphertext1,
                                    ConstCiphertext<DCRTPoly> ciphertext2) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string SerializedObjectName() const {
        return "MultipartyRNS";
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEMERNS_RNS_MULTIPARTY_H_
