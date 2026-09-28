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
#ifndef SRC_PKE_INCLUDE_SCHEMEBASE_BASE_CRYPTOPARAMETERS_H_
#define SRC_PKE_INCLUDE_SCHEMEBASE_BASE_CRYPTOPARAMETERS_H_

#include <cstdint>
#include <memory>
#include <string>

#include "encoding/encodings.h"
#include "encoding/plaintext.h"
#include "utils/serializable.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief main implementation class to capture essential cryptoparameters of
 * any LBC system
 * @tparam Element a ring element.
 */
template <typename Element>
class CryptoParametersBase : public Serializable {
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;
    using DugType = typename Element::DugType;
    using DggType = typename Element::DggType;
    using TugType = typename Element::TugType;

  public:
    CryptoParametersBase() = default;

    virtual ~CryptoParametersBase() = default;

    // NOTE: some getters and setters are declared "virtual" as they should be overriden and disabled in
    // some scheme-specific parameter classes derived from CryptoParametersBase
    /**
     * Returns the value of plaintext modulus p
     *
     * @return the plaintext modulus.
     */
    virtual PlaintextModulus GetPlaintextModulus() const {
        return m_encodingParams->GetPlaintextModulus();
    }

    uint32_t GetBatchSize() const {
        return m_encodingParams->GetBatchSize();
    }

    /**
     * Returns the reference to IL params
     *
     * @return the ring element parameters.
     */
    const std::shared_ptr<typename Element::Params> GetElementParams() const {
        return m_params;
    }

    uint32_t GetRingDimension() const {
        return m_params->GetRingDimension();
    }

    /**
     * Returns the element parameters used for public key generation and public-key encryption; a scheme
     * may extend the ciphertext parameters here (e.g., with the auxiliary or extra moduli needed by
     * HRA-secure PRE or by the EXTENDED encryption technique).
     *
     * @return the element parameters for the public key.
     */
    virtual const std::shared_ptr<typename Element::Params> GetParamsPK() const = 0;

    /**
     * Returns the reference to encoding params
     *
     * @return the encoding parameters.
     */
    const EncodingParams GetEncodingParams() const {
        return m_encodingParams;
    }

    /**
     * Sets the value of plaintext modulus p
     * @param plaintextModulus the plaintext modulus
     */
    void SetPlaintextModulus(PlaintextModulus plaintextModulus) {
        m_encodingParams->SetPlaintextModulus(plaintextModulus);
    }

    void SetBatchSize(uint32_t batchSize) {
        m_encodingParams->SetBatchSize(batchSize);
    }

    bool operator==(const CryptoParametersBase<Element>& rhs) const {
        return CompareTo(rhs);
    }

    bool operator!=(const CryptoParametersBase<Element>& rhs) const {
        return !(*this == rhs);
    }

    /**
     * Overload to allow printing of parameters to an iostream
     * NOTE that the implementation relies on calling the virtual
     * PrintParameters method
     * @param out - the stream to print to
     * @param item - reference to the item to print
     * @return the stream
     */
    friend std::ostream& operator<<(std::ostream& out, const CryptoParametersBase& item) {
        item.PrintParameters(out);
        return out;
    }

    virtual uint32_t GetDigitSize() const {
        return 0;
    }

    /**
     * Returns the value of the maximum power of secret key for which the
     * relinearization key is generated
     *
     * @return maximum power of secret key
     */
    virtual uint32_t GetMaxRelinSkDeg() const {
        return 0;
    }

    /**
     * Sets the reference to element params
     * @param params the ring element parameters
     */
    virtual void SetElementParams(std::shared_ptr<typename Element::Params> params) {
        m_params = params;
    }

    /**
     * Sets the reference to encoding params
     * @param encodingParams the encoding parameters
     */
    virtual void SetEncodingParams(EncodingParams encodingParams) {
        m_encodingParams = encodingParams;
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("elp", m_params));
        ar(::cereal::make_nvp("enp", m_encodingParams));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("elp", m_params));
        ar(::cereal::make_nvp("enp", m_encodingParams));
    }

    std::string SerializedObjectName() const override {
        return "CryptoParametersBase";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

  protected:
    /**
     * Constructor that creates default encoding parameters for the given plaintext modulus; the element
     * parameters are left unset.
     *
     * @param plaintextModulus the plaintext modulus.
     */
    explicit CryptoParametersBase(const PlaintextModulus& plaintextModulus) {
        m_encodingParams = std::make_shared<EncodingParamsImpl>(plaintextModulus);
    }

    /**
     * Constructor that sets the element parameters and creates default encoding parameters for the
     * given plaintext modulus.
     *
     * @param params the ring element parameters.
     * @param plaintextModulus the plaintext modulus.
     */
    CryptoParametersBase(std::shared_ptr<typename Element::Params> params, const PlaintextModulus& plaintextModulus) {
        m_params = params;
        m_encodingParams = std::make_shared<EncodingParamsImpl>(plaintextModulus);
    }

    /**
     * Constructor that sets the element parameters and the encoding parameters.
     *
     * @param params the ring element parameters.
     * @param encodingParams the encoding parameters.
     */
    CryptoParametersBase(std::shared_ptr<typename Element::Params> params, EncodingParams encodingParams) {
        m_params = params;
        m_encodingParams = encodingParams;
    }

    /**
     * Constructor that copies the parameters of another object and replaces its element parameters.
     *
     * @param from the parameters to copy.
     * @param newElemParms the ring element parameters of the new object.
     */
    CryptoParametersBase(CryptoParametersBase<Element>* from, std::shared_ptr<typename Element::Params> newElemParms) {
        *this = *from;
        m_params = newElemParms;
    }

    /**
     * @brief CompareTo() is a method to compare two CryptoParametersBase objects. It is called by operator==()
     *
     * @param rhs - the other CryptoParametersBase object to compare to.
     * @return whether the two CryptoParametersBase objects are equivalent.
     */
    virtual bool CompareTo(const CryptoParametersBase<Element>& rhs) const {
        return (*m_encodingParams == *(rhs.m_encodingParams) && *m_params == *(rhs.m_params));
    }

    /**
     * Prints the element parameters and the encoding parameters to the stream; called by operator<<
     * and extended by derived classes.
     *
     * @param out the stream to print to.
     */
    virtual void PrintParameters(std::ostream& out) const {
        out << "Element Parameters: " << *m_params << std::endl;
        out << "Encoding Parameters: " << *m_encodingParams << std::endl;
    }

    /// element-specific parameters
    std::shared_ptr<typename Element::Params> m_params;

    /// encoding-specific parameters
    EncodingParams m_encodingParams;
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEMEBASE_BASE_CRYPTOPARAMETERS_H_
