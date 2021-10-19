/***
 * © 2020 Duality Technologies, Inc. All rights reserved.
 * This is a proprietary software product of Duality Technologies, Inc.
 *protected under copyright laws and international copyright treaties, patent
 *law, trade secret law and other intellectual property rights of general
 *applicability. Any use of this software is strictly prohibited absent a
 *written agreement executed by Duality Technologies, Inc., which provides
 *certain limited rights to use this software. You may not copy, distribute,
 *make publicly available, publicly perform, disassemble, de-compile or reverse
 *engineer any part of this software, breach its security, or circumvent,
 *manipulate, impair or disrupt its operation.
 ***/

#ifndef LBCRYPTO_CRYPTO_METADATA_H
#define LBCRYPTO_CRYPTO_METADATA_H

namespace lbcrypto {

/**
 * @brief Empty metadata container
 */
class Metadata {
 public:
  /**
   * Default constructor
   */
  Metadata() {}

  /**
   * Copy constructor
   */
  Metadata(const Metadata& mdata) { Metadata(); }

  /**
   * Destructor
   */
  virtual ~Metadata() {}

  /**
   * This method creates a copy of the Metadata object
   * wrapped in a shared_ptr
   */
  virtual std::shared_ptr<Metadata> Clone() const {
    return std::make_shared<Metadata>();
  }

  /**
   * Equality operator for Metadata.
   * Unless overriden by subclasses, Metadata does not carry any
   * metadata, so all Metadata objects are equal.
   */
  virtual bool operator==(const Metadata& mdata) const { return true; }

  /**
   * Inequality operator, implemented by a call to the
   * equality operator.
   */
  virtual bool operator!=(const Metadata& mdata) const {
    return !(*this == mdata);
  }

  /**
   * A method that prints the contents of metadata objects.
   * Please override in subclasses to print all members.
   */
  virtual std::ostream& print(std::ostream& out) const {
    out << "[ ]" << std::endl;
    return out;
  }

  /**
   * << operator implements by calling member method print.
   * This is a friend method and cannot be overriden by subclasses.
   */
  friend std::ostream& operator<<(std::ostream& out, const Metadata& m) {
    m.print(out);
    return out;
  }

  /**
   * save method for serialization
   */
  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {}

  /**
   * load method for serialization
   */
  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
  }

  /**
   * SerializedObjectName method for serialization
   */
  virtual std::string SerializedObjectName() const { return "Metadata"; }

  /**
   * SerializedVersion method for serialization
   */
  static uint32_t SerializedVersion() { return 1; }
};

/**
 * @brief Example class inheriting from Metadata and adding a member.
 * This is used in unit tests.
 */
class MetadataTest : public Metadata {
 public:
  /**
   * Default constructor
   */
  MetadataTest() : Metadata(), m_s("") {}
  /**
   * Destructor
   */
  virtual ~MetadataTest() {}

  /**
   * Copy constructor
   */
  MetadataTest(const MetadataTest& mdata) : Metadata() { m_s = mdata.m_s; }

  /**
   * This method creates a new MetadataTest object.
   *
   * Since Ciphertexts have a map of shared_ptr<Metadata>,
   * whenever we retrieve the contents of the map, we actually
   * get the shared pointer and we do not create a new object.
   *
   * If we do want to create a new object (e.g., because we
   * want to modify it only for a new Ciphertext), we can use
   * the Clone method.
   *
   */
  std::shared_ptr<Metadata> Clone() const {
    auto mdata = std::make_shared<MetadataTest>();
    mdata->m_s = this->m_s;
    return mdata;
  }

  /**
   * Setter method for the only value stored in this Metadata container.
   */
  void SetMetadata(string str) { m_s = string(str); }

  /**
   * This method returns the (only) value stored in this Metadata container
   */
  string GetMetadata() const { return m_s; }

  /**
   * Defines how to check equality between objects of this class.
   */
  bool operator==(const Metadata& mdata) const {
    try {
      const MetadataTest& mdataTest = dynamic_cast<const MetadataTest&>(mdata);
      return m_s == mdataTest.GetMetadata();  // All Metadata objects without
                                              // any members are equal
    } catch (const std::bad_cast& e) {
      PALISADE_THROW(
          palisade_error,
          "Tried to downcast an object of different class to MetadataTest");
    }
  }

  /**
   * Defines how to print the contents of objects of this class.
   */
  std::ostream& print(std::ostream& out) const {
    out << "[ " << m_s << " ]";
    return out;
  }

  /**
   * save method for serialization
   */
  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(cereal::base_class<Metadata>(this));
    ar(cereal::make_nvp("str", m_s));
  }

  /**
   * load method for serialization
   */
  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(cereal::base_class<Metadata>(this));
    ar(cereal::make_nvp("str", m_s));
  }

  /**
   * This static method retrieves a MetadataTest object
   * from a Ciphertext, and clones it so we can further
   * modify it.
   *
   * @param ciphertext the ciphertext whose metadata to retrieve.
   */
  template <class Element>
  static const shared_ptr<MetadataTest> CloneMetadata(
      ConstCiphertext<Element> ciphertext) {
    auto it = ciphertext->FindMetadataByKey("test");

    if (ciphertext->MetadataFound(it)) {
      return std::dynamic_pointer_cast<MetadataTest>(
          ciphertext->GetMetadata(it)->Clone());
    } else {
      PALISADE_THROW(
          palisade_error,
          "Attempt to access metadata (MetadataTest) that has not been set.");
    }
  }

  /**
   * This static method retrieves a MetadataTest object
   * from a Ciphertext, without cloning it. This means that any
   * modifications on the MetadataTest object will affect the
   * original Ciphertext we retrieved the metadata from.
   *
   * @param ciphertext the ciphertext whose metadata to retrieve.
   */
  template <class Element>
  static const shared_ptr<MetadataTest> GetMetadata(
      ConstCiphertext<Element> ciphertext) {
    auto it = ciphertext->FindMetadataByKey("test");

    if (ciphertext->MetadataFound(it)) {
      return std::dynamic_pointer_cast<MetadataTest>(
          ciphertext->GetMetadata(it));
    } else {
      PALISADE_THROW(
          palisade_error,
          "Attempt to access metadata (MetadataTest) that has not been set.");
    }
  }

  /**
   * This static method stores a MetadataTest object
   * to a Ciphertext. If the Ciphertext already has another MetadataTest
   * object stored in its map, it will get overwritten by this MetadataTest
   * object.
   *
   * Whenever we want to modify the metadata of a ciphertext, it is
   * recommended to (1) clone the MetadataTest object from another
   * ciphertext or create a new MetadataTest object with
   * make_shared<MetadataTest>(), (2) modify it using the Setter methods
   * of MetadataTest, and (3) store it to the ciphertext we want using
   * this method.
   *
   * @param ciphertext the ciphertext whose metadata to retrieve.
   */
  template <class Element>
  static void StoreMetadata(Ciphertext<Element> ciphertext,
                            shared_ptr<MetadataTest> mdata) {
    ciphertext->SetMetadataByKey("test", mdata);
  }

 protected:
  string m_s;
};

}  // end namespace lbcrypto

#endif
