// @file UnitTestFHEWSerial.cpp This code runs unit tests for the FHEW methods
// of the PALISADE lattice encryption library.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "gtest/gtest.h"

// these header files are needed for serialization
#include "binfhecontext-ser.h"

using namespace lbcrypto;

class UnitTestFHEWSerial : public ::testing::Test {
 protected:
  virtual void SetUp() {}

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};
// ---------------  TESTING SERIALIZATION METHODS OF FHEW ---------------

// Checks serialization for JSON mode
TEST(UnitTestFHEWSerialAP, JSON) {
  auto cc1 = BinFHEContext();
  cc1.GenerateBinFHEContext(TOY, AP);

  auto sk1 = cc1.KeyGen();
  // cc1.BTKeyGen(sk1);

  // Encryption for a ciphertext that will be serialized
  auto ct1 = cc1.Encrypt(sk1, 1, FRESH);

  std::string msg = "JSON serialization test failed: ";

  std::stringstream s;
  Serial::Serialize(cc1, s, SerType::JSON);
  BinFHEContext cc;
  Serial::Deserialize(cc, s, SerType::JSON);

  EXPECT_EQ(*cc.GetParams(), *cc1.GetParams()) << msg << " Context mismatch";

  s.str("");
  s.clear();

  Serial::Serialize(sk1, s, SerType::JSON);
  LWEPrivateKey sk;
  Serial::Deserialize(sk, s, SerType::JSON);

  s.str("");
  s.clear();

  EXPECT_EQ(*sk1, *sk) << msg << " Secret key mismatch";

  Serial::Serialize(ct1, s, SerType::JSON);
  LWECiphertext ct;
  Serial::Deserialize(ct, s, SerType::JSON);

  EXPECT_EQ(*ct1, *ct) << msg << " Ciphertext mismatch";
}

// Checks serialization for JSON mode
TEST(UnitTestFHEWSerialGINX, JSON) {
  auto cc1 = BinFHEContext();
  cc1.GenerateBinFHEContext(TOY, GINX);

  auto sk1 = cc1.KeyGen();
  // cc1.BTKeyGen(sk1);

  // Encryption for a ciphertext that will be serialized
  auto ct1 = cc1.Encrypt(sk1, 1, FRESH);

  std::string msg = "JSON serialization test failed: ";

  std::stringstream s;
  Serial::Serialize(cc1, s, SerType::JSON);
  BinFHEContext cc;
  Serial::Deserialize(cc, s, SerType::JSON);

  EXPECT_EQ(*cc.GetParams(), *cc1.GetParams()) << msg << " Context mismatch";

  s.str("");
  s.clear();

  Serial::Serialize(sk1, s, SerType::JSON);
  LWEPrivateKey sk;
  Serial::Deserialize(sk, s, SerType::JSON);

  s.str("");
  s.clear();

  EXPECT_EQ(*sk1, *sk) << msg << " Secret key mismatch";

  Serial::Serialize(ct1, s, SerType::JSON);
  LWECiphertext ct;
  Serial::Deserialize(ct, s, SerType::JSON);

  EXPECT_EQ(*ct1, *ct) << msg << " Ciphertext mismatch";
}

// Checks serialization for BINARY mode
TEST(UnitTestFHEWSerialAP, BINARY) {
  auto cc1 = BinFHEContext();
  cc1.GenerateBinFHEContext(TOY, AP);

  auto sk1 = cc1.KeyGen();
  // cc1.BTKeyGen(sk1);

  // Encryption for a ciphertext that will be serialized
  auto ct111 = cc1.Encrypt(sk1, 1, FRESH);

  std::string msg = "BINARY serialization test failed: ";

  std::stringstream s;
  Serial::Serialize(cc1, s, SerType::BINARY);
  BinFHEContext cc;
  Serial::Deserialize(cc, s, SerType::BINARY);

  EXPECT_EQ(*cc.GetParams(), *cc1.GetParams()) << msg << " Context mismatch";

  /* commented out for now; the bootstrapping key is too large to fit in the
  stringstream

  s.str("");
  s.clear();

  Serial::Serialize(cc.GetRefreshKey(), s, SerType::BINARY);
  std::shared_ptr<RingGSWBTKey> refreshKey;
  Serial::Deserialize(refreshKey, s, SerType::BINARY);

  s.str("");
  s.clear();

  Serial::Serialize(cc.GetSwitchKey(), s, SerType::BINARY);
  std::shared_ptr<LWESwitchingKey> switchKey;
  Serial::Deserialize(switchKey, s, SerType::BINARY);

  // Loading deserialized bootstrapping keys
  cc.BTKeyLoad({refreshKey,switchKey});

  EXPECT_EQ( *cc.GetRefreshKey(), *cc1.GetRefreshKey() ) << msg << "
  Bootstrapping key mismatch: refresh key";
  //EXPECT_EQ( *cc.GetSwitchKey(), *cc1.GetSwitchKey() ) << msg << "
  Bootstrapping key mismatch: refresh key";

  */

  s.str("");
  s.clear();

  Serial::Serialize(sk1, s, SerType::BINARY);
  LWEPrivateKey sk;
  Serial::Deserialize(sk, s, SerType::BINARY);

  EXPECT_EQ(*sk1, *sk) << msg << " Secret key mismatch";

  s.str("");
  s.clear();

  Serial::Serialize(ct111, s, SerType::BINARY);
  LWECiphertext ct;
  Serial::Deserialize(ct, s, SerType::BINARY);

  EXPECT_EQ(*ct111, *ct) << msg << " Ciphertext mismatch";
}

// Checks serialization for BINARY mode
TEST(UnitTestFHEWSerialGINX, BINARY) {
  auto cc1 = BinFHEContext();
  cc1.GenerateBinFHEContext(TOY);

  auto sk1 = cc1.KeyGen();
  // cc1.BTKeyGen(sk1);

  // Encryption for a ciphertext that will be serialized
  auto ct111 = cc1.Encrypt(sk1, 1, FRESH);

  std::string msg = "BINARY serialization test failed: ";

  std::stringstream s;
  Serial::Serialize(cc1, s, SerType::BINARY);
  BinFHEContext cc;
  Serial::Deserialize(cc, s, SerType::BINARY);

  EXPECT_EQ(*cc.GetParams(), *cc1.GetParams()) << msg << " Context mismatch";

  /* commented out for now; the bootstrapping key is too large to fit in the
  stringstream

  s.str("");
  s.clear();

  Serial::Serialize(cc.GetRefreshKey(), s, SerType::BINARY);
  std::shared_ptr<RingGSWBTKey> refreshKey;
  Serial::Deserialize(refreshKey, s, SerType::BINARY);

  s.str("");
  s.clear();

  Serial::Serialize(cc.GetSwitchKey(), s, SerType::BINARY);
  std::shared_ptr<LWESwitchingKey> switchKey;
  Serial::Deserialize(switchKey, s, SerType::BINARY);

  // Loading deserialized bootstrapping keys
  cc.BTKeyLoad({refreshKey,switchKey});

  EXPECT_EQ( *cc.GetRefreshKey(), *cc1.GetRefreshKey() ) << msg << "
  Bootstrapping key mismatch: refresh key";
  //EXPECT_EQ( *cc.GetSwitchKey(), *cc1.GetSwitchKey() ) << msg << "
  Bootstrapping key mismatch: refresh key";

  */

  s.str("");
  s.clear();

  Serial::Serialize(sk1, s, SerType::BINARY);
  LWEPrivateKey sk;
  Serial::Deserialize(sk, s, SerType::BINARY);

  EXPECT_EQ(*sk1, *sk) << msg << " Secret key mismatch";

  s.str("");
  s.clear();

  Serial::Serialize(ct111, s, SerType::BINARY);
  LWECiphertext ct;
  Serial::Deserialize(ct, s, SerType::BINARY);

  EXPECT_EQ(*ct111, *ct) << msg << " Ciphertext mismatch";
}
