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

/*
// This program demonstrates the use of the OpenFHE library to encrypt bytes of
text. All OpenFHE functionality takes place as a part of a CryptoContext, and
so the first step in using OpenFHE is creating a CryptoContext.
//
// A CryptoContext can be created on the fly by passing parameters into a method
provided in the CryptoContextFactory. A CryptoContext can be custom tuned for
your particular application by using parameter generation. A CryptoContext can
be constructed from one of a group of named, predetermined parameter sets
//
// This program uses the "group of named predetermined sets" method. Pass the
parameter set name to the program and it will use that set. Pass no names and it
will tell you all the available names.
// Use the -s option and the program will not be verbose as it operates
*/

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "palisade.h"

#include "cryptocontextgen.h"
#include "cryptocontextparametersets.h"

using namespace lbcrypto;

////////////////////////////////////////////////////////////
// This program demonstrates the use of the OpenFHE library's proxy
// re-encryption feature
//
// All OpenFHE functionality takes place as a part of a CryptoContext, and so
// the first step in using OpenFHE is creating a CryptoContext
//
// This program creates CryptoContexts for one of three user-specified schemes
//
// Pass the scheme name to the program and it will use that scheme.
// Pass no scheme name and it will tell you all the available schemes supported
// in this program. Use the -v option and the program will be verbose as it
// operates

CryptoContext<Poly> GeneratePREContext(std::string scheme, PlaintextModulus ptm) {
  std::shared_ptr<Poly::Params> ep;
  CryptoContext<Poly> cc;
  unsigned int m = 2048;

  if (scheme == "Null") {
    cc = GenTestCryptoContext<Poly>(scheme, m, ptm);
  } else if (scheme == "BFV") {
    cc = GenTestCryptoContext<Poly>("BFV_rlwe", m, ptm);
  } else {
    std::cout << "Unrecognized scheme '" << scheme << "'" << std::endl;
    std::cout << "Available schemes are: Null, and BFV" << std::endl;
  }

  return cc;
}

int main(int argc, char* argv[]) {
  std::string schemeName;
  bool beVerbose = true;
  bool haveName = false;

  // Process parameters, find the parameter set name specified on the command
  // line
  for (int i = 1; i < argc; i++) {
    std::string parm(argv[i]);

    if (parm[0] == '-') {
      if (parm == "-s") {
        beVerbose = false;
      } else {
        std::cout << "Unrecognized parameter " << parm << std::endl;
        return 1;
      }
    } else {
      if (haveName) {
        std::cout << "Cannot specify multiple parameter set names" << std::endl;
        return 1;
      }

      haveName = true;
      schemeName = parm;
    }
  }

  CryptoContext<Poly> cc = GeneratePREContext(schemeName, 256);

  if (cc == 0) return 0;

  if (beVerbose) {
    std::cout << "Crypto system for " << schemeName
         << " initialized with parameters:" << std::endl;
    std::cout << *cc->GetCryptoParameters() << std::endl;
  }

  // enable features that you wish to use
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(PRE);

  // The largest possible plaintext is the size of the ring
  size_t ptsize = cc->GetRingDimension();

  if (beVerbose) std::cout << "Plaintext will be of size " << ptsize << std::endl;

  // generate a random string of length ptsize
  auto randchar = []() -> char {
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    const size_t max_index = (sizeof(charset) - 1);
    return charset[rand() % max_index];
  };

  std::string rchars(ptsize, 0);
  std::generate_n(rchars.begin(), ptsize, randchar);

  // create a plaintext object from that string
  Plaintext plaintext = cc->MakeStringPlaintext(rchars);

  ////////////////////////////////////////////////////////////
  // Perform the key generation operation.
  ////////////////////////////////////////////////////////////

  if (beVerbose) std::cout << "Running key generation" << std::endl;

  KeyPair<Poly> kp = cc->KeyGen();

  if (!kp.good()) {
    std::cout << "Key generation failed" << std::endl;
    return 1;
  }

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////

  Ciphertext<Poly> ciphertext;

  if (beVerbose) std::cout << "Running encryption" << std::endl;

  ciphertext = cc->Encrypt(kp.publicKey, plaintext);

  ////////////////////////////////////////////////////////////
  // Decryption
  ////////////////////////////////////////////////////////////

  Plaintext plaintextNew;

  if (beVerbose) std::cout << "Running decryption" << std::endl;

  DecryptResult result = cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);

  if (!result.isValid) {
    std::cout << "Decryption failed" << std::endl;
    return 1;
  }

  if (plaintext != plaintextNew) {
    std::cout << "Mismatch on decryption" << std::endl;
    return 1;
  }

  // PRE SCHEME

  ////////////////////////////////////////////////////////////
  // Perform the second key generation operation.
  // This generates the keys which should be able to decrypt the ciphertext
  // after the re-encryption operation.
  ////////////////////////////////////////////////////////////

  if (beVerbose)
    std::cout << "Running second key generation (used for re-encryption)" << std::endl;

  KeyPair<Poly> newKp = cc->KeyGen();

  if (!newKp.good()) {
    std::cout << "Key generation failed" << std::endl;
    return 1;
  }

  ////////////////////////////////////////////////////////////
  // Perform the proxy re-encryption key generation operation.
  // This generates the keys which are used to perform the key switching.
  ////////////////////////////////////////////////////////////

  if (beVerbose) std::cout << "Generating proxy re-encryption key" << std::endl;

  EvalKey<Poly> evalKey;
  try {
    evalKey = cc->ReKeyGen(newKp.publicKey, kp.secretKey);
  } catch (std::exception& e) {
    std::cout << e.what() << ", cannot proceed with PRE" << std::endl;
    return 0;
  }

  ////////////////////////////////////////////////////////////
  // Perform the proxy re-encryption operation.
  ////////////////////////////////////////////////////////////

  if (beVerbose) std::cout << "Running re-encryption" << std::endl;

  auto newCiphertext = cc->ReEncrypt(evalKey, ciphertext);

  ////////////////////////////////////////////////////////////
  // Decryption
  ////////////////////////////////////////////////////////////

  Plaintext plaintextNew2;

  if (beVerbose) std::cout << "Running decryption of re-encrypted cipher" << std::endl;

  DecryptResult result1 =
      cc->Decrypt(newKp.secretKey, newCiphertext, &plaintextNew2);

  if (!result1.isValid) {
    std::cout << "Decryption failed!" << std::endl;
    exit(1);
  }

  if (plaintext != plaintextNew2) {
    std::cout << "Mismatch on decryption of PRE ciphertext" << std::endl;
    if (plaintext->GetEncodingType() != plaintextNew2->GetEncodingType())
      std::cout << "encoding mismatch" << std::endl;

    if (plaintext->GetEncodingParams() != plaintextNew2->GetEncodingParams())
      std::cout << "params" << std::endl;

    if (plaintext->GetLength() != plaintextNew2->GetLength())
      std::cout << "length mismatch " << plaintext->GetLength() << " and "
           << plaintextNew2->GetLength() << std::endl;

    for (size_t i = 0; i < plaintext->GetLength(); i++) {
      if (plaintext->GetStringValue().at(i) !=
          plaintextNew2->GetStringValue().at(i)) {
        std::cout << "mismatch at " << i << std::endl;
        std::cout << plaintext->GetStringValue() << std::endl;
        std::cout << plaintextNew2->GetStringValue() << std::endl;
        break;
      }
    }
    return 1;
  }

  if (beVerbose) std::cout << "Execution completed" << std::endl;

  return 0;
}
