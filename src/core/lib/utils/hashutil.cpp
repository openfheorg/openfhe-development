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
  hash utilities
 */

#include <iomanip>
#include <sstream>
#include "utils/hashutil.h"

namespace lbcrypto {

#define RIGHT_ROT(x, n) ((x >> (n % (sizeof(x) * 8)) | (x << ((sizeof(x) * 8) - (n % (sizeof(x) * 8))))))

const uint32_t HashUtil::k_256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

const uint64_t HashUtil::k_512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

void HashUtil::SHA256(std::string message, std::vector<int64_t>& digest) {
    uint32_t h_256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    uint64_t m_len   = message.size() * 8;
    uint16_t pad_len = 1;
    while ((m_len + pad_len) % 512 != 448) {
        pad_len++;
    }
    message.push_back(0);
    for (int a = 0; a < (pad_len) / 8 - 1; a++) {
        message.push_back(0);
    }
    message.push_back((uint8_t)((m_len & 0xff00000000000000) >> 56));
    message.push_back((uint8_t)((m_len & 0x00ff000000000000) >> 48));
    message.push_back((uint8_t)((m_len & 0x0000ff0000000000) >> 40));
    message.push_back((uint8_t)((m_len & 0x000000ff00000000) >> 32));
    message.push_back((uint8_t)((m_len & 0x00000000ff000000) >> 24));
    message.push_back((uint8_t)((m_len & 0x0000000000ff0000) >> 16));
    message.push_back((uint8_t)((m_len & 0x000000000000ff00) >> 8));
    message.push_back((uint8_t)(m_len & 0x00000000000000ff));

    for (size_t n = 0; n < (message.size() * 8) / 512; n++) {
        uint32_t w[64];
        short counter = 0;  // NOLINT
        for (size_t m = 64 * n; m < (64 * (n + 1)); m += 4) {
            w[counter] = ((uint32_t)message.at(m) << 24) ^ ((uint32_t)message.at(m + 1) << 16) ^
                         ((uint32_t)message.at(m + 2) << 8) ^ ((uint32_t)message.at(m + 3));
            counter++;
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ((uint32_t)RIGHT_ROT(w[i - 15], 7)) ^ ((uint32_t)(RIGHT_ROT(w[i - 15], 18))) ^
                          ((uint32_t)(w[i - 15] >> 3));
            uint32_t s1 = ((uint32_t)RIGHT_ROT(w[i - 2], 17)) ^ ((uint32_t)RIGHT_ROT(w[i - 2], 19)) ^
                          ((uint32_t)(w[i - 2] >> 10));
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h_256[0];
        uint32_t b = h_256[1];
        uint32_t c = h_256[2];
        uint32_t d = h_256[3];
        uint32_t e = h_256[4];
        uint32_t f = h_256[5];
        uint32_t g = h_256[6];
        uint32_t h = h_256[7];

        for (int i = 0; i < 64; i++) {
            uint32_t S1    = ((uint32_t)RIGHT_ROT(e, 6)) ^ ((uint32_t)RIGHT_ROT(e, 11)) ^ ((uint32_t)RIGHT_ROT(e, 25));
            uint32_t ch    = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k_256[i] + w[i];
            uint32_t S0    = ((uint32_t)RIGHT_ROT(a, 2)) ^ ((uint32_t)RIGHT_ROT(a, 13)) ^ ((uint32_t)RIGHT_ROT(a, 22));
            uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h_256[0] += a;
        h_256[1] += b;
        h_256[2] += c;
        h_256[3] += d;
        h_256[4] += e;
        h_256[5] += f;
        h_256[6] += g;
        h_256[7] += h;
    }

    for (int i = 0; i < 8; i++) {
        digest.push_back((uint8_t)((h_256[i] & 0xff000000) >> 24));
        digest.push_back((uint8_t)((h_256[i] & 0x00ff0000) >> 16));
        digest.push_back((uint8_t)((h_256[i] & 0x0000ff00) >> 8));
        digest.push_back((uint8_t)(h_256[i] & 0x000000ff));
    }

    return;
}

std::string HashUtil::HashString(std::string message) {
    uint32_t h_256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    uint64_t m_len   = message.size() * 8;
    uint16_t pad_len = 1;
    while ((m_len + pad_len) % 512 != 448) {
        pad_len++;
    }

    message += static_cast<char>(0x80);
    for (int a = 0; a < (pad_len) / 8 - 1; a++) {
        message += static_cast<char>(0);
    }
    message += static_cast<char>((m_len & 0xff00000000000000) >> 56);
    message += static_cast<char>((m_len & 0x00ff000000000000) >> 48);
    message += static_cast<char>((m_len & 0x0000ff0000000000) >> 40);
    message += static_cast<char>((m_len & 0x000000ff00000000) >> 32);
    message += static_cast<char>((m_len & 0x00000000ff000000) >> 24);
    message += static_cast<char>((m_len & 0x0000000000ff0000) >> 16);
    message += static_cast<char>((m_len & 0x000000000000ff00) >> 8);
    message += static_cast<char>(m_len & 0x00000000000000ff);

    for (size_t n = 0; n < (message.size() * 8) / 512; n++) {
        uint32_t w[64];
        short counter = 0;  // NOLINT
        for (size_t m = 64 * n; m < (64 * (n + 1)); m += 4) {
            w[counter] = ((uint32_t)(message.at(m) & 0xff) << 24) ^ ((uint32_t)(message.at(m + 1) & 0xff) << 16) ^
                         ((uint32_t)(message.at(m + 2) & 0xff) << 8) ^ ((uint32_t)(message.at(m + 3) & 0xff));
            counter++;
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ((uint32_t)RIGHT_ROT(w[i - 15], 7)) ^ ((uint32_t)(RIGHT_ROT(w[i - 15], 18))) ^
                          ((uint32_t)(w[i - 15] >> 3));
            uint32_t s1 = ((uint32_t)RIGHT_ROT(w[i - 2], 17)) ^ ((uint32_t)RIGHT_ROT(w[i - 2], 19)) ^
                          ((uint32_t)(w[i - 2] >> 10));
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h_256[0];
        uint32_t b = h_256[1];
        uint32_t c = h_256[2];
        uint32_t d = h_256[3];
        uint32_t e = h_256[4];
        uint32_t f = h_256[5];
        uint32_t g = h_256[6];
        uint32_t h = h_256[7];

        for (int i = 0; i < 64; i++) {
            uint32_t S1    = ((uint32_t)RIGHT_ROT(e, 6)) ^ ((uint32_t)RIGHT_ROT(e, 11)) ^ ((uint32_t)RIGHT_ROT(e, 25));
            uint32_t ch    = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k_256[i] + w[i];
            uint32_t S0    = ((uint32_t)RIGHT_ROT(a, 2)) ^ ((uint32_t)RIGHT_ROT(a, 13)) ^ ((uint32_t)RIGHT_ROT(a, 22));
            uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h_256[0] += a;
        h_256[1] += b;
        h_256[2] += c;
        h_256[3] += d;
        h_256[4] += e;
        h_256[5] += f;
        h_256[6] += g;
        h_256[7] += h;
    }

    std::stringstream s;
    s.fill('0');
    s << std::hex;
    for (size_t ii = 0; ii < 8; ii++)
        s << std::setw(8) << h_256[ii];

    return s.str();
}

#if 0
lbcrypto::BytePlaintextEncoding HashUtil::SHA512(
    lbcrypto::BytePlaintextEncoding message) {
  uint64_t h_512[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                       0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                       0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                       0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

  uint128_t m_len = message.size() * 8;
  uint64_t m_len_first = message.size() / (0x2000000000000000);
  uint64_t m_len_second = message.size() * 8;
  uint16_t pad_len = 1;
  while ((m_len + pad_len) % 1024 != 896) {
    pad_len++;
  }
  message.push_back(128);
  for (int a = 0; a < (pad_len) / 8 - 1; a++) {
    message.push_back(0);
  }

  message.push_back((uint8_t)((m_len_first & 0xff00000000000000) >> 56));
  message.push_back((uint8_t)((m_len_first & 0x00ff000000000000) >> 48));
  message.push_back((uint8_t)((m_len_first & 0x0000ff0000000000) >> 40));
  message.push_back((uint8_t)((m_len_first & 0x000000ff00000000) >> 32));
  message.push_back((uint8_t)((m_len_first & 0x00000000ff000000) >> 24));
  message.push_back((uint8_t)((m_len_first & 0x0000000000ff0000) >> 16));
  message.push_back((uint8_t)((m_len_first & 0x000000000000ff00) >> 8));
  message.push_back((uint8_t)(m_len_first & 0x00000000000000ff));

  message.push_back((uint8_t)((m_len_second & 0xff00000000000000) >> 56));
  message.push_back((uint8_t)((m_len_second & 0x00ff000000000000) >> 48));
  message.push_back((uint8_t)((m_len_second & 0x0000ff0000000000) >> 40));
  message.push_back((uint8_t)((m_len_second & 0x000000ff00000000) >> 32));
  message.push_back((uint8_t)((m_len_second & 0x00000000ff000000) >> 24));
  message.push_back((uint8_t)((m_len_second & 0x0000000000ff0000) >> 16));
  message.push_back((uint8_t)((m_len_second & 0x000000000000ff00) >> 8));
  message.push_back((uint8_t)(m_len_second & 0x00000000000000ff));

  for (int n = 0; n < (message.size() * 8) / 1024; n++) {
    uint64_t w[80];
    short counter = 0; // NOLINT
    for (int m = 128 * n; m < (128 * (n + 1)); m += 8) {
      w[counter] = ((uint64_t)message.at(m) << 56) ^
                   ((uint64_t)message.at(m + 1) << 48) ^
                   ((uint64_t)message.at(m + 2) << 40) ^
                   ((uint64_t)message.at(m + 3) << 32) ^
                   ((uint64_t)message.at(m + 4) << 24) ^
                   ((uint64_t)message.at(m + 5) << 16) ^
                   ((uint64_t)message.at(m + 6) << 8) ^
                   ((uint64_t)message.at(m + 7));
      counter++;
    }
    for (int i = 16; i < 80; i++) {
      uint64_t s0 = ((uint64_t)RIGHT_ROT(w[i - 15], 1)) ^
                    ((uint64_t)(RIGHT_ROT(w[i - 15], 8))) ^
                    ((uint64_t)(w[i - 15] >> 7));
      uint64_t s1 = ((uint64_t)RIGHT_ROT(w[i - 2], 19)) ^
                    ((uint64_t)RIGHT_ROT(w[i - 2], 61)) ^
                    ((uint64_t)(w[i - 2] >> 6));
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = h_512[0];
    uint64_t b = h_512[1];
    uint64_t c = h_512[2];
    uint64_t d = h_512[3];
    uint64_t e = h_512[4];
    uint64_t f = h_512[5];
    uint64_t g = h_512[6];
    uint64_t h = h_512[7];

    for (int i = 0; i < 80; i++) {
      uint64_t S1 = ((uint64_t)RIGHT_ROT(e, 14)) ^
                    ((uint64_t)RIGHT_ROT(e, 18)) ^ ((uint64_t)RIGHT_ROT(e, 41));
      uint64_t ch = (e & f) ^ ((~e) & g);
      uint64_t temp1 = h + S1 + ch + k_512[i] + w[i];
      uint64_t S0 = ((uint64_t)RIGHT_ROT(a, 28)) ^
                    ((uint64_t)RIGHT_ROT(a, 34)) ^ ((uint64_t)RIGHT_ROT(a, 39));
      uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint64_t temp2 = S0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    h_512[0] += a;
    h_512[1] += b;
    h_512[2] += c;
    h_512[3] += d;
    h_512[4] += e;
    h_512[5] += f;
    h_512[6] += g;
    h_512[7] += h;
  }

  lbcrypto::BytePlaintextEncoding digest;
  for (int i = 0; i < 8; i++) {
    digest.push_back((uint8_t)((h_512[i] & 0xff00000000000000) >> 56));
    digest.push_back((uint8_t)((h_512[i] & 0x00ff000000000000) >> 48));
    digest.push_back((uint8_t)((h_512[i] & 0x0000ff0000000000) >> 40));
    digest.push_back((uint8_t)((h_512[i] & 0x000000ff00000000) >> 32));
    digest.push_back((uint8_t)((h_512[i] & 0x00000000ff000000) >> 24));
    digest.push_back((uint8_t)((h_512[i] & 0x0000000000ff0000) >> 16));
    digest.push_back((uint8_t)((h_512[i] & 0x000000000000ff00) >> 8));
    digest.push_back((uint8_t)(h_512[i] & 0x00000000000000ff));
  }

  return digest;
}
#endif

}  // namespace lbcrypto
