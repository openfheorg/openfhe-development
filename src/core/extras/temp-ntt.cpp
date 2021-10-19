// @file TODO
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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

#include "palisadecore.h"

using namespace lbcrypto;

void NTTDummy();
void NTTSmall();
void NTTLarge();
void NTTBenchmark();

int main() {
  //  NTTSmall();
  NTTLarge();
  //  NTTBenchmark();
  return 0;
}

void NTTDummy() {
  int mod = 17;

  int W[8] = {1, 4, 15, 9, 7, 11, 3, 12};
  int WI[8] = {1, 13, 8, 2, 5, 14, 6, 10};

  int x[8] = {3, 3, 3, 4, 4, 4, 5, 5};
  int y[8] = {3, 3, 3, 4, 4, 4, 5, 5};
  int z[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  int q[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  int n = 8;

  for (int i = 0; i < 8; ++i) {
    std::cout << x[i] << ",";
  }
  std::cout << std::endl;

  for (int i = 0; i < 8; ++i) {
    std::cout << y[i] << ",";
  }
  std::cout << std::endl;

  for (int i = 0; i < 8; ++i) {
    for (int j = 0; j < 8; ++j) {
      if (i + j < 8) {
        q[i + j] += (x[i] * y[j]);
        q[i + j] %= mod;
      } else {
        q[i + j - 8] += (mod * mod);
        q[i + j - 8] -= (x[i] * y[j]);
        q[i + j - 8] %= mod;
      }
    }
  }

  for (int i = 0; i < 8; ++i) {
    std::cout << q[i] << ",";
  }
  std::cout << std::endl;

  int t = n;
  for (int m = 1; m < n; m <<= 1) {
    t >>= 1;
    for (int i = 0; i < m; ++i) {
      int j1 = 2 * i * t;
      int j2 = j1 + t;
      int s = W[m + i];
      for (int j = j1; j < j2; ++j) {
        int u = x[j];
        int v = (x[j + t] * s) % mod;
        x[j] = (u + v) % mod;
        x[j + t] = (u + mod - v) % mod;
      }
    }
  }

  for (int i = 0; i < 8; ++i) {
    std::cout << x[i] << ",";
  }
  std::cout << std::endl;

  t = n;
  for (int m = 1; m < n; m <<= 1) {
    t >>= 1;
    for (int i = 0; i < m; ++i) {
      int j1 = 2 * i * t;
      int j2 = j1 + t;
      int s = W[m + i];
      for (int j = j1; j < j2; ++j) {
        int u = y[j];
        int v = (y[j + t] * s) % mod;
        y[j] = ((u + v) % mod);
        y[j + t] = ((u + mod - v) % mod);
      }
    }
  }

  for (int i = 0; i < 8; ++i) {
    std::cout << y[i] << ",";
  }
  std::cout << std::endl;

  for (int i = 0; i < 8; ++i) {
    z[i] = (x[i] * y[i]) % mod;
  }

  for (int i = 0; i < 8; ++i) {
    std::cout << z[i] << ",";
  }
  std::cout << std::endl;

  t = 1;
  for (int m = n; m > 1; m >>= 1) {
    int j1 = 0;
    int h = m >> 1;
    for (int i = 0; i < h; ++i) {
      int j2 = j1 + t;
      int s = WI[h + i];
      for (int j = j1; j < j2; ++j) {
        int u = z[j];
        int v = z[j + t];
        z[j] = u + v;
        z[j + t] = ((u + mod - v) * s) % mod;
      }
      j1 += (t << 1);
    }
    t <<= 1;
  }

  for (int i = 0; i < n; ++i) {
    z[i] = (z[i] * 15) % mod;
  }

  for (int i = 0; i < 8; ++i) {
    std::cout << z[i] << ",";
  }
  std::cout << std::endl;
}

void NTTSmall() {
  usint m = 8;
  usint phim = 4;

  NativeInteger modulusQ("73");
  NativeInteger rootOfUnity("22");
  //  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  NativeVector x(phim, modulusQ);
  NativeVector y(phim, modulusQ);

  NativeVector xx(phim, modulusQ);
  NativeVector yy(phim, modulusQ);

  x[0] = 2;
  x[1] = 1;
  x[2] = 1;
  x[3] = 1;

  y[0] = 1;
  y[1] = 0;
  y[2] = 1;
  y[3] = 1;

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  std::cout << "-----------------------" << std::endl;
  for (usint i = 0; i < phim; ++i) {
    std::cout << x[i] << ",";
  }
  std::cout << std::endl;
  std::cout << "-----------------------" << std::endl;

  ChineseRemainderTransformFTT<NativeVector>::ForwardTransformToBitReverse(
      x, rootOfUnity, m, &xx);

  ChineseRemainderTransformFTT<NativeVector>::ForwardTransformToBitReverse(
      y, rootOfUnity, m, &yy);

  std::cout << "-----------------------" << std::endl;
  for (usint i = 0; i < phim; ++i) {
    xx[i].ModMulEq(yy[i], modulusQ);
  }

  std::cout << std::endl;
  std::cout << "-----------------------" << std::endl;

  ChineseRemainderTransformFTT<NativeVector>::InverseTransformFromBitReverse(
      xx, rootOfUnity, m, &x);

  std::cout << "-----------------------" << std::endl;
  for (usint i = 0; i < phim; ++i) {
    std::cout << x[i] << ",";
  }
  std::cout << std::endl;
  std::cout << "-----------------------" << std::endl;
}

void NTTLarge() {
  usint m = 2048;
  usint phim = 1024;

  NativeInteger modulusQ("288230376151748609");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);
  NativeInteger mu = modulusQ.ComputeMu();
  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);
  NativeVector y = dug.GenerateVector(phim);
  NativeVector x_ntt(phim, modulusQ);
  NativeVector y_ntt(phim, modulusQ);
  NativeVector z_ntt(phim, modulusQ);
  NativeVector z(phim, modulusQ);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  ChineseRemainderTransformFTT<NativeVector>::ForwardTransformToBitReverse(
      x, rootOfUnity, m, &x_ntt);
  ChineseRemainderTransformFTT<NativeVector>::ForwardTransformToBitReverse(
      y, rootOfUnity, m, &y_ntt);

  for (usint i = 0; i < phim; ++i) {
    z_ntt[i] = x_ntt[i].ModMulFast(y_ntt[i], modulusQ, mu);
  }

  ChineseRemainderTransformFTT<NativeVector>::InverseTransformFromBitReverse(
      z_ntt, rootOfUnity, m, &z);
}

void NTTBenchmark() {
  usint counter = 1000;
  //  usint m = 2048;
  usint m = (1 << 13);
  usint phim = m / 2;

  //  NativeInteger modulusQ("288230376151748609");
  //  NativeInteger modulusQ("36028794871627777");
  NativeInteger modulusQ("1152921496017387521");

  //  NativeInteger rootOfUnity("160550286306538");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);
  NativeVector x_ntt(phim);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  for (usint i = 0; i < counter; ++i) {
    ChineseRemainderTransformFTT<NativeVector>::ForwardTransformToBitReverse(
        x, rootOfUnity, m, &x_ntt);
    ChineseRemainderTransformFTT<NativeVector>::InverseTransformFromBitReverse(
        x_ntt, rootOfUnity, m, &x);
  }

  std::cout << "finished" << std::endl;
}
