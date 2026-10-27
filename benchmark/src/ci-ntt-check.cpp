// Validate + time the optimized twisted CI NTT against the original reference implementation.
#include "openfhe.h"
#include "math/ci-transform.h"
#include <chrono>
#include <iostream>
#include <random>
using namespace lbcrypto;
int main() {
    for (uint32_t logN : {3u, 4u, 10u, 13u, 16u}) {
        uint32_t N = 1u << logN;
        auto q     = LastPrime<NativeInteger>(59, 4 * N);
        auto wm    = RootOfUnity<NativeInteger>(4 * N, q);
        ClearCIModuli();
        RegisterCIModulus(q, N, wm);
        std::mt19937_64 g(logN);
        NativeVector a(N, q);
        for (uint32_t i = 0; i < N; ++i)
            a[i] = NativeInteger(g() % q.ConvertToInt());
        NativeVector f1 = a, f2 = a;
        CIForwardTransform(f1);
        CIForwardTransformRef(f2);
        bool okF = (f1 == f2);
        NativeVector i1 = f1, i2 = f1;
        CIInverseTransform(i1);
        CIInverseTransformRef(i2);
        bool okI = (i1 == i2) && (i1 == a);
        const int reps = (logN >= 13) ? 50 : 200;
        auto t0 = std::chrono::steady_clock::now();
        for (int r = 0; r < reps; ++r) { CIForwardTransform(f1); CIInverseTransform(f1); }
        double tNew = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() / reps;
        t0 = std::chrono::steady_clock::now();
        for (int r = 0; r < reps; ++r) { CIForwardTransformRef(f2); CIInverseTransformRef(f2); }
        double tRef = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() / reps;
        // standard negacyclic NTT of the same size (OpenFHE's optimized path), for reference
        auto psi = RootOfUnity<NativeInteger>(2 * N, q);
        ChineseRemainderTransformFTT<NativeVector>().PreCompute(psi, 2 * N, q);
        NativeVector f3 = a;
        t0 = std::chrono::steady_clock::now();
        for (int r = 0; r < reps; ++r) {
            ChineseRemainderTransformFTT<NativeVector>().ForwardTransformToBitReverseInPlace(psi, 2 * N, &f3);
            ChineseRemainderTransformFTT<NativeVector>().InverseTransformFromBitReverseInPlace(psi, 2 * N, &f3);
        }
        double tStd = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() / reps;
        std::cout << "std_negacyclic_roundtrip_us=" << tStd * 1e6 << " ";
        std::cout << "NTTCHECK logN=" << logN << " fwd_match=" << okF << " inv_match=" << okI
                  << " roundtrip_new_us=" << tNew * 1e6 << " roundtrip_ref_us=" << tRef * 1e6
                  << " speedup=" << tRef / tNew << std::endl;
    }
    return 0;
}
