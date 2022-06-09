/***
 * © 2020 Duality Technologies, Inc. All rights reserved.
 * This is a proprietary software product of Duality Technologies, Inc. protected under copyright laws
 * and international copyright treaties, patent law, trade secret law and other intellectual property
 * rights of general applicability.
 * Any use of this software is strictly prohibited absent a written agreement executed by Duality
 * Technologies, Inc., which provides certain limited rights to use this software.
 * You may not copy, distribute, make publicly available, publicly perform, disassemble, de-compile or
 * reverse engineer any part of this software, breach its security, or circumvent, manipulate, impair or
 * disrupt its operation.
 ***/
/**
 * @file testcasegen.h Helper methods for serialization.
 */

#ifndef SRC_CORE_LIB_UTILS_TESTCASEGEN_H_
#define SRC_CORE_LIB_UTILS_TESTCASEGEN_H_

#define GENERATE_PKE_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, PTM, FIRST_MOD) \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME) {                                    \
    CryptoContext<ELEMENT> cc;                                                   \
    try {                                                                           \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, PTM, FIRST_MOD);             \
    } catch (const not_implemented_error&) {                                        \
      return;                                                                       \
    } catch (const not_available_error&) {                                          \
      return;                                                                       \
    } catch (const std::exception& ex) {                                            \
      std::cerr << "Exception occurred: " << ex.what() << std::endl;                \
    } catch (...) {                                                                 \
      std::cerr << "Unknown failure occurred." << std::endl;                        \
    }                                                                               \
    FUNC<ELEMENT>(cc, #SCHEME);                                                     \
  }

#define GENERATE_PKE_TEST_CASE_BITS(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, PTM, FIRST_MOD, BITS) \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME) {                                               \
    CryptoContext<ELEMENT> cc;                                                              \
    try {                                                                                      \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, PTM, FIRST_MOD, BITS);                  \
    } catch (const not_implemented_error&) {                                                   \
      return;                                                                                  \
    } catch (const not_available_error&) {                                                     \
      return;                                                                                  \
    } catch (const std::exception& ex) {                                                       \
      std::cerr << "Exception occurred: " << ex.what() << std::endl;                           \
    } catch (...) {                                                                            \
      std::cerr << "Unknown failure occurred." << std::endl;                                   \
    }                                                                                          \
    FUNC<ELEMENT>(cc, #SCHEME);                                                                \
  }

#define GENERATE_CKKS_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, SCALE, FIRST_MOD, NUMPRIME, RELIN, BATCH,     \
                                KEYSWITCH, RESCALEALG)                                                             \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME##_##KEYSWITCH##_##RESCALEALG##_##ORD) {  \
    CryptoContext<ELEMENT> cc;                                                                                  \
    try {                                                                                                          \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, SCALE, FIRST_MOD, SCALE, NUMPRIME, RELIN, BATCH, KEYSWITCH, \
                                         RESCALEALG);                                                              \
    } catch (const not_implemented_error&) {                                                                       \
      return;                                                                                                      \
    } catch (const not_available_error&) {                                                                         \
      return;                                                                                                      \
    } catch (const std::exception& ex) {                                                                           \
      std::cerr << "Exception occurred: " << ex.what() << std::endl;                                               \
    } catch (...) {                                                                                                \
      std::cerr << "Unknown failure occurred." << std::endl;                                                       \
    }                                                                                                              \
    FUNC<ELEMENT>(cc, #SCHEME);                                                                                    \
  }

#define GENERATE_CKKSNULL_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, SCALE, FIRST_MOD, NUMPRIME, RELIN, BATCH, \
                                    KEYSWITCH, RESCALEALG)                                                         \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME##_##KEYSWITCH##_##RESCALEALG) {                                      \
    CryptoContext<ELEMENT> cc;                                                                                  \
    try {                                                                                                          \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, SCALE, FIRST_MOD, SCALE, NUMPRIME, RELIN, BATCH, KEYSWITCH, \
                                         RESCALEALG);                                                              \
    } catch (...) {                                                                                                \
      std::exception_ptr p = std::current_exception();                                                             \
      std::cerr << (p ? p.__cxa_exception_type()->name() : "null") << std::endl;                                   \
      return;                                                                                                      \
    }                                                                                                              \
    FUNC<ELEMENT>(cc, #SCHEME);                                                                                    \
  }

#define GENERATE_CKKS_PERMUTE_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, SCALE, FIRST_MOD, NUMPRIME, RELIN,    \
                                        STRATEGY, BATCH, ITERS, KEYSWITCH, RESCALEALG)                             \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME##_##BATCH##_##STRATEGY##_##KEYSWITCH##_##RESCALEALG) {               \
    CryptoContext<ELEMENT> cc;                                                                                  \
    try {                                                                                                          \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, SCALE, FIRST_MOD, SCALE, NUMPRIME, RELIN, BATCH, KEYSWITCH, \
                                         RESCALEALG);                                                              \
    } catch (const not_implemented_error&) {                                                                       \
      return;                                                                                                      \
    } catch (const not_available_error&) {                                                                         \
      return;                                                                                                      \
    } catch (const std::exception& ex) {                                                                           \
      std::cerr << "Exception occurred: " << ex.what() << std::endl;                                               \
    } catch (...) {                                                                                                \
      std::cerr << "Unknown failure occurred." << std::endl;                                                       \
    }                                                                                                              \
    FUNC<ELEMENT>(cc, STRATEGY, BATCH, ITERS, #SCHEME);                                                            \
  }

// Somebody should figure out how to do recursive macros. I give up. For now.

//#define _PP_0(_1, ...) _1
//#define _PP_X(_1, ...) (__VA_ARGS__)

//#define ITER_0(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[0])
//#define ITER_1(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_0(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[1])
//#define ITER_2(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_1(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[2])
//#define ITER_3(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_2(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[3])
//#define ITER_4(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_3(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[4])
//#define ITER_5(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_4(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[5])
//#define ITER_6(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_5(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[6])
//#define ITER_7(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_6(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[7])
//#define ITER_8(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_7(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[8])
//#define ITER_9(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_8(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[9])
//#define ITER_10(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_9(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT)

//#define ITER(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_6(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT)
//
//static vector<string> V( {"Null", "StSt", "BGV", "BFV", "BFVrns"} );
//
//ITER(V, GENERATE_PKE_TEST_CASE, Encrypt_Decrypt, EncryptionScalar, Poly)

#endif /* SRC_CORE_LIB_UTILS_TESTCASEGEN_H_ */
