//==================================================================================
// © 2024 Duality Technologies, Inc. All rights reserved.
// This is a proprietary software product of Duality Technologies, Inc.
// protected under copyright laws and international copyright treaties, patent
// law, trade secret law and other intellectual property rights of general
// applicability. Any use of this software is strictly prohibited absent a
// written agreement executed by Duality Technologies, Inc., which provides
// certain limited rights to use this software. You may not copy, distribute,
// make publicly available, publicly perform, disassemble, de-compile or reverse
// engineer any part of this software, breach its security, or circumvent,
// manipulate, impair or disrupt its operation.
//==================================================================================
#ifndef __PRNG_H__
#define __PRNG_H__

#include <cstdint>
#include <limits>


class PRNG {
public:
    // all C++11 distributions used in OpenFHE work by default with uint32_t
    // a different data type can be specified if needed for a particular
    // architecture
    using result_type = uint32_t;
    
    PRNG(result_type seed) {}
  /**
   * @brief minimum value used by C+11 distribution generators when no lower
   * bound is explicitly specified by the user
   */
  static constexpr result_type min() {
    return std::numeric_limits<result_type>::min();
  }

  /**
   * @brief maximum value used by C+11 distribution generators when no upper
   * bound is explicitly specified by the user
   */
  static constexpr result_type max() {
    return std::numeric_limits<result_type>::max();
  }

    virtual result_type operator()() = 0;
    virtual ~PRNG() = default;
};

#endif // __PRNG_H__

