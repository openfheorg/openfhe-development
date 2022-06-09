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
#ifndef _COMPARE_UTILS_H_
#define _COMPARE_UTILS_H_

#include <cmath>

namespace utils {
    constexpr double EPSILON = 1.0E-08;

    inline bool Equal(double a, double b, double eps = EPSILON) {
        return (eps > fabs(a - b));
    }

    inline bool Less(double a, double b, double eps = EPSILON) {
        return ((a - b) < (-eps));
    }

    inline bool Greater(double a, double b, double eps = EPSILON) {
        return ((a - b) > eps);
    }
};

#endif
