/*
 * @file
 * @author TPOC: contact@openfhe.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <iostream>

#include "include/gtest/gtest.h"
#include "src/gtest-all.cc"

#include "lattice/lat-hal.h"
#include "lattice/ilelement.h"
#include "math/math-hal.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;
using namespace testing;

static string lead = "****** ";

class MinimalistPrinter : public EmptyTestEventListener {
public:
    void OnTestProgramStart(const ::testing::UnitTest& unit_test) {
        cout << lead << "OpenFHE Version " << GetOPENFHEVersion() << endl;
        cout << lead << "Date " << testing::internal::FormatEpochTimeInMillisAsIso8601(unit_test.start_timestamp())
             << endl;
    }
    void OnTestIterationStart(const ::testing::UnitTest& unit_test, int iteration) {}
    void OnEnvironmentsSetUpStart(const ::testing::UnitTest& unit_test) {}
    void OnEnvironmentsSetUpEnd(const ::testing::UnitTest& unit_test) {}
    void OnTestCaseStart(const ::testing::TestCase& test_case) {}
    void OnTestStart(const ::testing::TestInfo& test_info) {}

    // Called after a failed assertion or a SUCCEED() invocation.
    void OnTestPartResult(const ::testing::TestPartResult& test_part_result) {}

    void OnTestEnd(const ::testing::TestInfo& test_info) {
        if (test_info.result()->Passed()) {
            return;
        }

        auto tr = test_info.result();

        for (int i = 0; i < tr->total_part_count(); i++) {
            auto pr = tr->GetTestPartResult(i);
            if (pr.passed())
                continue;

            internal::ColoredPrintf(internal::COLOR_GREEN, "[ RUN      ] ");
            printf("%s.%s\n", test_info.test_case_name(), test_info.name());
            fflush(stdout);

            auto n = pr.file_name();
            if (n != NULL)
                cout << n << ":" << pr.line_number() << "\n";

            cout << pr.summary() << endl;

            internal::ColoredPrintf(internal::COLOR_RED, "[  FAILED  ] ");
            printf("%s.%s\n", test_info.test_case_name(), test_info.name());
            fflush(stdout);
            internal::PrintFullTestCommentIfPresent(test_info);
        }
    }
    void OnTestCaseEnd(const ::testing::TestCase& test_case) {}
    void OnEnvironmentsTearDownStart(const ::testing::UnitTest& unit_test) {}
    void OnEnvironmentsTearDownEnd(const ::testing::UnitTest& /*unit_test*/) {}
    void OnTestIterationEnd(const ::testing::UnitTest& unit_test, int iteration) {}

    void OnTestProgramEnd(const ::testing::UnitTest& unit_test) {
        cout << lead << "End " << unit_test.test_to_run_count() << " cases " << unit_test.successful_test_count()
             << " passed " << unit_test.failed_test_count() << " failed" << endl;

        const int failed_test_count = unit_test.failed_test_count();
        if (failed_test_count == 0) {
            return;
        }

        for (int i = 0; i < unit_test.total_test_case_count(); ++i) {
            const TestCase& test_case = *unit_test.GetTestCase(i);
            if (!test_case.should_run() || (test_case.failed_test_count() == 0)) {
                continue;
            }
            for (int j = 0; j < test_case.total_test_count(); ++j) {
                const TestInfo& test_info = *test_case.GetTestInfo(j);
                if (!test_info.should_run() || test_info.result()->Passed()) {
                    continue;
                }
                internal::ColoredPrintf(internal::COLOR_RED, "[  FAILED  ] ");
                printf("%s.%s", test_case.name(), test_info.name());
                internal::PrintFullTestCommentIfPresent(test_info);
                printf("\n");
            }
        }
    }
};

bool TestB2     = false;
bool TestB4     = false;
bool TestB6     = false;
bool TestNative = true;

inline const std::string& GetMathBackendParameters() {
    static std::string id = "Backend " + std::to_string(MATHBACKEND) +
#ifdef WITH_BE2
                            (MATHBACKEND == 2 ? " internal int size " + std::to_string(sizeof(integral_dtype) * 8) +
                                                    " BitLength " + std::to_string(BigIntegerBitLength) :
                                                "") +
#endif
                            "";
    return id;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    bool terse = false;
    bool beset = false;
    for (int i = 1; i < argc; i++) {
        if (string(argv[i]) == "-t") {
            terse = true;
        }
        else if (string(argv[i]) == "-all") {
#ifdef WITH_BE2
            TestB2 = true;
#endif
#ifdef WITH_BE4
            TestB4 = true;
#endif
#ifdef WITH_NTL
            TestB6 = true;
#endif
            beset = true;
        }
        else if (string(argv[i]) == "-2") {
            TestB2 = true;
            beset  = true;
        }
        else if (string(argv[i]) == "-4") {
            TestB4 = true;
            beset  = true;
        }
        else if (string(argv[i]) == "-6") {
            TestB6 = true;
            beset  = true;
        }
    }

    // if there are no filters used, default to omitting VERY_LONG tests
    // otherwise we lose control over which tests we can run

    if (::testing::GTEST_FLAG(filter) == "*") {
        ::testing::GTEST_FLAG(filter) = "-*_VERY_LONG";
    }

    ::testing::TestEventListeners& listeners = ::testing::UnitTest::GetInstance()->listeners();

    if (!beset) {
        if (MATHBACKEND == 2)
            TestB2 = true;
        else if (MATHBACKEND == 4)
            TestB4 = true;
        else if (MATHBACKEND == 6)
            TestB6 = true;
    }

    if (terse) {
        // Adds a listener to the end.  Google Test takes the ownership.
        delete listeners.Release(listeners.default_result_printer());
        listeners.Append(new MinimalistPrinter);
    }
    else {
        cout << "OpenFHE Version " << GetOPENFHEVersion() << endl;
        cout << "Default Backend " << GetMathBackendParameters() << endl;
    }

    std::cout << "Testing Backends: " << (TestB2 ? "2 " : "") << (TestB4 ? "4 " : "") << (TestB6 ? "6 " : "")
              << (TestNative ? "Native " : "") << std::endl;

    return RUN_ALL_TESTS();
}
