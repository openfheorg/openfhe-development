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
#include "UnitTestReadCSVData.h"
#include "UnitTestException.h"

#include "scheme/gen-cryptocontext-params.h"
#include "utils/exception.h"

#include <fstream>
#include <sstream>
#include <utility>

//===========================================================================================================
constexpr char DELIMITER   = ',';
constexpr char EXTENSION[] = ".csv";
//===========================================================================================================
std::string createDataFileName(const std::string& sourceFileName) {
    size_t lastindex = sourceFileName.find_last_of(".");
    return (sourceFileName.substr(0, lastindex) + EXTENSION);
}
std::string createDataFileName(const char* sourceFileName) {
    return createDataFileName(std::string(sourceFileName));
}
//===========================================================================================================
std::vector<std::string> tokenize(const std::string& str, const char delim) {
    std::istringstream ss(std::move(str));
    std::vector<std::string> vec;
    for (std::string val; std::getline(ss, val, delim);) {
        vec.push_back(std::move(val));
    }
    return vec;
}
//===========================================================================================================
/**
 * checkColumnNamesForCryptocontextParameters() gets the first table row with column names and checks
 * if there are columns for all cryptocontext parameters. Throws an exception on error. The function is static in order
 * to limit access to it with this file.
 *
 * @param testData is the open file with test data
 */
static void checkColumnNamesForCryptocontextParameters(std::ifstream& testData) {
    std::string line;
    std::getline(testData, line);
    // get all the columns first
    auto row = tokenize(line, DELIMITER);
    // skip the first 2 fields as they are for the test name
    auto start = row.begin() + 2;
    std::vector<std::string> columnNames(start, start + lbcrypto::Params::getAllParamsDataMembers().size());
    if (columnNames != lbcrypto::Params::getAllParamsDataMembers()) {
        std::string s;
        for (const auto& n : columnNames) {
            s += n + ',';
        }
        std::string errMsg(
            std::string(
                "Check the number and names of the columns for cryptoparameters as they do not match the expected: ") +
            s);
        OPENFHE_THROW(errMsg);
    }
}
//===========================================================================================================
std::vector<std::vector<std::string>> readDataFile(const std::string& dataFileName) {
    std::ifstream testData(dataFileName);
    if (!testData.is_open()) {
        OPENFHE_THROW("Cannot read file " + dataFileName);
    }

    try {
        checkColumnNamesForCryptocontextParameters(testData);

        std::vector<std::vector<std::string>> fileRows;
        for (std::string line; std::getline(testData, line);) {
            // skip all commented lines; they start with #
            if (line[0] != '#') {
                auto row = tokenize(line, DELIMITER);
                fileRows.push_back(std::move(row));
            }
        }

        return fileRows;
    }
    catch (std::exception& e) {
        std::string errMsg(std::string("Exception for data file ") + dataFileName + ": " + e.what());
        OPENFHE_THROW(errMsg);
    }
    catch (...) {
        std::string errMsg(std::string("Unknown exception for data file ") + dataFileName + ": type " +
                           UNIT_TEST_EXCEPTION_TYPE_NAME);
        OPENFHE_THROW(errMsg);
    }
}
//===========================================================================================================
