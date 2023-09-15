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
  Examples for scheme switching between CKKS and FHEW and back, with intermediate computations
 */

#include "openfhe.h"
#include <unistd.h>
#include <ios>
#include <iostream>
#include <fstream>
#include <string>
#include <malloc.h>

using namespace lbcrypto;

// mem_usage function is from: https://www.tutorialspoint.com/how-to-get-memory-usage-at-runtime-using-cplusplus
void mem_usage(double& vm_usage, double& resident_set) {
    using namespace std;
    vm_usage     = 0.0;
    resident_set = 0.0;
    ifstream stat_stream("/proc/self/stat", ios_base::in);  // get info from proc directory
    // create some variables to get info
    string pid, comm, state, ppid, pgrp, session, tty_nr;
    string tpgid, flags, minflt, cminflt, majflt, cmajflt;
    string utime, stime, cutime, cstime, priority, nice;
    string O, itrealvalue, starttime;
    uint64_t vsize;
    int64_t rss;
    stat_stream >> pid >> comm >> state >> ppid >> pgrp >> session >> tty_nr >> tpgid >> flags >> minflt >> cminflt >>
        majflt >> cmajflt >> utime >> stime >> cutime >> cstime >> priority >> nice >> O >> itrealvalue >> starttime >>
        vsize >> rss;  // don't care about the rest
    stat_stream.close();
    int64_t page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024;  // for x86-64 is configured to use 2MB pages
    vm_usage             = vsize / 1024.0;
    resident_set         = rss * page_size_kb;
}

int main() {
    using namespace std;
    uint32_t multDepth          = 15;
    uint32_t scaleFactorBits    = 50;
    uint32_t batchSize          = 8;
    SecurityLevel securityLevel = HEStd_128_classic;

    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleFactorBits);
    parameters.SetScalingTechnique(FIXEDAUTO);
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Input
    vector<double> x = {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7};
    double vm, rss;
    mem_usage(vm, rss);
    cout << "Before encoding 1000 plaintexts: "
         << "Virtual Memory: " << (vm / (1 << 20)) << "GB; Resident set size: " << (rss / (1 << 20)) << "GB." << endl;

    vector<Plaintext> memTest;
    for (size_t i = 0; i < 1000; i++) {
        memTest.emplace_back(cc->MakeCKKSPackedPlaintext(x));
    }
    mem_usage(vm, rss);
    cout << "After encoding 1000 plaintexts: "
         << "Virtual Memory: " << (vm / (1 << 20)) << "GB; Resident set size: " << (rss / (1 << 20)) << "GB." << endl;
    memTest.clear();

    int res = malloc_trim(0);
    std::cout << res << std::endl;

    sleep(1);
    mem_usage(vm, rss);
    cout << "After clearing 1000 plaintexts: "
         << "Virtual Memory: " << (vm / (1 << 20)) << "GB; Resident set size: " << (rss / (1 << 20)) << "GB." << endl;
    return 0;
}
