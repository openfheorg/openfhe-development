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
#include "blake2engine.h"

Blake2Engine* createEngineInstance() {
// initialization of PRNGs
constexpr size_t maxGens = Blake2Engine::MAX_SEED_GENS;
#pragma omp critical
        std::array<uint32_t, maxGens> initKey{};
        initKey[0] = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        initKey[1] = std::hash<std::thread::id>{}(std::this_thread::get_id());
#if !defined(__arm__) && !defined(__EMSCRIPTEN__)
        if (sizeof(size_t) == 8)
            initKey[2] = (std::hash<std::thread::id>{}(std::this_thread::get_id()) >> 32);
#endif
        void* mem        = malloc(1);
        uint32_t counter = reinterpret_cast<long long>(mem);  // NOLINT
        free(mem);

        Blake2Engine gen(initKey, counter);

        std::uniform_int_distribution<uint32_t> distribution(0);
        std::array<uint32_t, maxGens> seed{};
        for (uint32_t i = 0; i < maxGens; i++) {
            seed[i] = distribution(gen);
        }

        std::array<uint32_t, maxGens> rdseed{};
        size_t attempts  = 3;
        bool rdGenPassed = false;
        for(size_t i = 0; i < attempts && !rdGenPassed; ++i) {
            try {
                std::random_device genR;
                for (uint32_t i = 0; i < maxGens; i++) {
                    rdseed[i] = distribution(genR);
                }
                rdGenPassed = true;
            }
            catch (std::exception& e) {
            }
        }
        for (uint32_t i = 0; i < maxGens; i++) {
            seed[i] += rdseed[i];
        }

        return new Blake2Engine(seed);
}
