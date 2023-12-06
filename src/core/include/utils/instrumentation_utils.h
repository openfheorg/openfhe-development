//
// Created by iq on 2/1/23.
//



#ifndef OPENFHE_SRC_CORE_INCLUDE_UTILS_INSTRUMENTATION_UTILS_H_
#define OPENFHE_SRC_CORE_INCLUDE_UTILS_INSTRUMENTATION_UTILS_H_

#include <string>
#include <iostream>
#include <chrono>
#include <ctime>

// strftime format
#define LOGGER_PRETTY_TIME_FORMAT "%Y-%m-%d %H:%M:%S"

// printf format
#define LOGGER_PRETTY_MS_FORMAT ".%03d"

// convert current time to milliseconds since unix epoch
template<typename T>
static int to_ms(const std::chrono::time_point<T> &tp) {
    using namespace std::chrono;

    auto dur = tp.time_since_epoch();
    return static_cast<int>(duration_cast<milliseconds>(dur).count());
}

// format it in two parts: main part with date and time and part with milliseconds
static std::string pretty_time() {
    auto tp = std::chrono::system_clock::now();
    std::time_t current_time = std::chrono::system_clock::to_time_t(tp);

    // this function use static global pointer. so it is not thread safe solution
    std::tm *time_info = std::localtime(&current_time);

    char buffer[128];

    int string_size = strftime(
        buffer, sizeof(buffer),
        LOGGER_PRETTY_TIME_FORMAT,
        time_info
    );

    int ms = to_ms(tp) % 1000;

    string_size += std::snprintf(
        buffer + string_size, sizeof(buffer) - string_size,
        LOGGER_PRETTY_MS_FORMAT, ms
    );

    return std::string(buffer, buffer + string_size);
}

inline void logInstrumentationResults(int originalValue, int finalValue, std::string name) {
    auto tm = pretty_time();
    std::cout << tm << ":" << name << ": Started: " << originalValue << " Ended: " << finalValue
              << " Diff: " << (finalValue - originalValue) << std::endl;
}

#endif  //OPENFHE_SRC_CORE_INCLUDE_UTILS_INSTRUMENTATION_UTILS_H_
