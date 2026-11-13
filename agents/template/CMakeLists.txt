cmake_minimum_required(VERSION 3.16.3)
project(openfhe_app CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# If OpenFHE is not in a default location, configure with
#   cmake -DCMAKE_PREFIX_PATH=/path/to/openfhe/install ..
find_package(OpenFHE CONFIG REQUIRED)
message(STATUS "OpenFHE ${BASE_OPENFHE_VERSION}, native size ${OpenFHE_NATIVE_SIZE}")

# OpenFHE must be compiled against with the flags it was built with.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenFHE_EXE_LINKER_FLAGS}")

include_directories(${OPENMP_INCLUDES})
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)
link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})

if(UNIX AND NOT APPLE)
    add_link_options(-Wl,--no-as-needed)
endif()

add_executable(app main.cpp)
# OpenFHE_LIBRARIES holds the libraries of the installation, shared or static
target_link_libraries(app ${OpenFHE_LIBRARIES})
