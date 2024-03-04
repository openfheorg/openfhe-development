##
## CMakeLists.txt for OpenFHE
##
## This script will build machine-specific header files for compile
## as it generates the Makefile
##
## Note many user options are handled using an OPTION in CMake
## An option has the value of ON or OFF
## See below for the list of options

cmake_minimum_required (VERSION 3.5.1)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-10")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-10")
##endif()
### TODO: for now, we use CLang for Mac

project (OpenFHE C CXX)

set(OPENFHE_VERSION_MAJOR 1)
set(OPENFHE_VERSION_MINOR 1)
set(OPENFHE_VERSION_PATCH 3)
set(OPENFHE_VERSION ${OPENFHE_VERSION_MAJOR}.${OPENFHE_VERSION_MINOR}.${OPENFHE_VERSION_PATCH})

set(CMAKE_CXX_STANDARD 17)
set(CXX_STANDARD_REQUIRED ON)

#--------------------------------------------------------------------
# Build options
#--------------------------------------------------------------------
if(CMAKE_BUILD_TYPE)
    set(RELEASE_TYPES Debug Release RelWithDebInfo MinSizeRel)
    list(FIND RELEASE_TYPES ${CMAKE_BUILD_TYPE} INDEX_FOUND)
    if(${INDEX_FOUND} EQUAL -1)
        message(FATAL_ERROR "CMAKE_BUILD_TYPE must be one of Debug, Release, RelWithDebInfo, or MinSizeRel" )
    endif()
else()
    # if no build type is chosen, default to Release mode
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Choose the type of build, options are: None, Debug, Release, RelWithDebInfo, or MinSizeRel." FORCE )
endif()

message(STATUS "Building in ${CMAKE_BUILD_TYPE} mode" )

if ( EMSCRIPTEN )
    set(BUILD_SHARED OFF)
    message( "Shared library is not supported by Emscripten")
    option( BUILD_STATIC "Set to ON to build static versions of the library"         ON  )
    option( BUILD_UNITTESTS "Set to ON to build unit tests for the library"          OFF )
    option( BUILD_EXAMPLES "Set to ON to build examples for the library"             OFF )
    option( BUILD_BENCHMARKS "Set to ON to build benchmarks for the library"         OFF )
    set(WITH_OPENMP OFF)
    message( "OpenMP is not supported by Emscripten" )
else()
    option( BUILD_SHARED "Set to ON to build shared versions of the library"         ON  )
    option( BUILD_STATIC "Set to ON to build static versions of the library"         OFF )
    option( BUILD_UNITTESTS "Set to ON to build unit tests for the library"          ON  )
    option( BUILD_EXAMPLES "Set to ON to build examples for the library"             ON  )
    option( BUILD_BENCHMARKS "Set to ON to build benchmarks for the library"         ON  )
    option( WITH_OPENMP "Use OpenMP to enable <omp.h>"                               ON  )
endif()

option( BUILD_EXTRAS "Set to ON to build extras for the library"                     OFF )
option( GIT_SUBMOD_AUTO "Submodules auto-update"                                     ON  )
option( WITH_BE2 "Include MATHBACKEND 2 in build by setting WITH_BE2 to ON"          OFF )
option( WITH_BE4 "Include MATHBACKEND 4 in build by setting WITH_BE4 to ON"          OFF )
option( WITH_NTL "Include MATHBACKEND 6 and NTL in build by setting WITH_NTL to ON"  OFF )
option( WITH_TCM "Activate tcmalloc by setting WITH_TCM to ON"                       OFF )
option( WITH_NATIVEOPT "Use machine-specific optimizations"                          OFF )
option( WITH_COVTEST "Turn on to enable coverage testing"                            OFF )
option( WITH_NOISE_DEBUG "Use only when running lattice estimator; not for production" OFF )
option( USE_MACPORTS "Use MacPorts installed packages"                               OFF )

# Set required number of bits for native integer in build by setting NATIVE_SIZE to 64 or 128
if( NOT NATIVE_SIZE )
    set( NATIVE_SIZE 64 )
endif()

if( NOT CKKS_M_FACTOR )
    set( CKKS_M_FACTOR 1 )
endif()

### Print options
message( STATUS "BUILD_UNITTESTS:  ${BUILD_UNITTESTS}")
message( STATUS "BUILD_EXAMPLES:   ${BUILD_EXAMPLES}")
message( STATUS "BUILD_BENCHMARKS: ${BUILD_BENCHMARKS}")
message( STATUS "BUILD_EXTRAS:     ${BUILD_EXTRAS}")
message( STATUS "BUILD_STATIC:     ${BUILD_STATIC}")
message( STATUS "BUILD_SHARED:     ${BUILD_SHARED}")
message( STATUS "GIT_SUBMOD_AUTO:  ${GIT_SUBMOD_AUTO}")
message( STATUS "WITH_BE2:         ${WITH_BE2}")
message( STATUS "WITH_BE4:         ${WITH_BE4}")
message( STATUS "WITH_NTL:         ${WITH_NTL}")
message( STATUS "WITH_TCM:         ${WITH_TCM}")
message( STATUS "WITH_OPENMP:      ${WITH_OPENMP}")
message( STATUS "NATIVE_SIZE:      ${NATIVE_SIZE}")
message( STATUS "CKKS_M_FACTOR:    ${CKKS_M_FACTOR}")
message( STATUS "WITH_NATIVEOPT:   ${WITH_NATIVEOPT}")
message( STATUS "WITH_COVTEST:     ${WITH_COVTEST}")
message( STATUS "WITH_NOISE_DEBUG: ${WITH_NOISE_DEBUG}")
message( STATUS "USE_MACPORTS:     ${USE_MACPORTS}")

#--------------------------------------------------------------------
# Compiler logic
#--------------------------------------------------------------------
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    # require at least gcc 9.0
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
        message(WARNING "GCC version should be at least 9.0.")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    # require at least clang 10
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10)
        message(WARNING "Clang version should be at least 10.0.")
    endif()
else()
    message(WARNING "You are using ${CMAKE_CXX_COMPILER_ID} version ${CMAKE_CXX_COMPILER_VERSION}, which is unsupported.")
endif()

# use, i.e. don't skip the full RPATH for the build tree
set(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

set(CMAKE_INSTALL_RPATH "${LIBINSTALL}")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${LIBINSTALL}" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
    set(CMAKE_INSTALL_RPATH "${LIBINSTALL}")
endif("${isSystemDir}" STREQUAL "-1")

# Compiler flags

# Added -Wno-parentheses for compatibility with g++
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set (IGNORE_WARNINGS "-Wno-parentheses")
    # we can use GNU built-in functions provided by GCC for debugging. ex: __builtin_LINE (), __builtin_FUNCTION (), __builtin_FILE ()
    add_definitions(-DBUILTIN_INFO_AVAILABLE)
    message (STATUS "BUILTIN_INFO_AVAILABLE is defined")
endif()

if("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    set(IGNORE_WARNINGS "${IGNORE_WARNINGS} -Wno-unused-private-field -Wno-shift-op-parentheses")
endif()

if( WITH_NATIVEOPT )
    set (NATIVE_OPT "-march=native")
else()
    set (NATIVE_OPT "")
endif()

set(C_COMPILE_FLAGS "-Wall -Werror -O3 ${NATIVE_OPT} -DOPENFHE_VERSION=${OPENFHE_VERSION}")
set(CXX_COMPILE_FLAGS "-Wall -Werror -O3 ${NATIVE_OPT} -DOPENFHE_VERSION=${OPENFHE_VERSION} ${IGNORE_WARNINGS}")

if ( EMSCRIPTEN )
    set(EMSCRIPTEN_IGNORE_WARNINGS "-Wno-unused-but-set-variable -Wno-unknown-warning-option")
    set(C_COMPILE_FLAGS "${C_COMPILE_FLAGS} ${EMSCRIPTEN_IGNORE_WARNINGS}")
    set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} ${EMSCRIPTEN_IGNORE_WARNINGS}")
    add_compile_options(-fexceptions)
    add_link_options(
        -sINITIAL_MEMORY=2047MB -sMAXIMUM_MEMORY=4GB -sALLOW_MEMORY_GROWTH=1
        -sMALLOC=emmalloc -sNO_DISABLE_EXCEPTION_CATCHING
    )
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_COMPILE_FLAGS}")

if(WITH_COVTEST)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
    link_libraries(gcov)
    set( BUILDDIR ${CMAKE_CURRENT_SOURCE_DIR}/build/)
    set( COVDIR ${BUILDDIR}coverage/)
endif()

if(BUILD_STATIC)
    set(OpenFHE_STATIC_LIBS OPENFHEcore_static OPENFHEpke_static OPENFHEbinfhe_static)
endif()

if(BUILD_SHARED)
    set(OpenFHE_SHARED_LIBS OPENFHEcore OPENFHEpke OPENFHEbinfhe)
endif()

set(OpenFHE_PACKAGE_LIBS ${OpenFHE_STATIC_LIBS} ${OpenFHE_SHARED_LIBS})

#--------------------------------------------------------------------
# Installation logic
#--------------------------------------------------------------------


### set up for install
set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(INSTALL_INCLUDE_DIR include/openfhe CACHE PATH "Installation directory for headers")
if(WIN32 AND NOT CYGWIN)
    set(DEF_INSTALL_CMAKE_DIR CMake)
else()
    set(DEF_INSTALL_CMAKE_DIR lib/OpenFHE)
endif()
set(INSTALL_CMAKE_DIR ${DEF_INSTALL_CMAKE_DIR} CACHE PATH "Installation directory for CMake files")

foreach(p LIB INCLUDE CMAKE)
    set(var INSTALL_${p}_DIR)
    if(NOT IS_ABSOLUTE "${${var}}")
        set(${var} "${CMAKE_INSTALL_PREFIX}/${${var}}")
    endif()
endforeach()

message("***** INSTALL IS AT ${CMAKE_INSTALL_PREFIX}; to change, run cmake with -DCMAKE_INSTALL_PREFIX=/your/path")
set (CMAKE_INSTALL_MESSAGE LAZY)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

#--------------------------------------------------------------------
# Uninstall logic
#--------------------------------------------------------------------
## clobber cleans and deletes the third-party stuff
add_custom_target(
        COMMAND make clean
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target("uninstall" COMMENT "Uninstall OpenFHE files")
add_custom_command(
        TARGET "uninstall"
        POST_BUILD
        COMMENT "Uninstall files within install_manifest.txt"
        COMMAND ../scripts/uninstall_openfhe.sh
        USES_TERMINAL
)


#--------------------------------------------------------------------
# Machine-specific checks
#--------------------------------------------------------------------
# determine the architecture on a Linux/Unix/macOS/MinGW system
if(CMAKE_HOST_UNIX OR MINGW)
    EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )
else()
    set(ARCHITECTURE "unknown")
endif()

if(ARCHITECTURE)
    if (${ARCHITECTURE} MATCHES "i386")
        message(SEND_ERROR "The " ${ARCHITECTURE} " architecture is not supported")
    else()
        message(STATUS "Architecture is " ${ARCHITECTURE})
    endif()
endif()

# Size checks
include(CheckTypeSize)
check_type_size("__int128" INT128)
check_type_size("uint64_t" INT64)

if (NOT(BUILD_SHARED OR BUILD_STATIC))
    message(SEND_ERROR "Either BUILD_SHARED or BUILD_STATIC neeed to be turned on.")
endif()

if( "${NATIVE_SIZE}" EQUAL 128 )
    if ( EMSCRIPTEN )
        message(SEND_ERROR "NATIVE_SIZE == 128 is not supported for EMSCRIPTEN")
    endif()
    if( ${HAVE_INT128} )
        set( NATIVEINT 128 )
        message (STATUS "NATIVEINT is set to " ${NATIVEINT})
    else()
        message(SEND_ERROR "Cannot support NATIVE_SIZE == 128")
    endif()
elseif( "${NATIVE_SIZE}" EQUAL 64 )
    if ( EMSCRIPTEN )
        set( HAVE_INT128 FALSE)
    endif()
    if( ${HAVE_INT64} )
        set( NATIVEINT 64 )
        message (STATUS "NATIVEINT is set to " ${NATIVEINT})
    else()
        message(SEND_ERROR "Cannot support NATIVE_SIZE == 64")
    endif()
elseif( "${NATIVE_SIZE}" EQUAL 32 )
    if( ${HAVE_INT64} )
        set( NATIVEINT 32 )
        set( HAVE_INT128 FALSE)
        message (STATUS "NATIVEINT is set to " ${NATIVEINT})
    else()
        message(SEND_ERROR "Cannot support NATIVE_SIZE == 32")
    endif()
else()
    message(SEND_ERROR "NATIVE_SIZE is " ${NATIVE_SIZE})
    message(SEND_ERROR "***ERROR*** need a Native implementation")
endif()


#--------------------------------------------------------------------
# Backend logic
#--------------------------------------------------------------------
if( NOT MATHBACKEND)
    set( MATHBACKEND 4 )
endif()

message (STATUS "MATHBACKEND is set to " ${MATHBACKEND})

if( "${NATIVEINT}" EQUAL 128 )
    if( "${MATHBACKEND}" EQUAL 6 )
        set (WITH_NTL OFF)
        set (MATHBACKEND 4)
        message (STATUS "MATHBACKEND 6 is not compatible with 128-bit native backend. Setting MATHBACKEND to 4.")
    elseif( WITH_NTL )
        set (WITH_NTL OFF)
        message (STATUS "MATHBACKEND 6 is not compatible with 128-bit native backend. Setting WITH_NTL to OFF.")
    endif()
endif()

if( "${MATHBACKEND}" EQUAL 2 )
    if( NOT WITH_BE2 )
        set (WITH_BE2 ON)
        message(STATUS "MATHBACKEND set to 2. Setting WITH_BE2 to ON")
    endif()
elseif( "${MATHBACKEND}" EQUAL 4 )
    if( NOT WITH_BE4 )
        set (WITH_BE4 ON)
        message(STATUS "MATHBACKEND set to 4. Setting WITH_BE4 to ON")
    endif()
elseif( "${MATHBACKEND}" EQUAL 6 )
    if( NOT WITH_NTL )
        set (WITH_NTL ON)
        message(STATUS "MATHBACKEND set to 6. Setting WITH_NTL to ON")
    endif()
else()
    message(SEND_ERROR "MATHBACKEND must be 2, 4 or 6")
endif()

set(OpenFHE_BACKEND_FLAGS "-DMATHBACKEND=${MATHBACKEND}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_BACKEND_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenFHE_BACKEND_FLAGS}")

if(WITH_TCM)
    message(STATUS "tcmalloc is turned ON")
    if(MINGW)
        message(SEND_ERROR "***ERROR*** tcmalloc is not supported for MinGW")
    endif()
endif()

### build configure_core.h to make options available
configure_file(./configure/config_core.in src/core/config_core.h)
install(FILES ${CMAKE_BINARY_DIR}/src/core/config_core.h DESTINATION include/openfhe/core)

find_program(TAR "gtar")
find_program(TAR "tar")

if(WITH_TCM OR WITH_NTL)
    ### tcmalloc, NTL and GMP require autoconf/automake/libtool to be installed.
    ### we need to make sure that they are:
    execute_process(COMMAND autogen --version OUTPUT_VARIABLE AUTOGEN_VER)
    # execute_process in MINGW by default does not run in a shell
    if(MINGW)
        execute_process(COMMAND sh autoconf --version OUTPUT_VARIABLE AUTOCONF_VER)
    else()
        execute_process(COMMAND autoconf --version OUTPUT_VARIABLE AUTOCONF_VER)
    endif()

    string(LENGTH "${AUTOCONF_VER}" AUTOCONF_VER_LEN)
    if( ${AUTOCONF_VER_LEN} EQUAL 0 )
        message(SEND_ERROR "Autoconf is not installed.")
    endif()
endif()

#--------------------------------------------------------------------
# OpenMP logic
#--------------------------------------------------------------------
if (WITH_OPENMP)
    # Used to optionally compile openmp code
    add_definitions(-DPARALLEL)

    # Set OpenMP configuration manually for macOS
    if (APPLE)
        if (USE_MACPORTS)
            # Macports-based installation
            message( STATUS "Using Macports setup")
            set(OPENMP_LIBRARIES "/opt/local/lib/libomp")
            set(OPENMP_INCLUDES "/opt/local/include/libomp")
            if(CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_C_COMPILER_ID MATCHES "AppleClang")
                set(OpenMP_C_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
                set(OpenMP_C_LIB_NAMES "omp")
                set(OpenMP_omp_LIBRARY ${OpenMP_C_LIB_NAMES})
            endif()
            if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
                set(OpenMP_CXX_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
                set(OpenMP_CXX_LIB_NAMES "omp")
                set(OpenMP_omp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
            endif()
        else (USE_MACPORTS)
            # Homebrew-based installation
            # Check for Apple M1 Processor
            if (${ARCHITECTURE} MATCHES "arm64")
                message( STATUS "Apple M1 detected")
                set(OPENMP_LIBRARIES "/opt/homebrew/opt/libomp/lib")
                set(OPENMP_INCLUDES "/opt/homebrew/opt/libomp/include")
            else() # Apple Intel Processor
                message( STATUS "Apple Intel detected")
                set(OPENMP_LIBRARIES "/usr/local/opt/libomp/lib")
                set(OPENMP_INCLUDES "/usr/local/opt/libomp/include")
            endif()

            if(CMAKE_C_COMPILER_ID MATCHES "Clang")
                set(OpenMP_C_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
                set(OpenMP_C_LIB_NAMES "libomp")
                set(OpenMP_libomp_LIBRARY ${OpenMP_C_LIB_NAMES})
            endif()
            if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
                set(OpenMP_CXX_FLAGS "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
                set(OpenMP_CXX_LIB_NAMES "libomp")
                set(OpenMP_libomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
            endif()
        endif (USE_MACPORTS)

        include_directories("${OPENMP_INCLUDES}")
        link_directories("${OPENMP_LIBRARIES}")
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")

        message( STATUS "OPENMP_LIBRARIES: " ${OPENMP_LIBRARIES})
        message( STATUS "OPENMP_INCLUDES: " ${OPENMP_INCLUDES})
        message( STATUS "OpenMP_CXX_FLAGS: " ${OpenMP_CXX_FLAGS})
        message( STATUS "OpenMP_CXX_LIB_NAMES: " ${OpenMP_CXX_LIB_NAMES})
    endif()

    find_package (OpenMP)
    # OpenMP_CXX_FOUND was added in cmake 3.9.x so we are also checking the OpenMP_FOUND flag
    if (OpenMP_CXX_FOUND OR OpenMP_FOUND)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
        set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
    else()
        message(SEND_ERROR "** ERROR ** OpenMP is not installed. If using macOS/clang, please run 'cmake ..' again.")
    endif()

    if (OpenMP_C_FOUND OR OpenMP_FOUND)
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    endif()
else()  # WITH_OPENMP == OFF
    find_package (Threads REQUIRED)
    # Disable unknown #pragma omp warning
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unknown-pragmas")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unknown-pragmas")
endif()

#--------------------------------------------------------------------
# Pthreads logic (only for Google benchmark)
#--------------------------------------------------------------------
# In order to have the Threads_FOUND on some Linux and macOS systems
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)

#--------------------------------------------------------------------
# Submodule Update logic
#--------------------------------------------------------------------
if(GIT_SUBMOD_AUTO AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
    # Update submodules as needed
    find_package (Git REQUIRED)
    message(STATUS "Submodule update")
    if(NOT GIT_SUBMODULE_SYNCED)
        # "git submodule sync --recursive" should run only once, when CMakeCache.txt doesn't exist'
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule sync --recursive
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                        RESULT_VARIABLE GIT_SUBMODULE_RESULT)
        if(NOT GIT_SUBMODULE_RESULT EQUAL "0")
            message(FATAL_ERROR "\"git submodule sync --recursive\" failed with ${GIT_SUBMODULE_RESULT}, please checkout submodules")
        endif()
    endif()

    execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    RESULT_VARIABLE GIT_SUBMODULE_RESULT)
    if(NOT GIT_SUBMODULE_RESULT EQUAL "0")
        if(NOT GIT_SUBMODULE_SYNCED)
            # print this message only if update has never happened
            message(FATAL_ERROR "\"git submodule update --init\" failed with ${GIT_SUBMODULE_RESULT}, please checkout submodules")
        else()
            message(SEND_ERROR "\"git submodule update --init\" failed with ${GIT_SUBMODULE_RESULT}, please checkout submodules or disable autoupdate with -DGIT_SUBMOD_AUTO=OFF")
        endif()
    endif()

    if(NOT GIT_SUBMODULE_SYNCED)
        set(GIT_SUBMODULE_SYNCED ON CACHE BOOL "" FORCE)
    endif()
endif()

#--------------------------------------------------------------------
# Coverage logic
#--------------------------------------------------------------------
if ( WITH_COVTEST )
    find_program(LCOV_BIN lcov)
    if (LCOV_BIN MATCHES "lcov$")
        #Creates the command make cov
        add_custom_target( cov
            DEPENDS core_tests pke_tests binfhe_tests
            COMMAND cd ${BUILDDIR} && mkdir -p coverage
            COMMAND cd ${BUILDDIR}/src/core/CMakeFiles/core_tests.dir/unittest/ && gcov *.gcno && lcov --capture --directory . --output-file ${COVDIR}/core.info
            COMMAND cd ${BUILDDIR}/src/pke/CMakeFiles/pke_tests.dir/unittest/ && gcov *.gcno && lcov --capture --directory . --output-file ${COVDIR}/pke.info
            COMMAND cd ${BUILDDIR}/src/binfhe/CMakeFiles/binfhe_tests.dir/unittest/ && gcov  *.gcno && lcov --capture --directory . --output-file ${COVDIR}/binfhe.info
            COMMAND cd ${COVDIR} && mkdir -p assets && genhtml -t "Coverage Test" -o ${COVDIR}/assets/ *.info
        )
        message(STATUS "lcov found in ${LCOV_BIN}")
    else ()
        message(STATUS "lcov needs to be installed to generate a coverage report")
    endif ()
endif()


#--------------------------------------------------------------------
# Third-party logic
#--------------------------------------------------------------------
include (ExternalProject)

# third party directories
set( THIRDPARTYDIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party )
include_directories( ${THIRDPARTYDIR}/include )

### Handle third-party CEREAL
include_directories( ${THIRDPARTYDIR}/cereal/include )
install(DIRECTORY ${THIRDPARTYDIR}/cereal/include/ DESTINATION include/openfhe)

include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/third-party/google-test/googletest )
include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/third-party/google-test/googletest/include )
include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/src/core/include )
include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/src/binfhe/include )

include_directories( ${CMAKE_CURRENT_BINARY_DIR}/src/core )

### Handle third-party gperftools for optional tcmalloc

add_custom_target(
    tcm
    COMMAND ./autogen.sh
    COMMAND ./configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/third-party --enable-minimal
    COMMAND make
    COMMAND make install
    WORKING_DIRECTORY ${THIRDPARTYDIR}/gperftools
)

add_custom_target(
    tcm_clean
    COMMAND rm -rf include/gperftools include/google lib/libtcmalloc_minimal* lib/pkgconfig/libtcmalloc* lib/pkgconfig/libprofiler.pc share/doc/gperftools
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party
)

if(BUILD_STATIC)
add_library(tcmalloc_static STATIC IMPORTED GLOBAL)
set_target_properties(tcmalloc_static PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libtcmalloc_minimal${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

if(BUILD_SHARED)
add_library(tcmalloc SHARED IMPORTED GLOBAL)
set_target_properties(tcmalloc PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib/libtcmalloc_minimal${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

if(WITH_TCM)
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/lib DESTINATION .
        FILES_MATCHING PATTERN "libtcmalloc_minimal.*")
    list(APPEND THIRDPARTYLIBS "tcmalloc")
    list(APPEND THIRDPARTYSTATICLIBS "tcmalloc_static")
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party/include DESTINATION include/openfhe/third-party/)
endif()

if(WITH_NTL)
    ### Find gmp and ntl libraries. They must be installed by the user
    list(APPEND general_paths "/usr" "/usr/local" "/opt" "/opt/local")
    list(APPEND header_suffixes "include" "include/NTL" "include/${CMAKE_LIBRARY_ARCHITECTURE}")
    list(APPEND lib_suffixes "lib" "lib/${CMAKE_LIBRARY_ARCHITECTURE}")
    if (NOT(NTL_INCLUDE_DIR AND NTL_LIBRARIES))
        find_path(NTL_INCLUDE_DIR
            NAMES RR.h
            PATHS ${general_paths}
            PATH_SUFFIXES ${header_suffixes}
        )
        find_library(NTL_LIBRARIES
            NAMES ntl libntl
            ONLY_CMAKE_FIND_ROOT_PATH
            PATHS ${general_paths}
            PATH_SUFFIXES ${lib_suffixes}
        )

        include(FindPackageHandleStandardArgs)
        FIND_PACKAGE_HANDLE_STANDARD_ARGS(NTL DEFAULT_MSG NTL_INCLUDE_DIR NTL_LIBRARIES)
        if(NTL_FOUND)
            get_filename_component(NTL_LIBRARIES ${NTL_LIBRARIES} DIRECTORY)
        else()
            message(FATAL_ERROR "** ERROR ** libntl is not found."
                "In order to use MATHBACKEND 6, install libntl or pass -DNTL_INCLUDE_DIR=<dir> and -DNTL_LIBRARIES=<dir> to cmake")
        endif()
    endif()

    if (NOT(GMP_INCLUDE_DIR AND GMP_LIBRARIES))
        find_path(GMP_INCLUDE_DIR
            NAMES gmp.h
            PATHS ${general_paths}
            PATH_SUFFIXES ${header_suffixes}
        )
        find_library(GMP_LIBRARIES
            NAMES gmp libgmp
            ONLY_CMAKE_FIND_ROOT_PATH
            PATHS ${general_paths}
            PATH_SUFFIXES ${lib_suffixes}
        )

        include(FindPackageHandleStandardArgs)
        FIND_PACKAGE_HANDLE_STANDARD_ARGS(GMP DEFAULT_MSG GMP_INCLUDE_DIR GMP_LIBRARIES)
        if(GMP_FOUND)
            get_filename_component(GMP_LIBRARIES ${GMP_LIBRARIES} DIRECTORY)
        else()
            message(FATAL_ERROR "** ERROR ** libgmp is not found."
                "In order to use MATHBACKEND 6, install libgmp or pass -DGMP_INCLUDE_DIR=<dir> and -GMPL_LIBRARIES=<dir> to cmake")
        endif()
    endif()
    mark_as_advanced(NTL_INCLUDE_DIR NTL_LIBRARIES)
    mark_as_advanced(GMP_INCLUDE_DIR GMP_LIBRARIES)
    include_directories(${NTL_INCLUDE_DIR})
    include_directories(${GMP_INCLUDE_DIR})
    link_directories(${NTL_LIBRARIES})
    link_directories(${GMP_LIBRARIES})

    list(APPEND THIRDPARTYLIBS "ntl")
    list(APPEND THIRDPARTYLIBS "gmp")
    list(APPEND THIRDPARTYSTATICLIBS "ntl")
    list(APPEND THIRDPARTYSTATICLIBS "gmp")
endif()

set(DEMODATAPATH ${CMAKE_CURRENT_SOURCE_DIR}/demoData)
set(BINDEMODATAPATH ${CMAKE_CURRENT_BINARY_DIR}/demoData)

# copies demoData folder from the root of the repo to build/demoData if the folder does not exist
add_custom_target(third-party ALL
    COMMAND [ ! -d ${BINDEMODATAPATH} ] && cp -R ${DEMODATAPATH} ${BINDEMODATAPATH} && echo "-- Copied demoData files" || echo "-- demoData folder already exists" )

# when running "make clean", additionally deletes the demoData folder and CMake cache file
set(ADDITIONAL_CLEAN_FILES "")
LIST(APPEND ADDITIONAL_CLEAN_FILES ${BINDEMODATAPATH})
LIST(APPEND ADDITIONAL_CLEAN_FILES ${CMAKE_CURRENT_BINARY_DIR}/CMakeCache.txt)

## for tests
if( BUILD_UNITTESTS )
    set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)
endif()

### add each of the subdirs of src
add_subdirectory(src/core)
add_subdirectory(src/pke)
add_subdirectory(src/binfhe)

### build the google test handlers
###if( BUILD_UNITTESTS )
###	add_subdirectory(third-party/google-test EXCLUDE_FROM_ALL)
###endif()

### build the google benchmark handlers (just the parts we need)
if ( BUILD_BENCHMARKS )
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Enable testing of the benchmark library." FORCE)
    set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Enable installation of benchmark. (Projects embedding benchmark may want to turn this OFF.)" FORCE)
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Enable building the unit tests which depend on gtest" FORCE)
    add_subdirectory(third-party/google-benchmark EXCLUDE_FROM_ALL)
    add_subdirectory(benchmark)
endif()

## clobber cleans AND deletes the third-party stuff
add_custom_target( clobber COMMAND make clean WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} )

if( BUILD_UNITTESTS )
    add_custom_target( testall
        DEPENDS core_tests pke_tests  binfhe_tests
        COMMAND echo core: && unittest/core_tests -t || true
        COMMAND echo pke: && unittest/pke_tests -t || true
        COMMAND echo binfhe: && unittest/binfhe_tests -t )
endif()

if (BUILD_EXAMPLES)
    add_custom_target( allexamples DEPENDS allcoreexamples allpkeexamples allbinfheexamples )
endif()

if (BUILD_EXTRAS)
    add_custom_target( allextras DEPENDS allcoreextras allpkeextras )
endif()

add_custom_target( allmodules DEPENDS ${OpenFHE_PACKAGE_LIBS} )

# Add the additional "make clean" files
GET_DIRECTORY_PROPERTY(clean_files ADDITIONAL_MAKE_CLEAN_FILES)
LIST(APPEND            clean_files ${ADDITIONAL_CLEAN_FILES})
LIST(REMOVE_DUPLICATES clean_files)
LIST(REMOVE_ITEM       clean_files "")
SET_DIRECTORY_PROPERTIES(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${clean_files}")

export(EXPORT OpenFHETargets FILE "${PROJECT_BINARY_DIR}/OpenFHETargets.cmake")

export(PACKAGE OpenFHE)

# Create the OpenFHEConfig.cmake and OpenFHEConfigVersion files
file(RELATIVE_PATH REL_INCLUDE_DIR "${INSTALL_CMAKE_DIR}"
   "${INSTALL_INCLUDE_DIR}")
# ... for the build tree
set(CONF_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}" "${PROJECT_BINARY_DIR}")
configure_file(OpenFHEConfig.cmake.in
  "${PROJECT_BINARY_DIR}/OpenFHEConfig.cmake" @ONLY)
# ... for the install tree
set(CONF_INCLUDE_DIRS "\${OpenFHE_CMAKE_DIR}/${REL_INCLUDE_DIR}")
configure_file(OpenFHEConfig.cmake.in
  "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/OpenFHEConfig.cmake" @ONLY)
# ... for both
configure_file(OpenFHEConfigVersion.cmake.in
  "${PROJECT_BINARY_DIR}/OpenFHEConfigVersion.cmake" @ONLY)

# Install the OpenFHEConfig.cmake and OpenFHEConfigVersion.cmake
install(FILES
  "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/OpenFHEConfig.cmake"
  "${PROJECT_BINARY_DIR}/OpenFHEConfigVersion.cmake"
  DESTINATION "${INSTALL_CMAKE_DIR}" COMPONENT dev)

# Install the export set for use with the install-tree
install(EXPORT OpenFHETargets DESTINATION
  "${INSTALL_CMAKE_DIR}" COMPONENT dev)
