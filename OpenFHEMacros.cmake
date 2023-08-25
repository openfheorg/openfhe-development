macro(enable_cmake_cache)
    find_program(CCACHE_PROGRAM ccache)
    if(CCACHE_PROGRAM)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
    endif()
endmacro()
#======================================================================================================================
macro(set_cpp_standard CPP_STANDARD)
    set(CMAKE_CXX_STANDARD "${CPP_STANDARD}")
    set(CMAKE_CXX_STANDARD_REQUIRED True)
endmacro()
#======================================================================================================================
macro(set_min_and_target_gcc_versions MIN_VERSION TARGET_VERSION)
    set(GCC_MIN_VERSION "${MIN_VERSION}")
    set(GCC_TARGET_VERSION "${TARGET_VERSION}")
endmacro()
#======================================================================================================================
macro(set_min_and_target_clang_versions MIN_VERSION TARGET_VERSION)
    set(CLANG_MIN_VERSION "${MIN_VERSION}")
    set(CLANG_TARGET_VERSION "${TARGET_VERSION}")
endmacro()
#======================================================================================================================
macro(check_build_type)
    if(CMAKE_BUILD_TYPE)
    set(RELEASE_TYPES
            Debug
            Release
            RelWithDebInfoGCC_VERSION_MIN
            MinSizeRel)
    list(FIND RELEASE_TYPES ${CMAKE_BUILD_TYPE} INDEX_FOUND)
    if(${INDEX_FOUND} EQUAL -1)
        message(FATAL_ERROR
                "CMAKE_BUILD_TYPE must be one of Debug, Release, RelWithDebInfo, or MinSizeRel")
    endif()
    else()
    # if no build type is chosen, default to Release mode
    set(CMAKE_BUILD_TYPE Release CACHE STRING
            "Choose the type of build, options are: None, Debug, Release, RelWithDebInfo, or MinSizeRel."
            FORCE )
    endif()

    message(STATUS "Building in ${CMAKE_BUILD_TYPE} mode" )
endmacro()
#======================================================================================================================
macro(check_installed_compiler_version)
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${GCC_MIN_VERSION})
            message(FATAL_ERROR "GCC version should be at least ${GCC_MIN_VERSION}.")
        elseif(CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${GCC_TARGET_VERSION})
            message(WARNING "GCC target version is ${GCC_TARGET_VERSION}.")
        endif()
    elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
        if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${CLANG_MIN_VERSION})
            message(FATAL_ERROR "Clang version should be at least ${CLANG_MIN_VERSION}.")
        elseif(CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${CLANG_TARGET_VERSION})
            message(WARNING "Clang target version is ${CLANG_TARGET_VERSION}.")
        endif()
    else()
        message(WARNING "You are using ${CMAKE_CXX_COMPILER_ID} version ${CMAKE_CXX_COMPILER_VERSION}, which is unsupported.")
    endif()
endmacro()
#======================================================================================================================
