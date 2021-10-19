PALISADE Lattice Cryptography Library - Tests
=============================================

[License Information](License.md)

Document Description
===================
This document discusses the scripts and procedures in the test/ directory. **Note that these scripts were written for the previous make configuration. They need to be updated to use the new CMake flags and build directory.**

Test Directory Description
==========================

Directory Objective
-------------------
This directory contains common test code and shell scripts useful for executing and automating
various PALISADE tests.

The scripts have to be run from the build directory, e.g., ../test/build_all_backends.sh.

File Listing
------------

* test
- [build_all_backends.sh](test/build_all_backends.sh) builds the library for all valid math backends. Each backend is placed in its own bin directory, bin/backend-N, where N is the backend number. Does a clean build of all backends, unless a backend number is passed on the command line; in that case, only that backend is built, WITHOUT a clean
- [test_all_backends.sh](test/test_all_backends.sh) runs "make testall" on each of the backends built by build_all_backends, unless a backend number is passed on the command line; in that case, only that backend is tested

- [build_cov_test_backends.sh](test/build_cov_test_backends.sh) builds the library for all valid math backends with coverage testing available. Each backend is placed in its own bin directory, bin/backend-N-cov, where N is the backend number. Does a clean build of all backends, unless a backend number is passed on the command line; in that case, only that backend is built, WITHOUT a clean
- [test_cov_backends.sh](test/test_cov_backends.sh) runs coverage test on each of the backends built by build_cov_test_backend, unless a backend number is passed on the command line; in that case, only that backend is tested

- [benchmark_all_backends.sh](test/benchmark_all_backends.sh) runs benchmarks against the backends built by build_all_backends.sh

- [valgrind_all_backends.sh](test/valgrind_all_backends.sh) runs valgrind on the unit tests for the backends built by build_all_backends, unless a backend number is passed on the command line; in that case, only that backend is tested

* test/include:
- [gtest](test/include/gtest) contains all
