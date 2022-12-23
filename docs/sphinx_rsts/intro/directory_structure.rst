Directory Structure
====================================

The high-level structure of the OpenFHE library is as follows.

Several of these directories may contain a README file with more specific information about the files in the directory.

::

    .
    ├── benchmark
    ├── build
    ├── doc
    ├── src
    ├────── binfhe
    ├────── core
    ├────── pke
    ├── test
    └── third-party

The descriptions of library components are as follows:

.. csv-table:: components
   :header: "Directory", "Description"

   "benchmark","Code for benchmarking OpenFHE library components, using the Google Benchmark frameworks"
   "build","Binaries and build scripts (this folder is created by the user)"
   "doc","Documentation of library components."
   "docker","Docker file and documentation."
   "src","Library source code. Each subcomponent has four or five subdirectories: include (for library header files), lib (for library source files), unittest (for google test cases), examples (for code samples), and optionally extras (for additional code samples)."
   "third-party","Code for distributions from third parties (includes NTL/GMP + git submodules for tcmalloc, cereal, google test, and google benchmark)"
   "test","Google unit test code"
