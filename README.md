PALISADE Lattice Cryptography Library
=====================================

PALISADE is a general lattice cryptography library that currently includes efficient implementations of the following lattice cryptography capabilities:
* Fully Homomorphic Encryption (FHE)
   * Brakerski/Fan-Vercauteren (BFV) scheme for integer arithmetic
   * Brakerski-Gentry-Vaikuntanathan (BGV) scheme for integer arithmetic
   * Cheon-Kim-Kim-Song (CKKS) scheme for real-number arithmetic
   * Ducas-Micciancio (FHEW) and Chillotti-Gama-Georgieva-Izabachene (TFHE) schemes for Boolean circuit evaluation
* Multi-Party Extensions of FHE (to support multi-key FHE)
   * Threshold FHE for BGV, BFV, and CKKS schemes
   * Proxy Re-Encryption for BGV, BFV, and CKKS schemes

Note as of version 1.11, the following features have been moved to their own repositories in the PALISADE group.

* Digital Signature (https://gitlab.com/palisade/palisade-signature)
* Identity-Based Encryption (https://gitlab.com/palisade/palisade-abe)
* Ciphertext-Policy Attribute-Based Encryption (https://gitlab.com/palisade/palisade-abe)

All the research prototypes for Key-Policy Attributed-Based Encryption and Program Obfuscation have been moved to https://gitlab.com/palisade/palisade-trapdoor)

PALISADE is a cross-platform C++11 library supporting Linux, Windows, and macOS. The supported compilers are g++ v6.1 or later and clang++ v6.0 or later.

The library also includes unit tests and sample application demos.

PALISADE is available under the BSD 2-clause license.

The library is based on modular architecture with the following layers:

* Math operations layer supporting low-level modular arithmetic, number theoretic transforms, and integer sampling.  This layer is implemented to be portable to multiple hardware computation substrates.
* Lattice operations layer supporting lattice operations, ring algebra, and lattice trapdoor sampling.
* Crypto layer containing efficient implementations of lattice cryptography schemes.
* Encoding layer supporting multiple plaintext encodings for cryptographic schemes.

A major focus is on the usability of the schemes. For instance, all HE schemes with packing use the same common API, and are implemented using runtime polymorphism.

PALISADE implements efficient Residue Number System (RNS) algorithms to achieve high performance, e.g., PALISADE was used as the library for a winning genome-wide association studies solution at iDASH’18.

By default, the library is built without external dependencies. But the user is also provided options to add GMP/NTL, tcmalloc, and/or Intel HEXL third-party libraries if desired.

Further information about PALISADE:

[License Information](LICENSE)

[Library Wiki with documentation](https://gitlab.com/palisade/palisade-development/wikis/home)

[Webinars](Webinars.md)

[YouTube Channel PALISADE](https://www.youtube.com/channel/UC1qByOsQina1rpZ8AGl5TZw)

[Code of Conduct](Code-of-conduct.md)

[Governance](Governance.md)

[Contributing to PALISADE](Contributing.md)

[PALISADE Examples](Examples.md)


Build Instructions
=====================================

We use CMake to build PALISADE. The high-level (platform-independent) procedure for building PALISADE is as follows (for OS-specific instructions, see the section "Detailed information about building PALISADE" at the bottom of this page):

1. Install system prerequisites (if not already installed), including a C++ compiler with OMP support, cmake, make, and autoconf.

2. Clone the PALISADE repo to your local machine.

3. Create a directory where the binaries will be built. The typical choice is a subfolder "build". In this case, the commands are:
```
mkdir build
cd build
cmake ..
```

Note that CMake will check for any system dependencies that are needed for the build process. If the CMake build does not complete successfully, please review the error CMake shows at the end. If the error does not go away (even though you installed the dependency), try running "make clean" to clear the CMake cache.

4. If you want to use any external libraries, such as NTL/GMP or tcmalloc, install these libraries.

5. Build PALISADE by running the following command (this will take few minutes; using the -j make command-line flag is suggested to speed up the build)
```
make
```
If you want to build only library files or some other subset of PALISADE, please review the last paragraph of this page.

After the "make" completes, you should see the PALISADE library files in the lib folder, binaries of demos in bin/demo, binaries of benchmarks in bib/benchmark, and binaries for unit tests in the unittest folder.

6. Install PALISADE to a system directory (if desired or for production purposes)
```
make install
```
You would probably need to run `sudo make install` unless you are specifying some other install location. You can change the install location by running
`cmake -DCMAKE_INSTALL_PREFIX=/your/path ..`. The header files are placed in the "include/palisade" folder of the specified path, and the binaries of the library
are copied directly to the "lib" folder. For example, if no installation path is provided in Ubuntu (and many other Unix-based OSes), the header and library
binary files will be placed in "/usr/local/include/palisade" and "/usr/local/lib", respectively.

Testing and cleaning the build
-------------------

Run unit tests to make sure all capabilities operate as expected
```
make testall
```

Run sample code to test, e.g.,
```
bin/examples/pke/simple-integers
```

To remove the files built by make, you can execute
```
make clean
```

Supported Operating Systems
--------------------------
PALISADE CI continually tests our builds on the following operating systems:

* Ubuntu [18.04] [20.04]
* macOS [Mojave]
* Centos 7
* NVIDIA Xavier [Linux for Tegra 4.2.2]
* MinGW (64-bit) on Windows 10

PALISADE users have reported successful operation on the following systems:

* FreeBSD
* Ubuntu [16.04]
* Arch Linux
* Manjaro Linux

Please let us know the results if you have run PALISADE any additional systems not listed above.

Detailed information about building PALISADE
------------------------------

More detailed steps for some common platforms are provided in the following Wiki articles:

[Instructions for building PALISADE in Linux](https://gitlab.com/palisade/palisade-development/wikis/Instructions-for-building-PALISADE-in-Linux)

[Instructions for building PALISADE in Windows](https://gitlab.com/palisade/palisade-development/wikis/Instructions-for-building-PALISADE-in-Windows)

[Instructions for building PALISADE in macOS](https://gitlab.com/palisade/palisade-development/wikis/Instructions-for-building-PALISADE-in-macOS)

PALISADE provides many CMake/make configuration options, such as installing specific modules of the library, compiling only libraries w/o any unit tests and demos, choosing the Debug mode for compilation, turning on/off NTL/GMP. These options are described in detail in the following Wiki article:

[Use of CMake in PALISADE](https://gitlab.com/palisade/palisade-development/-/wikis/Use-of-CMake-in-PALISADE)

[Instructions for building user projects that use PALISADE](https://gitlab.com/palisade/palisade-development/wikis/Instructions-for-building-user-projects-that-use-PALISADE)
