Installation
====================================

Welcome to the OpenFHE installation instructions! For OS-specific instructions, follow one of the following links below, or proceed with the high-level platform-independent installation instructions below.


.. note:: Note: By default, the library is built without external dependencies.
   But the user is also provided options to add

   - ``GMP/NTL``
   - ``tcmalloc``
   - and/or ``Intel HEXL`` third-party libraries if desired

.. toctree::
   :maxdepth: 1
   :caption: Contents:

   linux.rst
   macos.rst
   windows.rst
   cmake_in_openfhe.rst
   gmp_ntl.rst
   ../building_user_applications.rst


Build Instructions
##################
We use CMake to build OpenFHE. OpenFHE supports any GNU C++ compiler version 9 or above and clang C++ compiler version 10 or above.


1. Install system prerequisites (if not already installed), including a C++ compiler with OMP support, cmake, make.

2. Clone the OpenFHE repo to your local machine.

3. Create a directory where the binaries will be built. The typical choice is a subfolder "build". In this case, the commands are: ::

    mkdir build
    cd build
    cmake ..

.. note:: ``CMake`` will check for any system dependencies that are needed for the build process

   - If the ``CMake`` build does not complete successfully, please review the error ``CMake`` shows at the end.
   - If the error does not go away (even though you installed the dependency), try running ``make clean`` to clear the CMake cache.

4. If you want to use any external libraries, such as NTL/GMP or tcmalloc, install these libraries.

5. Build OpenFHE by running the following command (this will take few minutes; using the ``-j`` make command-line flag is suggested to speed up the build)
``make``

- If you want to build only library files or some other subset of OpenFHE, please review the last paragraph of this page.

- After the ``make`` completes, you should see the OpenFHE library files in the lib folder, binaries of examples in ``bin/examples``, binaries of benchmarks in ``bin/benchmark``, and binaries for unit tests in the unittest folder.

6. Install OpenFHE to a system directory (if desired or for production purposes) ::

    make install

You would probably need to run ``sudo make install`` unless you are specifying some other install location. You can change the install location by running
``cmake -DCMAKE_INSTALL_PREFIX=/your/path ..``.

- The header files are placed in the ``include/openfhe`` folder of the specified path, and the binaries of the library
  are copied directly to the ``lib`` folder. For example, if no installation path is provided in Ubuntu (and many other Unix-based OSes), the header and library
  binary files will be placed in ``/usr/local/include/openfhe`` and ``/usr/local/lib``, respectively.

Testing and cleaning the build
##############################


Run unit tests to make sure all capabilities operate as expected ::

   make testall

Run sample code to test, e.g., ::

   bin/examples/pke/simple-integers

To remove the files built by make, you can execute ::

   make clean

Supported Operating Systems
###########################
OpenFHE CI continually tests our builds on the following operating systems:

* Ubuntu [18.04] [20.04]
* macOS [Mojave]
* Centos 7
* NVIDIA Xavier [Linux for Tegra 4.2.2]
* MinGW (64-bit) on Windows 10

OpenFHE users have reported successful operation on the following systems:

* FreeBSD
* Ubuntu [16.04] [22.04] [23.04]
* macOS [Monterey] [Ventura]
* Arch Linux

Please let us know the results if you have run OpenFHE any additional systems not listed above.
