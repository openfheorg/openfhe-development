Installing OpenFHE on Linux
====================================

.. note:: CentOS Installation

    The installation process is the same as in Ubuntu except for using ``dnf`` instead of ``apt-get`` in Step 1. Here we provide additional notes specific to CentOS.

    On CentOS Stream 10, the default GCC 14 compiler meets the minimum requirement:

    ::

        sudo dnf install cmake gcc-c++

    On CentOS Stream 8 or 9, install GCC Toolset 13 and enable it in the shell where you will build OpenFHE:

    ::

        sudo dnf install cmake gcc-toolset-13
        scl enable gcc-toolset-13 bash

    .. important::

        CentOS GCC Toolsets must be activated before CMake can detect them. Run CMake and the build from the shell started by ``scl enable gcc-toolset-13 bash``.

1. Install pre-requisites (if not already installed) and set the default compiler.

.. topic:: g++

    OpenFHE requires g++ 13 or later. You can use ``g++ --version`` to check the version found by the system.

    On Ubuntu 24.04, install the minimum supported version of ``g++``, along with ``cmake`` and ``make``:

    ::

        sudo apt-get update
        sudo apt-get install g++-13 cmake make

    Then configure GCC 13 as the C and C++ compilers:

    ::

        export CC=/usr/bin/gcc-13
        export CXX=/usr/bin/g++-13

.. topic:: clang

    Typically g++ is the default compiler for Linux, but clang++ 18 or later can also be used.

    On Ubuntu 24.04, install the minimum supported version of clang/clang++, along with ``cmake`` and ``make``:

    ::

        sudo apt-get update
        sudo apt-get install clang-18 cmake make

    You may also need to install OpenMP:

    ::

        sudo apt-get install libomp-18-dev

    Then configure Clang 18 as the C and C++ compilers:

    ::

        export CC=/usr/bin/clang-18
        export CXX=/usr/bin/clang++-18

2. Clone the repo.

3. Create a directory where the binaries will be built. The typical choice is a subfolder "build". In this case, the commands are:

    ::

        mkdir build
        cd build
        cmake ..


.. note:: Note that cmake will check for any system dependencies that are needed for the build process.


4. The OpenFHE distribution includes some external libraries, such as ``GMP``, ``NTL`` and ``tcmalloc``. If you want to use any of these libraries:
    a) install ``autoconf``:

    ::

        sudo apt-get install autoconf

    b) enable them when you run cmake to force them to build (see instructions on cmake options).

5. Build OpenFHE by running the following command (this will take few minutes; using the ``-j <threads>`` command-line flag is suggested to speed up the build)

    ::

        make

6. Install OpenFHE in a system directory (if desired or for production purposes)

    ::

        make install

You would probably need to run "sudo make install" unless you are specifying some other install location. You can change the install location by running
``cmake -DCMAKE_INSTALL_PREFIX=/your/path ..``

Testing and cleaning the build
------------------------------

Run unit tests to make sure all capabilities operate as expected

    ::

        make testall

Run sample code to test, e.g.,

    ::

        bin/examples/pke/simple-integers

To remove the files built by make, you can execute

    ::

        make clean

To change the compiler, e.g., from g++ to clang++, or completely remove any cmake/make build files, delete the "build" folder and recreate it.
