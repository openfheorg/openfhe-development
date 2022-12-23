Installing OpenFHE on Linux
====================================

.. note:: CentOS Installation

    The installation process is the same as in Ubuntu except for using ``yum`` instead of ``apt-get`` in Step 1. Here we provide additional notes specific to CentOS.

    You may need to install cmake v3.x using the following commands:

    ::

        sudo yum install cmake3
        ln -s /usr/bin/cmake3 ~/bin/cmake

    If you need to install a specific version of gcc, do the following (this example is for g++ v10):
    ``sudo yum install devtoolset-10-gcc-c++``

1. Install pre-requisites (if not already installed) and set the default compiler.

.. topic:: g++

    Note that ``sudo apt-get install g++-<version>`` can be used to install a specific version of the compiler. You can use "g++ --version" to check the version of g++ that is found by the system.


    Install ``g++``, ``cmake`` and ``make``. Sample commands using apt-get are listed below. It is possible that these are already installed

    ::

        sudo apt-get install build-essential #this already includes g++
        sudo apt-get install cmake

.. topic:: clang

    Typically g++ is the default compiler for Linux but clang++ can also be installed.

    First install clang++, e.g., ``sudo apt-get install clang-11`` to install clang 11.

    If installing an older version of clang, you may also need to install OpenMP. The commands for this case are

    ::

        sudo apt-get install clang
        sudo apt-get install libomp5
        sudo apt-get install libomp-dev


    Then run the following two commands to configure clang/clang++ as the default compiler for C and C++ (default paths are used here). For clang 11:

    ::

        export CC=/usr/bin/clang-11
        export CXX=/usr/bin/clang++-11


    For a default version of clang, e.g., v6 in Ubuntu 20.04:

    ::

        export CC=/usr/bin/clang
        export CXX=/usr/bin/clang++


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
