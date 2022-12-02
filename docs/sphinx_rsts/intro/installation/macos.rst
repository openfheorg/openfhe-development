Installing OpenFHE on MacOS
====================================
These instructions were tested in macOS Mojave but should also work for other recent releases. It is assumed that the clang compiler that comes with Xcode is used for building OpenFHE.

1. Install the Mac terminal command line functions if needed (type ``git`` at the command line to trigger the install). Then install home-brew if not already present:

::

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"

2. Install pre-requisites ``cmake`` and ``OpenMP`` library using Homebrew:

::

    brew install cmake
    brew install libomp

3. Clone the repo.

4. Create a directory where the binaries will be built. The typical choice is a subfolder ``build``.

::

    mkdir build
    cd build

Cmake will check for any system dependencies that are needed for the build process. Note there are issues with some versions of clang/OMP and regular expressions that may cause cmake to fail.  The general fix is to run cmake twice. There are two distinct cases.

::

    cmake ..

.. note:: If you get an error about a missing regular expression backend, run the following commands

    ::

        cmake -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0 ..
        cmake ..

  If you get an error about OMP asking to rerun cmake, just run "cmake .." once more.

5. The OpenFHE distribution includes some external libraries, such as ``GMP``, ``NTL`` and ``tcmalloc``. If you want to use any of these libraries:
    a) install ``autoconf`` using Homebrew:

    ::

        brew install autoconf

    b) enable them when you run cmake to force them to build (see instructions on cmake options)

6. Build OpenFHE by running the following command (this will take few minutes; using the ``-j #`` make command-line flag is suggested to speed up the build, where # is the number of cores on your machine).

::

    make

7. Install OpenFHE in a system directory (if desired or for production purposes)

::

    make install

You would probably need to run ``sudo make install`` unless you are specifying some other install location. You can change the install location by running
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
