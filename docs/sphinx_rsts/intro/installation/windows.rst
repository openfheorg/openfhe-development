Installing OpenFHE on Windows
====================================
The preferred way of building OpenFHE in Windows is using MinGW64. VC++ is no longer supported.

Download and install `MSYS2 <http://www.msys2.org/>`__ using default settings. Start the MSYS2 MINGW 64-bit shell and execute the following command

::

    pacman -Syu

to update all packages (you may need to run it twice as it often fails the first time; just reopen the console and reenter the command. This may also happen for the other installs below).

1. Run the following commands to install all pre-requisites

::

    pacman -S mingw-w64-x86_64-gcc
    pacman -S mingw-w64-x86_64-cmake
    pacman -S make
    pacman -S git

2. Clone the repo.

3. Create a directory where the binaries will be built. The typical choice is a subfolder ``build``. In this case, the commands are:

::

    mkdir build
    cd build
    cmake ..

Note that cmake will check for any system dependencies that are needed for the build process.

4. The OpenFHE distribution includes some external libraries, such as ``GMP`` and ``NTL``. If you want to use any of these libraries:

    a) install ``autoconf``:

    ::

        pacman -S autoconf

    b) enable them when you run cmake to force them to build (see instructions on cmake options).

5. Build OpenFHE by running the following command (this will take few minutes; using the ``-j <threads>`` make command-line flag is suggested to speed up the build where threads is typically the number of cores or threads on your machine)

::

    make

6. Install OpenFHE in a system directory (if desired or for production purposes)

::

    make install

You need to run MinGW64 as an administrator unless you are specifying some other install location. You can change the install location by running
``cmake -DCMAKE_INSTALL_PREFIX=/your/path ..``

To run MinGW64 as an administrator, open Task Manager, go to File -> Run New Task, select the location of the executable for MinGW64, and check the box "Create this task with administrative privileges".

8. Add the following paths to the ``PATH`` variable (to find the dlls): ``lib`` (no NTL) or ``lib:third-party/bin`` (with NTL). For example, the following commands can be used

Without NTL:

::

    export PATH=$PATH:lib

With NTL:

::

    export PATH=$PATH:lib:{PATH_TO_NTL_BINARIES}

Alternatively, add the path(s) to ``ORIGINAL_PATH`` variable in ``c:/msys64/etc/profile`` to make this change permanent.

Testing and cleaning the build
-------------------------------

Run unit tests to make sure all capabilities operate as expected

::

    make testall

Run sample code to test, e.g.,

::

    bin/examples/pke/simple-integers

To remove the files built by make, you can execute

::

    make clean
