Building User Applications
##########################

How might you integrate OpenFHE into your projects?


OpenFHE provides a sample CMake file for building your own C++ project that links to the OpenFHE library.

The high-level instructions for building projects that use OpenFHE are as follows:

1. Build and install OpenFHE using "make install". This will copy the OpenFHE library files and header files to the directory chosen for installation.

2. Create the folder for your project on your system.

3. Copy CMakeLists.User.txt from the root directory of the git repo to the folder for your project.

4. Rename CMakeLists.User.txt to CMakeLists.txt.

5. Update CMakeLists.txt to specify the name of the executable and the source code files. For example, include the following line

::

    add_executable( fhe-demo simple-integers.cpp )

5. If using MinGW/Windows (skip this step for other platforms), copy PreLoad.cmake from the root directory of the git repo to the folder of your project.

6. Create the build directory and cd to it.

::

    mkdir build
    cd build

7. Run

::

    cmake ..

If OpenFHE is installed in a different location than the default one or you have different versions of OpenFHE installed, then you should specify the path to the desired location by running cmake with an option::

    cmake .. -DCMAKE_PREFIX_PATH=/openfhe/location/path

8. Run "make" to build the executable.

9. In order to run the executable, add the absolute path to the location of the openfhe libraries to ``PATH``::

    export PATH=$PATH:/openfhe/location/path/lib

To include a specific module, e.g., core or pke, in your C++ demo, use the main header file for that module, e.g., ``openfhecore.h`` or ``openfhe.h``. Please see the demos provided for that module for more examples. If your application uses serialization, additional header files will be needed (see the demos with serialization for more details).
