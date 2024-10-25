Pseudorandom Number Generator (PRNG)
=====================================
.. note:: By default, OpenFHE uses a `built-in blake2-based PRNG <https://github.com/openfheorg/openfhe-development/tree/main/src/core/include/utils/prng>`_, but provides the ability to integrate a cutom PRNG engine as a shared library. See below for instructions on how to implement and use a custom PRNG shared library.

.. contents:: Page Contents
   :local:
   :backlinks: none

Implemented PRNG hash function
-------------------------------

- The default cryptographic hash function in OpenFHE is based off of `Blake2b <https://blake2.net>`_, which allows fast hashing.

.. _for_existing_example:

Building and testing an external PRNG engine (existing example)
-------------------------------------------------------------

.. note:: Integration of an external PRNG engine is an experimental feature currently available only on Linux using the g++ compiler. We provide `an external blake2 PRNG example <https://github.com/openfheorg/openfhe-prng-blake2>`_ as a refernece. See below for instructions on how to build your own custom PRNG engine.

1. Build **OpenFHE 1.2.2+** by following `these instructions <https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/linux.html>`_ and set **g++** as the default compiler.

2. Clone `the external PRNG repo <https://github.com/openfheorg/openfhe-prng-blake2>`_.

3. Create a directory where the binaries will be built. The typical choice is a subfolder "build". In this case, the commands are:
   ::
      mkdir build
      cd build
      cmake ..
      make

4. Optionally install the shared object **libPRNGengine.so** you have just built.
   
   * for the default install location, run:
     ::
        sudo make install

   * for a custom install location you should run a different ``cmake`` command:
     ::
        cmake .. -DCMAKE_INSTALL_PREFIX=/custom/install/location

     and after that you run the remaining commands:
     ::
        make
        make install
   
5. Run `the example <https://github.com/openfheorg/openfhe-development/tree/main/src/core/examples/external-prng.cpp>`_ to test the engine. It calls PseudoRandomNumberGenerator::InitPRNGEngine() which initializes PRNG either with the built-in engine or a custom one.

   * If executed without arguments, the example calls InitPRNGEngine() which initializes PRNG with the built-in engine:
     ::
        ./build/bin/examples/core/external-prng
   
     and the output should be:
     ::
        ==== Using internal PRNG

   * If your provide the absolute path to the external PRNG as an argument to the example, then InitPRNGEngine() will use that path to initialize PRNG with the custom engine.

     For example: if you install **libPRNGengine.so** to the default location (/usr/local), then you will run:
     ::
        ./build/bin/examples/core/external-prng /usr/local/lib/libPRNGengine.so

     which should produce:
     ::
        ==== Using external PRNG
        InitPRNGEngine: using external PRNG

.. note:: If PseudoRandomNumberGenerator::InitPRNGEngine() initializes PRNG with a custom engine, it always notifies the user by producing a trace **"InitPRNGEngine: using external PRNG"**. There is no trace for the built-in PRNG engine. InitPRNGEngine() always throws an exception if it fails. 


Creating custom external PRNG engine using the existing example
----------------------------------------------------------------

You can create your own PRNG engine and use it with OpenFHE by following the steps below:

1. Create a separate repo for your own engine and copy everything from `the example of external PRNG <https://github.com/openfheorg/openfhe-prng-blake2>`_ to the new repo.

2. Change CMakeLists.txt: replace **"PRNGengine"** (LIBRARY_NAME) with the name of your choice.

3. Delete all source files from src/include and src/lib except:
   ::
      src/prng.h
      src/include/blake2engine.h
      src/lib/blake2engine.cpp

4. Create a new class similar to Blake2Engine (use the code in blake2engine.h/blake2engine.cpp as an example), following the requirements below:
   
   * the class PRNG defined in prng.h must be used as the base class for the new class. The file prng.h is not allowed to be changed.

   * rename blake2engine.h and blake2engine.cpp with the name of your engine.

   * **only two public member functions** should be in the new class: a trivial **constructor with 2 input parameters** (seed array and counter) and **operator()** providing similar functionality as Blake2Engine does, which is generating numbers.
   
   * create extern "C" function **createEngineInstance()** returning a dynamically allocated object of the new class. OpenFHE finds this function by name using dlsym(), so you may not change the name.

5. Follow `the instructions above <#for_existing_example>`_ to build and test your new PRNG.
