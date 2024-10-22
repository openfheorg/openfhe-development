Pseudorandom Number Generator (PRNG)
=====================================

Documentation for `core/include/utils/prng <https://github.com/openfheorg/openfhe-development/tree/main/src/core/include/utils/prng>`_. Additionally, we refer users to :ref:`our sampling documentation<sampling>`

.. contents:: Page Contents
   :local:
   :backlinks: none

Implemented PRNG hash function
-------------------------------

- Our cryptographic hash function is based off of `Blake2b <https://blake2.net>`_, which allows fast hashing.

Building and testing external PRNG engine (existing example)
-------------------------------------------------------------

External PRNG engines are an experimental feature currently available only on Linux, and g++ is the required compiler for linking them.

There is `an external blake2 PRNG <https://github.com/openfheorg/openfhe-prng-blake2>`_ that you can test and use as an example to build your own one.

.. note:: Installation and Testing of External PRNG on Ubuntu

1. Build OpenFHE 1.2.2+ by following `these instructions <https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/linux.html>`_ and set g++ as the default compiler.

2. Clone `the external PRNG repo <https://github.com/openfheorg/openfhe-prng-blake2>`_ and ``cd`` to it. All required pre-requisites for the next steps should have been installed in the previous directive.

3. Create a directory where the binaries will be built. The typical choice is a subfolder "build". In this case, the commands are:
   ::
      mkdir build
      cd build
      cmake ..
      make

4. Optionally install the built shared object ``libPRNGengine.so``:
   - if you chose the default location: ``sudo make install``
   - if you provided an install location (by running ``cmake -DCMAKE_INSTALL_PREFIX=/your/path``): ``make install``
   
5. Run an example from the OpenFHE ./build directory (without arguments): ``./bin/examples/core/external-prng``. It calls PseudoRandomNumberGenerator::InitPRNGEngine() which initializes PRNG either with the built-in engine or a custom one.
   Without arguments it should producegets the path toib/libPRNGengine.so``. In this case PseudoRandomNumberGenerator::InitPRNGEngine() initializes PRNG with the custom engine.
   It should produce
   ::
   ==== Using external PRNG
   InitPRNGEngine: using external PRNG


Creating custom external PRNG engine using the existing example
----------------------------------------------------------------

You can create your own PRNG engine and use it with OpenFHE follwing the steps below:

1. Create a separate repo for your own engine and copy everything from `the example <https://github.com/openfheorg/openfhe-prng-blake2>`_ to the new repo.

2. Change CMakeLists.txt: replace "PRNGengine" (LIBRARY_NAME) with the name of your choice.

3. Delete all source files from src/include and src/lib except:
::
src/prng.h
src/include/blake2engine.h
src/lib/blake2engine.cpp

4. Create a new class similar to Blake2Engine (use the code in blake2engine.h/blake2engine.cpp as an example), following the requirements below:
- the class PRNG defined in prng.h must be used as the base class for the new class. the file prng.h is not allowed to be changed.
- only two public member functions should be in the new class: a trivial constructor with 2 input parameters (seed array and counter) and operator() providing similar functionality as Blake2Engine does, which is generating numbers.
- create extern "C" function "createEngineInstance" returning a dynamically allocated object of the new class. OpenFHE finds this function by name using dlsym(), so you may not change the name.

5. Follow the instructions above to build and test your new PRNG