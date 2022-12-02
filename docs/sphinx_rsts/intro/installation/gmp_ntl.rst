.. _gmp_ntl_install:

Instructions for installing GMP and NTL
=======================================

This section describes how to install GMP and NTL onto your system, and how to use them in OpenFHE. Install ``autoconf`` if it is not already present:
.. topic:: on Linux

::

    sudo apt-get install autoconf

.. topic:: on MacOS

::

    brew install autoconf

.. topic:: on Windows

::

    pacman -S autoconf


.. note:: scroll to the bottom for an all-in-one install script

The standard binary install using tools like ``apt-get`` will not work, and manual installation of GMP and NTL from the source code is needed. The steps are detailed below.

Installing GMP and NTL for OpenFHE:

1. First, download gmp-6.1.2.tar.lz from https://ftp.gnu.org/gnu/gmp/

::

    wget https://ftp.gnu.org/gnu/gmp/gmp-6.1.2.tar.lz

2. Unpack:

::

    tar --lzip -xvf gmp-6.1.2.tar.lz

.. note:: You may need to install lzip
   - Debian based systems:``sudo apt-get install lzip``

3. Build and install `GMP <https://gmplib.org/manual/Installing-GMP>`_ (installed in /usr/local/lib by default):



.. code-block:: bash
    :linenos:

    cd ./gmp-6.1.2
    ./configure
    make
    make check
    sudo make install

4. Download ntl-10.5.0.tar.gz from http://www.shoup.net/ntl/download.html

::

    wget https://libntl.org/ntl-10.5.0.tar.gz

5. Unpack:

::

    tar -xvf ntl-10.5.0.tar.gz

6. Build and install NTL (https://libntl.org/doc/tour-unix.html) (in /usr/local/lib by default):

::

    cd ./ntl-10.5.0/src
    ./configure NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off TUNE=generic
    make
    make check
    sudo make install


GMP AND NTL INSTALL
----------------------

GMP
^^^

.. code-block:: bash
    :linenos:

    curl -O https://ftp.gnu.org/gnu/gmp/gmp-6.1.2.tar.lz
    tar --lzip -xvf gmp-6.1.2.tar.lz
    ( \
      cd ./gmp-6.1.2 || exit; \
      ./configure; \
      make; \
      make check; \
      sudo make install; \
      cd ..; \
    )

    rm gmp-6.1.2.tar.lz
    rm -rf gmp-6.1.2


NTL
^^^


.. code-block:: bash
    :linenos:

    curl -O https://libntl.org/ntl-10.5.0.tar.gz
    tar -xvf ntl-10.5.0.tar.gz
    ( \
      cd ./ntl-10.5.0/src || exit; \
      ./configure NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off TUNE=generic; \
      make; \
      make check; \
      sudo make install; \
      cd ../.. \
    )

    rm ntl-10.5.0.tar.gz
    rm -rf ntl-10.5.0
