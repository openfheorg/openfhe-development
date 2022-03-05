#!/bin/bash
# 
# This script can be used to install all of the requistes for the Linux Platform
# 
# https://github.com/openfheorg/openfhe-development/wiki/Instructions-for-building-OpenFHE-in-Linux

# update
sudo apt-get update

# install cmake
sudo apt-get install -y cmake=3.16.3-1ubuntu1

# install required packages
sudo apt-get install -y build-essential
sudo apt-get install -y autoconf
sudo apt-get install -y libntl-dev
sudo apt-get install -y libgmp-dev
sudo apt-get install -y libtool

# install clang
sudo apt-get install -y clang-10 

# Install optional extra compilers for manual pipeline
sudo apt-get install -y g++-11 g++-10 clang-9 clang-11

# for documentation
sudo apt-get install doxygen -y
sudo apt-get install graphviz -y