#!/bin/bash
# 
# This script can be used to install all of the requistes for the Linux Platform
# 

# run update before installing every package

# install cmake
sudo apt-get update
sudo apt-get install -y cmake

# install required packages
sudo apt-get update
sudo apt-get install -y build-essential
sudo apt-get update
sudo apt-get install -y autoconf
sudo apt-get update
sudo apt-get install -y libtool
sudo apt-get update
sudo apt-get install -y libgmp-dev
sudo apt-get update
sudo apt-get install -y libntl-dev

# install all necessary and additional compilers
sudo apt-get update
sudo apt-get install -y g++-9 g++-10 g++-11 g++-12
sudo apt-get update
sudo apt-get install -y clang-12 clang-13 clang-14 clang-15

# for documentation
sudo apt-get update
sudo apt-get install -y doxygen
sudo apt-get update
sudo apt-get install -y graphviz

# python packages
sudo apt-get update
sudo apt-get install -y python3-pip
sudo apt-get update
sudo pip install pybind11[global]
sudo apt-get update
sudo apt-get install -y python3-pytest
# to verify pytest installation: python3 -m pip show pytest