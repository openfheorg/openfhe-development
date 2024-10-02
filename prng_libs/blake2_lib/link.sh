#!/bin/sh

# set -x

g++ -fPIC -shared -o libblake2.so -I./include -I../ ./lib/*.c ./lib/*.cpp

