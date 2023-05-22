#!/bin/bash
# 
# This script is meant to uninstall OpenFHE installed on a Linux, Mac, or MinGW distribution.
# 
# NOTE - the bash expansion is a little convoluted, here's a better explanation for those interested
# 
# > _inc=$(cat install_manifest.txt|grep "/include/openfhe" | head -n 1)
# 
# Results in something like `/usr/local/include/openfhe/core/config_core.h` but the file maybe different over time
# What this does is finds all the lines containing "/include/openfhe" and then selects only the first result
# 
# > ${_inc%openfhe*}openfhe
# 
# Results in /usr/local/include/openfhe
# This will trim everything, including "openfhe" for the string, thus "openfhe" must be concatenated back onto the
# remainder.
# ---------------------------------------------------------------------------------------------------------------------

function uninstall_unix() {
    sudo xargs rm -vf < install_manifest.txt || echo Nothing in install_manifest.txt to be uninstalled!

    # Parse out the include directory's full path from install_manifest.txt's by using bash parameter expansion
    _inc=$(cat install_manifest.txt|grep "/include/openfhe" | head -n 1)
    match="${_inc%openfhe*}openfhe"
    echo "Removing: ${match}"
    sudo rm -vr "${match}"

    # Parse out the include directory's full path from install_manifest.txt's by using bash parameter expansion
    _lib=$(cat install_manifest.txt|grep "/lib/OpenFHE" | head -n 1)
    match="${_lib%OpenFHE*}"
    echo "Removing: ${match}"
    sudo rm -vr "${match}"

    unset _inc _lib
}


function uninstall_mingw() {
    echo "WARNING - Running uninstall on MinGW requires admin priviledges"

    # Parse out the include directory's full path from install_manifest.txt's by using bash parameter expansion
    _inc=$(cat install_manifest.txt|grep "/include/openfhe" | head -n 1)
    match="${_inc%openfhe*}"
    echo "Removing: ${match}"
    rm -vr "${match}"

    # Parse out the include directory's full path from install_manifest.txt's by using bash parameter expansion
    _lib=$(cat install_manifest.txt|grep "OpenFHElib" | head -n 1)
    match=${_lib%lib/libOpenFHE*}lib/
    echo "Removing: ${match}"
    rm -vr "${match}"
    
    # Parse out the include directory's full path from install_manifest.txt's by using bash parameter expansion
    _cmake=$(cat install_manifest.txt|grep "CMake/OpenFHE" | head -n 1)
    match="${_cmake%OpenFHE*}"
    echo "Removing: ${match}"
    rm -vr "${match}"

    echo "Be sure to cleanup your env PATH"

    unset match _inc _lib _cmake
}

# Need to check if sudo exists, on mingw sudo is not a valid command, and the user needs
# to run this in a mingw terminal with admin priviledges
osname=$(uname -s)
if [[ "$osname" -eq "Linux" ]] || [[ "$osname" -eq "Darwin" ]]; then
    uninstall_unix    
else # mingw differs over versions
    uninstall_mingw
fi

unset osname