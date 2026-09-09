#!/bin/bash
# 
# This script is meant to uninstall OpenFHE installed on a Linux, Mac, or MinGW distribution.
# 
# NOTE - openfhe_remove_manifest_files below deletes every file listed in install_manifest.txt.
# The manifest lists files only, never directories, so the two directories OpenFHE creates for
# itself have to be derived from it and removed separately:
#
#   - the header tree,       <includedir>/openfhe
#   - the CMake package dir, <libdir>/OpenFHE (or <prefix>/CMake on Windows)
#
# Neither location can be assumed: they follow CMAKE_INSTALL_INCLUDEDIR and CMAKE_INSTALL_LIBDIR,
# so the library directory may be lib, lib64 or lib/<arch-triplet>. Both are therefore derived by
# locating a file that OpenFHE is known to install and stripping that file's known trailing path,
# which leaves the directory to remove no matter how the prefix is laid out.
#
# Searching for a path component instead would not be safe: a component such as "/OpenFHE" can
# also occur inside the install prefix (-DCMAKE_INSTALL_PREFIX=$HOME/OpenFHE), and cutting there
# names a directory far above the install tree.
#
# The two are then removed differently, because only one of them is certainly ours:
#
#   - <includedir>/openfhe is CMAKE_INSTALL_INCLUDEDIR plus a hardcoded "openfhe" component, so
#     no setting can aim it at a directory another package shares. It is taken with everything
#     below it, which also clears headers an earlier install left behind.
#
#   - the CMake package directory is INSTALL_CMAKE_DIR verbatim, which the user chooses freely
#     and which find_package is happy to locate in a shared directory: -DINSTALL_CMAKE_DIR=cmake,
#     or "." for the install prefix itself, are both working layouts. Removing that recursively
#     would take unrelated packages - or the entire prefix - with it, so only the directories the
#     manifest has already emptied are pruned and anything else found there is left alone.
#
# The enclosing <includedir>, <libdir> and <bindir> are deliberately left in place: they are
# shared with other packages, and their OpenFHE contents are already gone with the manifest.
# ---------------------------------------------------------------------------------------------------------------------

# install_manifest.txt is newline-separated and its entries may contain spaces (a Windows
# install under "C:\Program Files\..." for one), so it has to be read a line at a time. "xargs"
# cannot be used: it splits on spaces as well as newlines, and with "rm -f" the resulting
# failures are silent, leaving those files installed. A trailing CR is stripped in case the
# manifest was written with CRLF line endings.
function openfhe_manifest_line() {
    local line
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%$'\r'}"
        [[ -n "${line}" ]] && printf '%s\n' "${line}"
    done
}

function openfhe_remove_manifest_files() {
    local line count=0
    while IFS= read -r line; do
        rm -vf -- "${line}"
        count=$((count + 1))
    done < <(openfhe_manifest_line < install_manifest.txt)
    echo "Removed ${count} file(s) listed in install_manifest.txt"
}

# Print the directory holding the first manifest entry that ends in $1, with $1 stripped off.
# Prints nothing when the manifest has no such entry or the directory is already gone.
function openfhe_dir_of() {
    local suffix="$1"
    local line match
    while IFS= read -r line; do
        if [[ "${line}" == *"${suffix}" ]]; then
            match="${line%"${suffix}"}"
            break
        fi
    done < <(openfhe_manifest_line < install_manifest.txt)

    if [[ -n "${match}" && -d "${match}" ]]; then
        printf '%s\n' "${match}"
    fi
}

# Remove that directory and everything below it. Only for a directory OpenFHE owns outright.
function openfhe_remove_dir_of() {
    local match
    match="$(openfhe_dir_of "$1")"
    if [[ -n "${match}" ]]; then
        echo "Removing: ${match}"
        rm -vr -- "${match}"
    else
        echo "Nothing to remove for *$1"
    fi
}

# Remove that directory only as far as it is empty, for a directory that may be shared with other
# packages. -depth visits children first, so nested directories the manifest emptied go before
# their parents; rmdir refuses the rest, and its complaints about them are the expected case.
function openfhe_prune_dir_of() {
    local match
    match="$(openfhe_dir_of "$1")"
    if [[ -z "${match}" ]]; then
        echo "Nothing to remove for *$1"
        return
    fi

    echo "Pruning: ${match}"
    find "${match}" -depth -type d -exec rmdir -- {} + 2>/dev/null
    if [[ -d "${match}" ]]; then
        echo "Kept: ${match} still holds files this install did not put there"
    fi
}

# config_core.h is installed as <includedir>/openfhe/core/config_core.h, and OpenFHEConfig.cmake
# sits directly in the CMake package directory.
function openfhe_remove_dirs() {
    openfhe_remove_dir_of "/core/config_core.h"
    openfhe_prune_dir_of "/OpenFHEConfig.cmake"
}

function uninstall_unix() {
    openfhe_remove_manifest_files
    openfhe_remove_dirs
}


function uninstall_mingw() {
    echo "WARNING - Running uninstall on MinGW requires admin priviledges"

    # Delete the installed files first. This branch used to remove whole directories instead,
    # which relied on the import libraries and the DLLs sharing one directory; the DLLs now go
    # to CMAKE_INSTALL_BINDIR, so go by the manifest as the unix branch does.
    openfhe_remove_manifest_files
    openfhe_remove_dirs

    echo "Be sure to cleanup your env PATH"
}

# Everything below reads install_manifest.txt, so stop here if there is nothing to act on. This
# script runs with root privileges and deletes directories, so bail out rather than continue with
# paths derived from a manifest that could not be read.
if [[ ! -s install_manifest.txt ]]; then
    echo "Nothing in install_manifest.txt to be uninstalled!"
    echo "Run this from the build directory that was used for 'make install'."
    exit 0
fi

# On MinGW sudo is not a valid command, and the user needs to run this in a mingw terminal with
# admin priviledges. Match the Windows-like environments explicitly rather than testing for
# Linux/Darwin, so that any other unix (FreeBSD, SunOS, ...) takes the unix path. Note that the
# previous form, [[ "$osname" -eq "Linux" ]], compared the strings numerically: -eq evaluates
# both sides as arithmetic, where an undefined name such as Linux is 0, so it matched anything
# that also evaluated to 0 and raised an arithmetic syntax error on the rest.
osname=$(uname -s)
case "${osname}" in
    MINGW*|MSYS*|CYGWIN*) uninstall_mingw ;;
    *)                    uninstall_unix ;;
esac

unset osname
