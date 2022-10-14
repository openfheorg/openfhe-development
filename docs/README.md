# Documentation

This README details the documentation present in the OpenFHE library. We support both `Doxygen` and `Sphinx` builds, but highly recommend using `Sphinx` as, in addition to code, we also provide in-depth information.

In this readme we detail:

1. [The requirements to build the documentation](#Requirements)
2. [Steps to build the documentation](#Building-The-Documentation) for both `Sphinx` and `Doxygen`
3. [Debugging the documentation build](#Debugging)

## Requirements

- doxygen
- sphinx
- packages mentioned in `requirements.txt`
  - We recommend using `conda` or `venv` to set up a virtual environment in the process.


## Building The Documentation

### Building Doxygen

```bash
# At the top-level
mkdir build
cd build
cmake ..
make Doxygen  # the files can now be accessed at build/docs/doxygen/html/index.html
```

### Building via `exhale`

```bash
# In this directory
make clean  # Assuming you've got a previous build
make html
```
This will generate documentation within this directory. You can then access this documentation by opening up []()
