# Documentation

This README details the documentation present in the OpenFHE library. We support both `Doxygen` and `Sphinx` builds, but highly recommend using `Sphinx` as, in addition to code, we also provide in-depth information.

In this readme we detail:

1. [The requirements to build the documentation](#Requirements)
2. [Steps to build the documentation](#Building The Documentation) for both `Sphinx` and `Doxygen`
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

### Building Sphinx

```bash
# At the top-level
mkdir build
cd build
cmake ..
make Sphinx # the files can now be accessed at  build/docs/sphinx/index.html
```

## Debugging the documentation

Debugging the documentation essentially involves turning on the warnings

### Debugging Doxygen

Check the [Doxyfile](Doxyfile.in) and search for the following variables:

```
QUIET
WARN_IF_UNDOCUMENTED
WARNINGS
WARN_IF_DOC_ERROR
WARN_IF_INCOMPLETE_DOC
WARN_NO_PARAMDOC
```

which should control the output messages

### Debugging Sphinx

We use `breathe` to parse generated `XML` (from `Doxygen`) and then populate our documentation. However, it is important to note the following:

#### Using `autoX`

When using `autodoxygenfile` or `autodoxygenindex`, `breathe` will actually regenerate the `XML` values (as per [Does breathe read in Doxyfile, and does breathe use pre-generated XML files](https://github.com/michaeljones/breathe/issues/826#issuecomment-1095420873)). 

**However**, this regeneration does **not** use the flags in the `Doxyfile`, which means that the flags must be set in [conf.py](conf.py). For this, you will want to look at the

```python
breathe_doxygen_config_options = {
  "QUIET": "YES",
  "WARN_IF_UNDOCUMENTED" : "NO",
  "WARNINGS": "NO",
  "WARN_IF_DOC_ERROR": "NO",
  "WARN_IF_INCOMPLETE_DOC": "NO",
  "WARN_NO_PARAMDOC": "NO"
}
```

#### Using non-`autoX`

No special notes