# Documentation

- contains all the assets and files for building our documentation. Refer to the folder structure below

## Building the documentation

### Requirements:

- doxygen
- sphinx

#### Building Doxygen

```bash
# At the top-level
mkdir build
cd build
cmake ..
make Doxygen  # the files can now be accessed at build/docs/doxygen/html/index.html
```

#### Building Sphinx

```bash
# At the top-level
mkdir build
cd build
cmake ..
make Sphinx 2> sphinx_warnings.txt # the files can now be accessed at  build/docs/sphinx/index.html
```

## Folders

[assets](assets) - styling, images, etc.

[static docs](static_docs) - static markdown files. Used primarily for doxygen and markdown-rendered readmes.