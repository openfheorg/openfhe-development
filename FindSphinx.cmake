#Look for an executable called sphinx-build
find_program(SPHINX_EXECUTABLE
        NAMES sphinx-build
        DOC "Path to sphinx-build executable")


include(FindPackageHandleStandardArgs)
# We need to "patch" this in so that it maintains parity with the apidocs in the
# doxygen side of things
find_package_handle_standard_args(Sphinx
        "Failed to find sphinx-build executable"
        SPHINX_EXECUTABLE)