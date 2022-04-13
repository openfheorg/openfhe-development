# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))
import subprocess

# -- Project information -----------------------------------------------------
from typing import Union

project = 'OpenFHE'
copyright = '2022, OpenFHE'
author = 'OpenFHE'
MODULE_LIST = ["pke", "core", "binfhe"]
import subprocess, os

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.mathjax',
    'sphinx.ext.viewcode',
    'sphinx.ext.imgmath',
    'sphinx.ext.duration',
    'sphinx.ext.todo',
    'breathe',
    'sphinxcontrib.mermaid'
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['assets/sphinx_builds/_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['assets/sphinx_builds/_static']

# -- Breathe ---------------------------------------------------

breathe_default_project = "OpenFHE"
breathe_default_members = ('members', 'undoc-members', "private-members")
breathe_implementation_filename_extensions = ['.c', '.cc', '.cpp']

##############################################################################3
# Generate the breathe_sources
accumulator = []

def scan_dir(prefix, append_print, fixed):

    fmt_path = lambda a: a
    files = []
    horizon = []
    all_files = []
    for el in os.listdir(prefix):
        all_files.append(el)
        if el.endswith(".h"):
            files.append(el)
        elif os.path.isdir(prefix + "/" + el):
            horizon.append(el)

    accumulator.append((append_print, fmt_path(prefix), files))

    for el in horizon:
        scan_dir(prefix + f"/{el}", append_print + f"_{el}", fixed)

# Location of the modules
for module in MODULE_LIST:
    scan_dir(f"../src/{module}/include", module, module)

breathe_projects_source = {k: (v1, v2) for (k, v1, v2) in accumulator}

##############################################################################3

breathe_domain_by_extension = {
    "h": "cpp",
}
breathe_show_include = False


########################################
# Read the docs deployment
########################################

def configureDoxyfile(
        code_input_dir: str,
        output_dir: str,
        main_page: str,
        openfhe_version: Union[int, str],
        styling_sheet_name: str
):
    """

    :param code_input_dir:
        our `src` directory path i.e where all the code lives
    :param output_dir:
        where to dump the XML and HTML files that were produced
    :param main_page:
        our main README.md landing page. Only relevant for pure-Doxygen builds
    :param openfhe_version:
        project number
    :param styling_sheet_name:
    :return:
    """
    with open('Doxyfile.in', 'r') as file:
        filedata = file.read()

    filedata = filedata.replace('@CODE_INPUT_DIR@', code_input_dir)
    filedata = filedata.replace('@MAIN_PAGE@', main_page)
    filedata = filedata.replace('@DOXYGEN_OUTPUT_DIR@', output_dir)
    filedata = filedata.replace('@OPENFHE_VERSION@', str(openfhe_version))
    filedata = filedata.replace('@STYLING@', styling_sheet_name)

    with open('Doxyfile', 'w') as file:
        file.write(filedata)


import re


def read_version_number(pth="../CMakeLists.txt"):
    version = {"major": -1, "minor": -1, "patch": -1}
    with open(pth, "r") as f:
        data = f.readlines()

    matcher = re.compile("set\(OPENFHE_VERSION_([a-zA-Z]+) (\d+)\)")
    for ln in data:
        result = matcher.match(ln)

        if result:
            mode = result.group(1)  # Major, minor, patch
            version[mode.lower()] = result.group(2)  # The numeric

    assert -1 not in version.values()
    return f"{version['major']}.{version['minor']}.{version['patch']}"


# Check if we're running on Read the Docs' servers
read_the_docs_build = os.environ.get('READTHEDOCS', None) == 'True'

breathe_projects = {}

if read_the_docs_build:
    """According to:
    https://devblogs.microsoft.com/cppblog/clear-functional-c-documentation-with-sphinx-breathe-doxygen-cmake/
    
    we need to hardcode the paths....
    """
    input_dir = '../src'
    output_dir = '../build/doxygen'
    main_page = "../README.md"
    project_number = read_version_number()
    style_sheet = "./assets/doxygen-style/doxygen-awesome.css"
    configureDoxyfile(input_dir, output_dir, main_page, project_number, style_sheet)
    subprocess.call('doxygen', shell=True)
    # breathe_projects['OpenFHE'] = output_dir + '/xml'
