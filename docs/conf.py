# -*- coding: utf-8 -*-
#
# NanoGUI documentation build configuration file, created by
# sphinx-quickstart on Mon Aug 22 20:05:54 2016.
#
# This file is execfile()d with the current directory set to its
# containing dir.
#
# Note that not all possible configuration values are present in this
# autogenerated file.
#
# All configuration values have a default; values that are commented out
# serve to show the default.

import sys
import os
import shlex
import textwrap

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
# sys.path.insert(0, os.path.abspath('.'))

# -- General configuration ------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
# [[[ begin extensions marker ]]]
# Tell Sphinx to use both the `breathe` and `exhale` extensions
extensions = [
    'breathe',
    'exhale'
]

# Setup the `breathe` extension
breathe_projects = { "ExhaleCompanion": "./doxyoutput/xml" }
breathe_default_project = "ExhaleCompanion"

# Setup the `exhale` extension
import textwrap

__exhale_base = "../src"
__exhale_path = {
    # Binfhe
    # f"{__exhale_base}/binfhe/include",
    # f"{__exhale_base}/binfhe/lib",
    # # Core
    # f"{__exhale_base}/core/extras",
    f"{__exhale_base}/core/include",
    # f"{__exhale_base}/core/lib",
    # # PKE
    # f"{__exhale_base}/pke/extras",
    # f"{__exhale_base}/pke/include",
    # f"{__exhale_base}/pke/lib",
}

container = "INPUT = "
for path in __exhale_path:
    container += f"{path} "

exhale_args = {
    ############################################################################
    # These arguments are required.                                            #
    ############################################################################
    "containmentFolder":     "./api",
    "rootFileName":          "library_root.rst",
    "rootFileTitle":         "Library API",
    "doxygenStripFromPath":  f"{__exhale_base}",
    ############################################################################
    # Suggested optional arguments.                                            #
    ############################################################################
    "createTreeView":        True,
    "exhaleExecutesDoxygen": True,
    "exhaleDoxygenStdin": textwrap.dedent(container + '''
        # For this code-base, the following helps Doxygen get past a macro
        # that it has trouble with.  It is only meaningful for this code,
        # not for yours.
        PREDEFINED += NAMESPACE_BEGIN(arbitrary)="namespace arbitrary {"
        PREDEFINED += NAMESPACE_END(arbitrary)="}"
    '''),
    ############################################################################
    # HTML Theme specific configurations.                                      #
    ############################################################################
    # Fix broken Sphinx RTD Theme 'Edit on GitHub' links
    # Search for 'Edit on GitHub' on the FAQ:
    #     http://exhale.readthedocs.io/en/latest/faq.html
    "pageLevelConfigMeta": ":github_url: https://github.com/svenevs/exhale-companion",
    ############################################################################
    # Main library page layout example configuration.                          #
    ############################################################################
    "afterTitleDescription": textwrap.dedent(u'''
        Welcome to the developer reference to Exhale Companion.  The code being
        documented here is largely meaningless and was only created to test
        various corner cases e.g. nested namespaces and the like.

        .. note::

            The text you are currently reading was fed to ``exhale_args`` using
            the :py:data:`~exhale.configs.afterTitleDescription` key.  Full
            reStructuredText syntax can be used.

        .. tip::

           Sphinx / Exhale support unicode!  You're ``conf.py`` already has
           it's encoding declared as ``# -*- coding: utf-8 -*-`` **by
           default**.  If you want to pass Unicode strings into Exhale, simply
           prefix them with a ``u`` e.g. ``u"👽😱💥"`` (of course you would
           actually do this because you are writing with åçćëñtß or
           non-English 寫作 😉).
    '''),
    "afterHierarchyDescription": textwrap.dedent('''
        Below the hierarchies comes the full API listing.

        1. The text you are currently reading is provided by
           :py:data:`~exhale.configs.afterHierarchyDescription`.
        2. The Title of the next section *just below this* normally defaults to
           ``Full API``, but the title was changed by providing an argument to
           :py:data:`~exhale.configs.fullApiSubSectionTitle`.
        3. You can control the number of bullet points for each linked item on
           the remainder of the page using
           :py:data:`~exhale.configs.fullToctreeMaxDepth`.
    '''),
    "fullApiSubSectionTitle": "Custom Full API SubSection Title",
    "afterBodySummary": textwrap.dedent('''
        You read all the way to the bottom?!  This text is specified by giving
        an argument to :py:data:`~exhale.configs.afterBodySummary`.  As the docs
        state, this summary gets put in after a **lot** of information.  It's
        available for you to use if you want it, but from a design perspective
        it's rather unlikely any of your users will even see this text.
    '''),
    ############################################################################
    # Individual page layout example configuration.                            #
    ############################################################################
    # Example of adding contents directives on custom kinds with custom title
    "contentsTitle": "Page Contents",
    "kindsWithContentsDirectives": ["class", "file", "namespace", "struct"],
    # This is a testing site which is why I'm adding this
    "includeTemplateParamOrderList": True,
    ############################################################################
    # useful to see ;)
    "verboseBuild": True
}

# Tell sphinx what the primary language being documented is.
primary_domain = 'cpp'

# Tell sphinx what the pygments highlight language should be.
highlight_language = 'cpp'
# [[[ end extensions marker ]]]

# Hiding this from the main docs for no real reason other than to hopefully
# avoid people thinking they need it
extensions.append('sphinx.ext.intersphinx')
intersphinx_mapping = {
    'exhale':  ('https://exhale.readthedocs.io/en/latest/', None),
    'nanogui': ('http://nanogui.readthedocs.io/en/latest/', None)
}

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
# source_suffix = ['.rst', '.md']
source_suffix = '.rst'

# The encoding of source files.
#source_encoding = 'utf-8-sig'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = u'ExhaleCompanion'
copyright = u'2017, Stephen McDowell'
author = u'Stephen McDowell'

# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.
#
# The short X.Y version.
import exhale
# NOTE: this is the companion site for Exhale, which is why I'm setting the
#       version to be the same.  For your own projects, you would NOT do this!
version = exhale.__version__
# The full version, including alpha/beta/rc tags.
release = exhale.__version__

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = None

# There are two options for replacing |today|: either, you set today to some
# non-false value, then it is used:
#today = ''
# Else, today_fmt is used as the format for a strftime call.
#today_fmt = '%B %d, %Y'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build']

# The reST default role (used for this markup: `text`) to use for all
# documents.
#default_role = None

# If true, '()' will be appended to :func: etc. cross-reference text.
#add_function_parentheses = True

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
#add_module_names = True

# If true, sectionauthor and moduleauthor directives will be shown in the
# output. They are ignored by default.
#show_authors = False

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# A list of ignored prefixes for module index sorting.
#modindex_common_prefix = []

# If true, keep warnings as "system message" paragraphs in the built documents.
#keep_warnings = False

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = False

# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
# [[[ begin theme marker ]]]
# The name of the Pygments (syntax highlighting) style to use.
# `sphinx` works very well with the RTD theme, but you can always change it
pygments_style = 'sphinx'

# on_rtd is whether we are on readthedocs.org, this line of code grabbed from docs.readthedocs.org
on_rtd = os.environ.get('READTHEDOCS', None) == 'True'

if not on_rtd:  # only import and set the theme if we're building docs locally
    import sphinx_rtd_theme
    html_theme = 'sphinx_rtd_theme'
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
# [[[ end theme marker ]]]

# NOTE: this is only here for me to auto-place sections of conf.py in the docs
#       but isn't needed in producion releases
html_theme = 'sphinx_rtd_theme'

# The name for this set of Sphinx documents.  If None, it defaults to
# "<project> v<release> documentation".
#html_title = None

# A shorter title for the navigation bar.  Default is the same as html_title.
#html_short_title = None

# The name of an image file (relative to this directory) to place at the top
# of the sidebar.
#html_logo = None

# The name of an image file (within the static path) to use as favicon of the
# docs.  This file should be a Windows icon file (.ico) being 16x16 or 32x32
# pixels large.
#html_favicon = None

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
# html_static_path = ['_static']

# Add any extra paths that contain custom files (such as robots.txt or
# .htaccess) here, relative to this directory. These files are copied
# directly to the root of the documentation.
#html_extra_path = []

# If not '', a 'Last updated on:' timestamp is inserted at every page bottom,
# using the given strftime format.
#html_last_updated_fmt = '%b %d, %Y'

# If true, SmartyPants will be used to convert quotes and dashes to
# typographically correct entities.
#html_use_smartypants = True

# Custom sidebar templates, maps document names to template names.
#html_sidebars = {}

# Additional templates that should be rendered to pages, maps page names to
# template names.
#html_additional_pages = {}

# If false, no module index is generated.
#html_domain_indices = True

# If false, no index is generated.
#html_use_index = True

# If true, the index is split into individual pages for each letter.
#html_split_index = False

# If true, links to the reST sources are added to the pages.
#html_show_sourcelink = True

# If true, "Created using Sphinx" is shown in the HTML footer. Default is True.
#html_show_sphinx = True

# If true, "(C) Copyright ..." is shown in the HTML footer. Default is True.
#html_show_copyright = True

# If true, an OpenSearch description file will be output, and all pages will
# contain a <link> tag referring to it.  The value of this option must be the
# base URL from which the finished HTML is served.
#html_use_opensearch = ''

# This is the file name suffix for HTML files (e.g. ".xhtml").
#html_file_suffix = None

# Language to be used for generating the HTML full-text search index.
# Sphinx supports the following languages:
#   'da', 'de', 'en', 'es', 'fi', 'fr', 'hu', 'it', 'ja'
#   'nl', 'no', 'pt', 'ro', 'ru', 'sv', 'tr'
#html_search_language = 'en'

# A dictionary with options for the search language support, empty by default.
# Now only 'ja' uses this config value
#html_search_options = {'type': 'default'}

# The name of a javascript file (relative to the configuration directory) that
# implements a search results scorer. If empty, the default will be used.
#html_search_scorer = 'scorer.js'

# Output file base name for HTML help builder.
htmlhelp_basename = 'ExhaleCompaniondoc'

# -- Options for LaTeX output ---------------------------------------------

latex_elements = {
# The paper size ('letterpaper' or 'a4paper').
#'papersize': 'letterpaper',

# The font size ('10pt', '11pt' or '12pt').
#'pointsize': '10pt',

# Additional stuff for the LaTeX preamble.
#'preamble': '',

# Latex figure (float) alignment
#'figure_align': 'htbp',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
  (master_doc, 'ExhaleCompanion.tex', u'ExhaleCompanion Documentation',
   u'Stephen McDowell', 'manual'),
]

# The name of an image file (relative to this directory) to place at the top of
# the title page.
#latex_logo = None

# For "manual" documents, if this is true, then toplevel headings are parts,
# not chapters.
#latex_use_parts = False

# If true, show page references after internal links.
#latex_show_pagerefs = False

# If true, show URL addresses after external links.
#latex_show_urls = False

# Documents to append as an appendix to all manuals.
#latex_appendices = []

# If false, no module index is generated.
#latex_domain_indices = True


# -- Options for manual page output ---------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (master_doc, 'exhalecompanion', u'ExhaleCompanion Documentation',
     [author], 1)
]

# If true, show URL addresses after external links.
#man_show_urls = False


# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
  (master_doc, 'ExhaleCompanion', u'ExhaleCompanion Documentation',
   author, 'ExhaleCompanion', 'One line description of project.',
   'Miscellaneous'),
]

# Documents to append as an appendix to all manuals.
#texinfo_appendices = []

# If false, no module index is generated.
#texinfo_domain_indices = True

# How to display URL addresses: 'footnote', 'no', or 'inline'.
#texinfo_show_urls = 'footnote'

# If true, do not generate a @detailmenu in the "Top" node's menu.
#texinfo_no_detailmenu = False

rst_epilog = ".. |theme| replace:: ``{0}``".format(html_theme)

# Called auto-magicallly by sphinx
def setup(app):
    # This is pretty meta.  To help demonstrate what is going on, I'm
    # generating an rst file to `.. include::` in `index.rst` to show
    # the relevant sections of `conf.py` on the page.
    #
    # That is, I love python and how convenient it is to read in files
    # even if the file being read is the one that is running xD
    begin_ext   = "# [[[ begin extensions marker ]]]"
    end_ext     = "# [[[ end extensions marker ]]]"
    begin_theme = "# [[[ begin theme marker ]]]"
    end_theme   = "# [[[ end theme marker ]]]"

    # open up `conf.py` and scan the lines for the markers
    ext_lines   = []
    theme_lines = []
    in_ext      = False
    in_theme    = False

    import codecs
    with codecs.open("conf.py", "r", "utf-8") as conf:
        for line in conf:
            # determine where we are / if we should be grabbing lines
            if line.startswith(begin_ext):
                in_ext = True
                continue
            elif line.startswith(end_ext):
                in_ext = False
                continue
            elif line.startswith(begin_theme):
                in_theme = True
                continue
            elif line.startswith(end_theme):
                # when we reach here, since ext came before theme,
                # we have everything we need
                break

            if in_ext:
                ext_lines.append(line)
            elif in_theme:
                theme_lines.append(line)

    # At this point `ext_lines` and `theme_lines` have the code we care about
    from exhale.utils import prefix
    for fname, lines in [("conf_extensions.rst", ext_lines), ("conf_theme.rst", theme_lines)]:
        with codecs.open(fname, "w", "utf-8") as file:
            file.write(".. code-block:: py\n\n")
            file.write(prefix("   ", "".join(l for l in lines)))
            file.write("\n")

    # write out the requirements used
    requirements = []
    with open("requirements.txt", "r") as req:
        for line in req:
            requirements.append(line)

    with open("the_requirements.rst", "w") as the_req:
        the_req.write(".. code-block:: nginx\n\n")
        the_req.write(prefix("   ", "".join(l for l in requirements)))
        the_req.write("\n")

