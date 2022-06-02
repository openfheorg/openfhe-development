.. code-block:: py

   # Tell Sphinx to use both the `breathe` and `exhale` extensions
   
   extensions = [
       'sphinx.ext.autodoc',
       "sphinx.ext.autosectionlabel",
       "sphinx.ext.autosummary",
       'sphinx.ext.doctest',
       'sphinx.ext.duration',
       'sphinx.ext.graphviz',
       'sphinx.ext.imgmath',
       'sphinx.ext.mathjax',
       'breathe',
       'exhale',
       'sphinxcontrib.mermaid'
   ]
   
   # Setup the `breathe` extension
   breathe_projects = { "OpenFHE": "./doxyoutput/xml" }
   breathe_default_project = "OpenFHE"
   
   # Setup the `exhale` extension
   import textwrap
   
   __exhale_base = "../src"
   __exhale_path = {
       # Binfhe
       f"{__exhale_base}/binfhe/include",
       f"{__exhale_base}/binfhe/lib",
       # Core
       f"{__exhale_base}/core/extras",
       f"{__exhale_base}/core/include",
       f"{__exhale_base}/core/lib",
       # # PKE
       f"{__exhale_base}/pke/extras",
       f"{__exhale_base}/pke/include",
       f"{__exhale_base}/pke/lib",
   }
   
   container = "INPUT = "
   for path in __exhale_path:
       container += f"{path} "
   
   
   def specificationsForKind(kind):
       '''
       For a given input ``kind``, return the list of reStructuredText specifications
       for the associated Breathe directive.
       '''
       # Change the defaults for .. doxygenclass:: and .. doxygenstruct::
       if kind == "class" or kind == "struct":
           return [
             ":members:",
             ":protected-members:",
             ":undoc-members:",
             ":allow-dot-graphs:",
           ]
       # Change the defaults for .. doxygenenum::
       elif kind == "enum":
           return [":no-link:"]
       # An empty list signals to Exhale to use the defaults
       else:
           return []
   
   exhale_args = {
       ############################################################################
       # These arguments are required.                                            #
       ############################################################################
       "containmentFolder":     "./api",
       "rootFileName":          "library_root.rst",
       "rootFileTitle":         "OpenFHE Library API",
       "doxygenStripFromPath":  f"{__exhale_base}",
       "customSpecificationsMapping": utils.makeCustomSpecificationsMapping(
           specificationsForKind),
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
           EXCLUDE_PATTERNS += *.md
           
           WARN_IF_UNDOCUMENTED = NO,
           WARNINGS" = NO,
           WARN_IF_DOC_ERROR: NO,
           WARN_IF_INCOMPLETE_DOC: NO,
           WARN_NO_PARAMDOC: NO
       '''),
       ############################################################################
       # HTML Theme specific configurations.                                      #
       ############################################################################
       # Fix broken Sphinx RTD Theme 'Edit on GitHub' links
       # Search for 'Edit on GitHub' on the FAQ:
       #     http://exhale.readthedocs.io/en/latest/faq.html
       "pageLevelConfigMeta": ":github_url: https://github.com/openfheorg/openfhe-development",
       ############################################################################
       # Main library page layout example configuration.                          #
       ############################################################################
       "afterTitleDescription": textwrap.dedent(u'''
           Welcome to the user-facing documentation for OpenFHE.
   
           .. tip::
   
               OpenFHE is a large library so we recommend using the sidebar to navigate around across the 
               ``namespaces``, ``classes``, ``structs``, ``enums``, ``functions``, ``variables``, ``defines`` and the ``typedefs``. 
               
               We also recommend using the search functionality
       '''),
       "fullApiSubSectionTitle": "OpenFHE Documentation",
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
       "verboseBuild": False
   }
   
   # Tell sphinx what the primary language being documented is.
   primary_domain = 'cpp'
   
   # Tell sphinx what the pygments highlight language should be.
   highlight_language = 'cpp'

