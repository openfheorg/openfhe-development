.. code-block:: py

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

