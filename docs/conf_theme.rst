.. code-block:: py

   # The name of the Pygments (syntax highlighting) style to use.
   # `sphinx` works very well with the RTD theme, but you can always change it
   pygments_style = 'sphinx'
   
   # on_rtd is whether we are on readthedocs.org, this line of code grabbed from docs.readthedocs.org
   on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
   
   if not on_rtd:  # only import and set the theme if we're building docs locally
       import sphinx_rtd_theme
       html_theme = 'sphinx_rtd_theme'
       html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

