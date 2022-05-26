.. _using_intersphinx:

Using Intersphinx
========================================================================================

The Sphinx `intersphinx`_ extension is exceptionally convenient, and typically works
out-of-the-box for most projects you would want to link to.  This is not limited to
linking to documents just within your domain, and if you really want to go the extra
mile (and create your own mapping), it doesn't even have to be restricted to linking to
documentation that was generated with Sphinx.

.. _intersphinx: http://www.sphinx-doc.org/en/stable/ext/intersphinx.html

.. contents:: Contents
   :local:
   :backlinks: none

Setup your ``conf.py``
----------------------------------------------------------------------------------------

First, how you link to things depends on what your `domain`_ is.  In the Exhale
`Quickstart Guide <quickstart_>`_, I encouraged you to add these lines to your
``conf.py``:

.. _domain:     http://www.sphinx-doc.org/en/stable/domains.html
.. _quickstart: http://exhale.readthedocs.io/en/latest/usage.html#quickstart-guide


.. code-block:: py

   # Tell sphinx what the primary language being documented is.
   primary_domain = 'cpp'

   # Tell sphinx what the pygments highlight language should be.
   highlight_language = 'cpp'

This will come up in the next section, but is added to ``conf.py`` so it is included
here.

For this ExhaleCompanion project, I want to link to two Sphinx generated projects.  In
the ``conf.py``, this means that I have:

.. code-block:: py

   # In addition to `breathe` and `exhale`, use the `intersphinx` extension
   extensions = [
       'sphinx.ext.intersphinx',
       'breathe',
       'exhale'
   ]

   # Specify the baseurls for the projects I want to link to
   intersphinx_mapping = {
       'exhale':  ('https://exhale.readthedocs.io/en/latest/', None),
       'nanogui': ('http://nanogui.readthedocs.io/en/latest/', None)
   }

Linking to Other Sites Using Intersphinx
----------------------------------------------------------------------------------------

This is where understanding your primary domain becomes particularly relevant.  Since
the ``primary_domain`` for this project is ``cpp``, I can link to things like
``:cpp:function:`` as just ``:function:``.  But if I want to link to Python or C domains
I need to specify that explicitly.  Inlined from the `Cross Referencing Syntax <xref_>`_
docs, there is some syntax you will likely need to wield:


- You may supply an explicit title and reference target: ``:role:`title <target>``` will
  refer to target, but the link text will be title.
- If you prefix the content with ``!``, no reference/hyperlink will be created.
- If you prefix the content with ``~``, the link text will only be the last component of
  the target. For example, ``:py:meth:`~Queue.Queue.get``` will refer to
  ``Queue.Queue.get`` but only display ``get`` as the link text.

.. _xref: http://www.sphinx-doc.org/en/stable/domains.html#cross-referencing-syntax

Linking to Python Docs from a ``cpp`` Project
****************************************************************************************

Since I've setup intersphinx to point back to the main Exhale site, I'll just link to
some from there.

**Linking to a Python Class**
    ``:py:class:`exhale.graph.ExhaleRoot```
        Links to :py:class:`exhale.graph.ExhaleRoot`
    ``:py:class:`graph.ExhaleRoot <exhale.graph.ExhaleRoot>```
        Links to :py:class:`graph.ExhaleRoot <exhale.graph.ExhaleRoot>`
    ``:py:class:`~exhale.graph.ExhaleRoot```
        Links to :py:class:`~exhale.graph.ExhaleRoot`

**Linking to a Python Function**
    ``:py:func:`exhale.deploy.explode```
        Links to :py:func:`exhale.deploy.explode`
    ``:py:func:`deploy.explode <exhale.deploy.explode>```
        Links to :py:func:`deploy.explode <exhale.deploy.explode>`
    ``:py:func:`~exhale.deploy.explode```
        Links to :py:func:`~exhale.deploy.explode`

Linking to Another C++ Project
****************************************************************************************

This is where understanding how to manipulate the link titles becomes relevant.  I'll
use the NanoGUI docs since I stole the :c:macro:`NAMESPACE_BEGIN` macro from there.

**Linking to a C++ Class**
    Using a single ``:`` does not appear to work, but using the ``namespace::ClassName``
    seems to include a leading ``:``.  I think this is a bug, but solving it would
    likely be treacherous so instead just control the title yourself.

    ``:class:`nanogui::Screen```
        Links to :class:`nanogui::Screen`

    ``:class:`nanogui::Screen <nanogui::Screen>```
        Links to :class:`nanogui::Screen <nanogui::Screen>`

    ``:class:`~nanogui::Screen```
        Links to :class:`~nanogui::Screen`

**Linking to C Domains**
    Even if the other project is primarily C++, things like macros are in the ``:c:``
    Sphinx domain.  I choose the ``NAMESPACE_BEGIN`` example to show you how to qualify
    where Sphinx should link --- both **this project** and **NanoGUI** have links to it,
    so when I just do ``:c:macro:`NAMESPACE_BEGIN``` the link (:c:macro:`NAMESPACE_BEGIN`)
    goes to **this project**.  Using ``nanogui:NAMESPACE_BEGIN`` (since ``'nanogui'``
    was a key in our ``intersphinx_mapping``)

    ``:c:macro:`nanogui:NAMESPACE_BEGIN```
        Links to :c:macro:`nanogui:NAMESPACE_BEGIN`

    ``:c:macro:`NanoGUI macro NAMESPACE_BEGIN <nanogui:NAMESPACE_BEGIN>```
        Links to :c:macro:`NanoGUI macro NAMESPACE_BEGIN <nanogui:NAMESPACE_BEGIN>`

    ``:c:macro:`~nanogui:NAMESPACE_BEGIN```
        Links to :c:macro:`~nanogui:NAMESPACE_BEGIN`

.. tip::

   These kinds of cross references are **reStructuredText** syntax!  You **must** enable
   the ``\rst`` environment for Doxygen (see `Doxygen ALIASES <aliases_>`_) **and**
   use this in the documentation.  For example, in order to get the
   :c:macro:`NAMESPACE_BEGIN` link to work, the actual C++ code is as follows:

   .. _aliases: http://exhale.readthedocs.io/en/latest/mastering_doxygen.html#doxygen-aliases

   .. code-block:: cpp

      #if !defined(NAMESPACE_BEGIN) || defined(DOXYGEN_DOCUMENTATION_BUILD)
          /**
           * \rst
           * See :c:macro:`NanoGUI macro NAMESPACE_BEGIN <nanogui:NAMESPACE_BEGIN>`.
           * \endrst
           */
          #define NAMESPACE_BEGIN(name) namespace name {
      #endif

Finding the Links to Use
----------------------------------------------------------------------------------------

For things like classes that are qualified in namespaces, it should be pretty easy for
you to figure out what the link is by inspection.  However, there is an excellent tool
available for you: the `Sphinx Objects.inv Encoder/Decoder <sphobjinv_>`_.

.. _sphobjinv: https://sphobjinv.readthedocs.io/en/latest/

1. Install the utility:

   .. code-block:: console

      $ pip install sphobjinv

2. Download the Sphinx ``objects.inv`` for the project you want to use.  This should
   be at the location you specified in your ``intersphinx_mapping``.  So if the URL you
   gave was ``url``, the ``objects.inv`` should be at ``url/objects.inv``.  Sticking
   with the NanoGUI example:

   .. code-block:: bash

      # Go to wherever you want and download the file
      $ cd /tmp

      # That's a capital 'Oh' not a zero; or use `wget`
      $ curl -O http://nanogui.readthedocs.io/en/latest/objects.inv
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
      100 44056  100 44056    0     0   109k      0 --:--:-- --:--:-- --:--:--  109k

      # rename it so you know where it hails from
      $ mv objects.inv nanogui_objects.inv

3. Decode it to plain text and search for what you are trying to link.

   .. code-block:: console

      # decode it so we can search it
      $ sphobjinv convert plain nanogui_objects.inv

      Conversion completed.
      'nanogui_objects.inv' decoded to 'nanogui_objects.txt'.

      # search for the thing you are trying to link to
      $ grep NAMESPACE_BEGIN nanogui_objects.txt | grep -v -- -1
                      vvvvvvv
      NAMESPACE_BEGIN c:macro 1 api/define_NAMESPACE_BEGIN.html#c.$ -
                      ^^^^^^^

   .. tip::

      Refer to the `sphobjinv syntax <syntax_>`_ section, the reason I am piping to
      ``grep -v -- -1`` is because "priority" ``-1`` means it won't be available to link
      to.  The ``-v`` tells ``grep`` to invert the match, and ``--`` tells ``grep`` that
      the command-line options (e.g., ``-v``) are finished and what follows is an
      argument.  That is, ``-- -1`` just makes it so ``grep`` doesn't think ``-1`` is
      a flag.

      .. _syntax: https://sphobjinv.readthedocs.io/en/latest/syntax.html

Custom Links
****************************************************************************************

You can also make your own ``intersphinx`` mappings.  I did this for linking to the
BeautifulSoup docs.  See `the _intersphinx/README.md of Exhale <bs4_hacks_>`_.

This use case was for a dysfunctional ``objects.inv``, but you could also easily create
your own mapping to index a project that was not created using Sphinx.

.. _bs4_hacks: https://github.com/svenevs/exhale/tree/master/docs/_intersphinx

Testing your Intersphinx Links
----------------------------------------------------------------------------------------

By default the Sphinx build process does not inform you of broken link targets when you
run ``make html``.  The ``sphinx-build`` flag you want for testing this is ``-n`` (for
*nitpicky*).  You will want to make sure to ``clean`` first so that all errors get shown.

.. code-block:: console

   $ make SPHINXOPTS='-n' clean html

.. tip::

   There is also a ``make linkcheck`` target for the Sphinx generated Makefiles!
