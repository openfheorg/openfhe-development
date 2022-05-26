OpenFHE Style Guide
========================


General Style Guidelines
---------------------------

-  Try to follow the style of surrounding code, and use variable names
   that follow existing patterns. Pay attention to indentation and
   spacing.
-  Configure your editor to use 4 spaces per indentation level, and
   **never to use tabs**.
-  Avoid introducing trailing whitespace
-  Limit line lengths to 80 characters when possible
-  Give meaningful variable names to all variables.
-  Every reused discrete block of code has its own method
-  Every discrete line of code, or discrete group of code lines for each task has its own comment.


C++
---

OpenFHE coding style is based on the official `Google C++ Coding Style Guide <https://google.github.io/styleguide/cppguide.html/>`_.

We explicitly note:

-  Write comments to explain non-obvious operations within the code,
   both in header or source files.

-  All classes, member variables, methods, and constants should have Doxygen-style comments

   - Please document all input and output data characteristics (required lengths of vectors,
   restrictions on combinations of variables) as well as any conditions
   that generate exceptions.

   - e.g comment lines starting with ``//!`` or comment blocks
   starting with ``/*!``

-  Avoid defining non-trivial functions in header files

-  Header files should include an ‘include guard’

- Operator overloading is allowed, especially for binary operations


Design Principles
^^^^^^^^^^^^^^^^^^

- ``cout`` should never be used for exception handling and should never be used in committed code in the core OpenFHE library.

- ``std::logic_error`` is the standard exception for all exceptions not caught by the OpenFHE exception handling subsystem (which has not yet been universally implemented in the library at this time).

- Code may make use of most C++11 features. The minimum required compiler versions are listed in the main README.md file.

- Avoid manual memory management (i.e. ``new`` and ``delete``),
  preferring to use standard library containers, as well as
  ``std::unique_ptr`` and ``std::shared_ptr`` when dynamic allocation
  is required.

- Portions of Boost which are "header only" may be used. If possible, include Boost
  header files only within ``.cpp`` files rather than other header files to
  avoid unnecessary increases in compilation time. Boost should not be added
  to the public interface unless its existence and use is optional. This keeps
  the number of dependencies low for users of OpenFHE. In these cases,
  ``OpenFHE_API_NO_BOOST`` should be used to conditionally remove Boost dependencies

Naming Conventions
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Protected and private member variable names are generally prefixed
   with ``m_``. For most classes, member variables should not be public.
   Data member should generally use ``m_camelCase``.

-  Variable names use ``camelCase``

-  Class, struct, typedef, and enum names use ``CamelCase``

-  Class Methods use ``CamelCase``

-  Global variable names: ``g_camelCase``

-  Class accessor names: ``GetProperty()`` and ``SetProperty()``

-  Constant names and macros use ``UPPER_CASE_WITH_UNDERSCORES``
   (example: ``BIT_LENGTH``)

-  Do not indent the contents of namespaces

Additional Resources
^^^^^^^^^^^^^^^^^^^^^

-  While OpenFHE does not specifically follow these rules, the following
   style guides are useful references for possible style choices and the
   rationales behind them.

   -  `The Google C++ Style Guide: <https://google.github.io/styleguide/cppguide.html>`_
   -  `Geosoft: C++ Programming Style Guidelines <http://geosoft.no/development/cppstyle.html>`_

.. note:: We have automated syntax checking on commit using ``clang-format``,
   so many of the above formatting rules will be automatically made.

Python
------

-  Style generally follows `PEP8 <https://www.python.org/dev/peps/pep-0008/>`_
-  Code in ``.py`` and ``.pyx`` files needs to be written to work with
   Python 3
-  The minimum Python version that OpenFHE supports is Python 3.4, so
   code should only use features added in Python 3.4 or earlier
-  Code in the Python examples should be written for Python 3
