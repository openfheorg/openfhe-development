PALISADE Style Guide
========================

PALISADE coding style is based on the official
 `Google C++ Coding Style Guide <https://google.github.io/styleguide/cppguide.html/>`_.

Of particular note on the documentation style:

1.	We use doxygen commenting style on classes, methods and constants.

2.	We given meaningful variable names to all variables.

3.	Every reused discrete block of code has its own method.

4.	Every discrete line or code or discrete group of code lines for each task has its own comment.

With regards to naming conventions:

1.	Variable names: camelCase

2.	Class, struct, typedef, and enum names: CamelCase

3.	Class data members: m_camelCase

4.	Class accessor names: GetProperty() and SetProperty()

5.	Class method names: CamelCase

6.	Global variable names: g_camelCase

7.	Constant names and macros: UPPER_CASE_WITH_UNDERSCORES (example: BIT_LENGTH)

8.	Operator overloading is allowed, especially for binary operations

We also follow these design principles:

* cout should never be used for exception handling and should never be used in committed code in the core PALISADE library.

* ``std::logic_error`` is the standard exception for all exceptions not caught by the PALISADE exception handling subsystem (which has not yet been universally implemented in the library at this time).