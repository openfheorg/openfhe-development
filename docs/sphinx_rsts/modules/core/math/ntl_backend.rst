NTL Backend API
===============

This page exposes OpenFHE's extensions in ``namespace NTL``. These
classes are only compiled when OpenFHE is configured with ``WITH_NTL``,
and the documentation build defines that macro so Doxygen can extract
the guarded declarations.

.. contents:: Page Contents
   :local:
   :backlinks: none

Namespace
---------

.. doxygennamespace:: NTL
   :members:
   :protected-members:
   :undoc-members:

Integer And Vector Types
------------------------

.. doxygenclass:: NTL::myZZ
   :members:
   :protected-members:
   :undoc-members:

.. doxygenclass:: NTL::myVecP
   :members:
   :protected-members:
   :undoc-members:

Number Theoretic Transform Types
--------------------------------

.. doxygenclass:: NTL::NumberTheoreticTransformNtl
   :members:
   :protected-members:
   :undoc-members:

.. doxygenclass:: NTL::ChineseRemainderTransformFTTNtl
   :members:
   :protected-members:
   :undoc-members:

.. doxygenclass:: NTL::ChineseRemainderTransformArbNtl
   :members:
   :protected-members:
   :undoc-members:

.. doxygenclass:: NTL::BluesteinFFTNtl
   :members:
   :protected-members:
   :undoc-members:
