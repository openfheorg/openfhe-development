PKE Scheme documentation
====================================

This is comprised of 3 folders:

- `scheme <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/scheme/>`_, which contains the specifications of the different RNS implementations

- `schemebase <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/schemebase/>`_, which contains the base implementations of various functionalities

- `schemerns <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/schemerns/>`_, which contains the RNS-ed base schemeimplementations.

At a high level, this can be thought of as:

.. mermaid::

  graph BT
      A[Scheme Base] --> |Inherited by|B[Scheme RNS];
      B[Scheme RNS] --> |Inherited by|D[Scheme: CKKS-RNS];
      B[Scheme RNS] --> |Inherited by|E[Scheme: BGV-RNS];
      B[Scheme RNS] --> |Inherited by|F[Scheme: BFV-RNS];


.. contents:: Page Contents
   :depth: 2
   :local:
   :backlinks: none



PKE Scheme
-------------------------------

.. autodoxygenindex::
   :project: pke_scheme
   :allow-dot-graphs:

PKE Scheme Base
-------------------------------

.. autodoxygenindex::
   :project: pke_schemebase
   :allow-dot-graphs:


PKE RNS Scheme
-------------------------------

.. autodoxygenindex::
   :project: pke_schemerns
   :allow-dot-graphs:


PKE RNS - CKKS Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autodoxygenindex::
   :project: pke_scheme_ckksrns
   :allow-dot-graphs:

PKE RNS - BGVRNS Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autodoxygenindex::
   :project: pke_scheme_bgvrns
   :allow-dot-graphs:


PKE RNS - BFVRNS Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autodoxygenindex::
   :project: pke_scheme_bfvrns
   :allow-dot-graphs:
