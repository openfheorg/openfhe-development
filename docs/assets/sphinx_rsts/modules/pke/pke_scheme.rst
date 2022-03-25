PKE Scheme documentation
====================================

This is comprised of 3 folders:

- `scheme `_, which contains the specifications of the different RNS implementations

- `schemebase`_, which contains the base implementations of various functionalities

- `schemerns`_, which contains the RNS-ed base schemeimplementations.

At a high level, this can be thought of as:

.. mermaid::

  graph BT
      A[Scheme Base] --> |Inherited by|B[Scheme RNS];
      B[Scheme RNS] --> |Inherited by|D[Scheme: CKKS-RNS];
      B[Scheme RNS] --> |Inherited by|E[Scheme: BGV-RNS];
      B[Scheme RNS] --> |Inherited by|F[Scheme: BFV-RNS];


.. contents:: Table of Contents
   :depth: 1
   :local:
   :backlinks: none


PKE RNS Scheme
-------------------------------

.. autodoxygenindex::
   :project: pke_schemerns


PKE RNS - CKKS Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autodoxygenindex::
   :project: pke_scheme_ckksrns


PKE RNS - BGVRNS Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autodoxygenindex::
   :project: pke_scheme_bgvrns

PKE RNS - BFVRNS Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autodoxygenindex::
   :project: pke_scheme_bfvrns


PKE Base Scheme
-------------------------------

.. autodoxygenindex::
   :project: pke_schemebase

Standard PKE Scheme
-------------------------------

.. autodoxygenindex::
   :project: pke_scheme


PKE RNS Scheme
-------------------------------

.. autodoxygenindex::
   :project: pke_schemerns


PKE RNS - CKKS Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autodoxygenindex::
   :project: pke_scheme_ckksrns


PKE RNS - BGVRNS Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autodoxygenindex::
   :project: pke_scheme_bgvrns

PKE RNS - BFVRNS Scheme
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. autodoxygenindex::
   :project: pke_scheme_bfvrns


