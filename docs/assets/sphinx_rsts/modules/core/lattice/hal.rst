.. _hal:

Core Lattice Hardware Abstraction Layer Documentation
======================================================

.. mermaid::

  graph BT
      a[DCRTPolyInterface] --> |Inherited by|b[DCRTPoly - HAL Default];
      b[DCRTPoly-HAL Default] --> |Inherited by|c[HexlDCRTPoly];

This hardware abstraction layer allows OpenFHE to use a variety of device backends while still allowing for high performance. As of March 31st 2022, we have the default backend, and the `Intel Hexl <https://github.com/intel/hexl>`_ backend.

**Note:** Follow the convention set by the the `PALISADE HEXL code <https://github.com/openfheorg/openfhe-development/tree/main/src/core/include/lattice/hal/hexl>`_ to extend the supported backends.

.. contents:: Core Lattice HAL
   :depth: 2
   :local:
   :backlinks: none


Core Lattice HAL Documentation
-------------------------------

.. autodoxygenindex::
   :project: core_lattice_hal

Core Lattice HAL HEXL Documentation
-------------------------------------

.. autodoxygenindex::
   :project: core_lattice_hal_hexl

Core Lattice HAL Default Backend Documentation
-----------------------------------------------

.. autodoxygenindex::
   :project: core_lattice_hal_default

