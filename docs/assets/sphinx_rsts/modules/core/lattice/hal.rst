.. _hal:

Core Lattice Hardware Abstraction Layer Documentation
======================================================


.. contents:: Page Contents
   :local:
   :backlinks: none

Lattice HAL Introduction
----------------------------

.. mermaid::

  graph BT
      a[DCRTPolyInterface] --> |Inherited by|b[DCRTPoly - HAL Default];
      b[DCRTPoly-HAL Default] --> |Inherited by|c[HexlDCRTPoly];

This hardware abstraction layer allows OpenFHE to use a variety of hardware-integrated backends while still allowing for high performance. As of March 31st 2022, we have the:

- default backend

- `Intel Hexl <https://github.com/intel/hexl>`_ backend

.. note:: Follow the convention set by the the `OpenFHE HEXL code <https://github.com/openfheorg/openfhe-hexl>`_ to extend the supported backends.

Core Lattice HAL Documentation
-------------------------------

.. autodoxygenindex::
   :project: core_lattice_hal
   :allow-dot-graphs:

Core Lattice HAL Default Backend Documentation
-----------------------------------------------

.. autodoxygenindex::
   :project: core_lattice_hal_default
   :allow-dot-graphs: