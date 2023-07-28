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

This hardware abstraction layer allows OpenFHE to use a variety of hardware-integrated backends while still allowing for high performance. As of March 31st 2022, we have the:

- default backend

- `Intel Hexl <https://github.com/intel/hexl>`_ backend

.. note:: Follow the convention set by the the `OpenFHE HEXL code <https://github.com/openfheorg/openfhe-hexl>`_ to extend the supported backends.

File Listing
---------------

`DCRTPolyInterface (dcrtpoly-interface.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/lattice/hal/dcrtpoly-interface.h>`_

-  Base class for ``DCRTPoly``

`DCRTPoly Interface Aliases (lat-backend-default.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/lattice/hal/default/lat-backend-default.h>`_

-  Defines aliases for the lattice default backend

`Integer Lattice Double CRT Params (ildcrtparams.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/lattice/ildcrtparams.h>`_

-  Inherits from ``DCRTPolyInterface`` and provides a public-facing interface used downstream by the various schemes.
