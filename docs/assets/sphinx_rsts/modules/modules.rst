OpenFHE Code Components
=================================================

Understanding the various components
------------------------------------

.. mermaid::

  graph BT
      A[CORE<br/>- math implementation<br/>- lattice implementation<br/>- serialization] --> B[PKE<br/> -generalized FHE];
      A --> C[BINFHE<br/>- binary FHE];
      B --> D[Application<br/>- encrypted data analysis<br/>- privacy-compliant data sharing];
      C --> D;


Below we describe the various components

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   binfhe.rst
   core.rst
   pke.rst
