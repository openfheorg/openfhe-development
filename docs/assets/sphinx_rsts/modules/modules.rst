OpenFHE Modules
=================================================

Understanding the various Modules
------------------------------------

.. mermaid::

  graph BT
      A[CORE<br/>- math implementation<br/>- lattice implementation<br/>- serialization] --> B[PKE<br/> -generalized FHE];
      A --> C[BINFHE<br/>- boolean FHE];
      B --> D[Application<br/>- encrypted data analysis<br/>- privacy-compliant data sharing];
      C --> D;

Boolean FHE
----------------------------
.. toctree::
   :maxdepth: 2

   binfhe.rst


Core
----------------------------
.. toctree::
   :maxdepth: 3

   core.rst

Public-Key Encryption (PKE)
----------------------------
.. toctree::
   :maxdepth: 3

   pke.rst