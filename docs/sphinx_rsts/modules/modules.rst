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
   :maxdepth: 2

   core/core.rst
   core/lattice/core_lattice.rst
   core/lattice/hal.rst
   core/math/core_math.rst
   core/utils/core_utils.rst


Public-Key Encryption (PKE)
----------------------------
.. toctree::
   :maxdepth: 2

   pke/pke.rst
   pke/pke_encoding.rst
   pke/pke_keys.rst
   pke/pke_keyswitch.rst
   pke/pke_scheme.rst
