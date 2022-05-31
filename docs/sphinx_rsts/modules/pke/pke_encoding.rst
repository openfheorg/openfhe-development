PKE Encoding documentation
====================================

`Github Source <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/encoding>`_: Encoding of plaintext into intermediate form

.. contents:: Page Contents
   :local:
   :backlinks: none


Interactions
------------------------

.. mermaid::

  graph BT
      A[Input Plaintext] --> |"1) Encode"| B(Encoded Plaintext);
      B(Encoded Plaintext) --> |"2) Encrypt"| C(Ciphertext);
      C(Ciphertext) --> |"3) Decrypt"| B(Encoded Plaintext);
      B(Encoded Plaintext) --> |"4) SetLength"| D(Homomorphically Transformed Plaintext);

File Listings
-----------------------

`CKKS Packed Encoding (ckkspackedencoding.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/encoding/ckkspackedencoding.h>`_
    - Describes the CKKS packing. Accepts a ``std::vector<double>`` or a ``std::vector<std::complex>`` (although the double is recommended) unlike the other schemes.

`Coef Packed Encoding (coefpackedencoding.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/encoding/coefpackedencoding.h>`_
    - Packs integers into a vector of size ``n``
    - Element-wise ops: Supports only element-wise addition (``EvalAdd``), but not multiplication. Thus, typically only works well when no multiplications are necessary
    - Scalar ops: multiplication supported
    .. note:: ``Coef Packed Encoding`` is rarely used.

`Encoding Params (encodingparams.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/encoding/encodingparams.h>`_
    - The object containing the parameters for encoding. These parameters are kept and continually reused (can be modified) during the encoding of new values

`Encodings (encodings.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/encoding/encodings.h>`_
    - “import” file which can be used for a single ``#include``

`Packed Encoding (packedencoding.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/encoding/packedencoding.h>`_
    - Packs integers into a vector of size ``n``
    - Supports element-wise addition and multiplication via ``EvalAdd`` and ``EvalMult`` respectively
    - Supports automorphisms (commonly known as rotations) via ``EvalAtIndex``
        - Right Shift: positive index
        - Left Shift: negative index
        - Rotations work cyclically

    .. note:: is almost always what you want to use (other than if you want to deal with floating numbers)

`Plaintext (plaintext.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/encoding/plaintext.h>`_
    - The base plaintext implementation

`Plaintext Factory (plaintextfactory.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/encoding/plaintextfactory.h>`_
    - Factory class that instantiates plaintexts

`String Encoding (stringencoding.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/encoding/stringencoding.h>`_
    - Encodes strings