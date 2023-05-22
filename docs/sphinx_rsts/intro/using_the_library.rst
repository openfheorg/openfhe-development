Using The Library
====================================

OpenFHE consists of a number of library objects that can be linked into lattice cryptography applications.

The source files in the demo directories, particularly those in src/examples/pke, illustrate the use of the library.

To use OpenFHE, you must

* select a scheme to use

  * ``BFVrns``

  * ``BGVrns``

  * ``CKKSrns``

* create a CryptoContext for the scheme. This requires that you:

 * run a parameter generation function or, alternatively,

  * decide on lattice parameters (ring dimension, size of moduli)

  * decide on encoding parameters (plaintext modulus)

  * decide on scheme-specific parameters

 * enable the algorithms that you want to use, e.g.,

   * Enable(ENCRYPTION) - allows for key generation and encrypt/decrypt

   * Enable(PRE) - allows for the use of proxy re-encryption

   * Enable(SHE) - enables SHE operations such as EvalAdd and EvalMult

   * Enable(MULTIPARTY) - enables threshold FHE operations

In order to make this easier for the user, there are several CryptoContextFactory methods for the various schemes.

Streamlining and improving the process of parameter selection and CryptoContext generation is an area that is being actively worked.

Anything done in OpenFHE is done through the CryptoContext. All operations are CryptoContext methods. The code only allows operations between objects that were created in the same context, and will generate an error if it finds that this is not the case.

Saving to string or disk file
-----------------------------

Serialization and Deserialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

An object created by a CryptoContext usually has a ``Serialize`` method that converts the object into a cereal object that can be saved to a string or to a disk file:

* Serial::Serialize()

* Serial::SerializeToFile()

A serialized object can be ``Deserialized`` using the following functions, respectively:

* Serial::Deserialize()

* Serial::DeserializeFromFile()

The Deserialize process will ensure that the serialized object's parameters match the CryptoContext. If they do, then
the new object "belongs to" the CryptoContext and can be used with other objects from the same CryptoContext.

.. note:: A mismatch of parameters will cause the deserialization to fail.
