Throwing Exceptions in OpenFHE
===============================

The OpenFHE library will throw a openfhe_error exception in the event of certain unrecoverable errors. A openfhe_error is a subclass of ``std::exception``. The library *actually* throws an exception which is a subclass of openfhe_error.


Programmers use the OPENFHE_THROW macro in exception.h to generate an exception. Each exception includes the filename and line number at which the exception was thrown as well as a programmer-defined message.


Exceptions and the methods associated with them are defined in ``src/core/include/utils/exception.h``.


Available Exceptions
-----------------------

The available exceptions are as follows

config_error
^^^^^^^^^^^^^^^^

This exception is thrown whenever the user of the library supplies configuration parameters that cannot be used to configure OpenFHE. An example of this would be providing a ciphertext modulus that is not a prime number, or providing a plaintext modulus that cannot be used with a particular encoding type.

math_error
^^^^^^^^^^^^^^^^

This exception is thrown whenever a math error occurs during the operation of the library. An example of this would be an overflow.

serialization_error
^^^^^^^^^^^^^^^^^^^^

This exception is thrown whenever a fatal serialization error occurs. For example, if a required field is missing, this exception is thrown.

not_implemented_error
^^^^^^^^^^^^^^^^^^^^^

This exception is thrown if a method is unimplemented. An example of this is a circumstance where a default implementation is provided in a base class, but an overridden exception is not provided in the derived class.

not_available_error
^^^^^^^^^^^^^^^^^^^

This exception is thrown if a method is not available for a given configuration. For example, an arbitrary cyclotomics method is not available for a power-of-2 configuration.

Exceptions in critical regions and OMP threads
-----------------------------------------------

An exception that is thrown in a critical region, or that is thrown within an OMP thread, must be caught in the same region where it is thrown. The program will abort if this is not done.

If an exception must be thrown in a critical region or OMP thread, but must be caught in another thread, then it is necessary to catch the exception and re-throw it. Classes and sample code is provided in ``src/core/include/utils/exception.h`` to show how this is done.

For example, the following code will catch and rethrow an exception thrown inside of a thread

.. code-block:: c++
   :linenos:

    ThreadException e;
    #pragma omp parallel for
    for(unsigned i=0; i<rv.size(); i++) {
        try {
            rv.polys[i] = (polys[i].*f)();
        }
        catch(...) {
            e.CaptureException();
        }
    }

    e.Rethrow();
