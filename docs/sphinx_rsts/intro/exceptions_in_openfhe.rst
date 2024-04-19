Throwing Exceptions in OpenFHE
===============================

The OpenFHE library will throw a OpenFHEException exception in the event of certain unrecoverable errors. A OpenFHEException is a subclass of ``std::exception``.


Programmers use the OPENFHE_THROW macro in exception.h to generate an exception. Each exception includes the filename and line number at which the exception was thrown as well as a programmer-defined message.


The exception and the methods associated with them are defined in ``src/core/include/utils/exception.h``.

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
