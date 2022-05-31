Sampling in OpenFHE
===================

OpenFHE library offers various methods for sampling from discrete
Gaussian distribution. The methods are implemented in both
`DiscreteGaussianGenerator <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/discretegaussiangenerator.h>`__ and
`DiscreteGaussianGeneratorGeneric <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/discretegaussiangeneratorgeneric.h>`__
classes, which have their specific uses. All of the samplers discussed
have been tested in `GLITCH Discrete Gaussian Testing
Suite <https://eprint.iacr.org/2017/438.pdf>`__ and no
problems/abnormalities have been found.

Samplers in DiscreteGaussianGenerator
-------------------------------------

The class `DiscreteGaussianGenerator <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/discretegaussiangenerator.h>`__
is the main class for homomorphic encryption and includes the
implementations of rejection sampling, Karney’s method and Peikert’s
inversion method.

-  **Rejection Sampling:** Rejection sampling is defined in section 4.1
   of the paper `Trapdoors for Hard Lattices and New Cryptographic
   Constructions <https://eprint.iacr.org/2007/432.pdf>`__. It is used
   in the methods GenerateInteger(double mean, double stddev, size_t n,
   const IntType &modulus) and GenerateInteger(double mean, double
   stddev, size_t n). Rejection sampling can be used for any arbitrary
   center and distribution parameter without any precomputations.
   However, it has high rejection rate and is vulnerable to timing
   attacks. It is currently not used by any cryptographic protocols in
   OpenFHE.

-  **Karney’s Method:** Karney’s method is defined as Algorithm D in the
   paper `Sampling exactly from the normal
   distribution <https://arxiv.org/pdf/1303.6257.pdf>`__, which is an
   improved sampling method, based on rejection sampling. It is used in
   the method GenerateIntegerKarney. Like the rejection sampling, it can
   be used for arbitrary center and distribution parameter without any
   precomputations. It has a smaller rejection rate than the traditional
   sampling but it may still be prone to timing attacks.

-  **Peikert’s Inversion Method:** Peikert’s inversion method discussed
   in section 4.1 of the paper `An Efficient and Parallel Gaussian
   Sampler for Lattices <https://eprint.iacr.org/2010/088.pdf>`__ and
   summarized in section 3.2.2 of `Sampling from discrete Gaussians for
   lattice-based cryptography on a constrained
   device <https://link.springer.com/content/pdf/10.1007%2Fs00200-014-0218-3.pdf>`__.
   It requires CDF tables of probabilities centered around single center
   to be kept in memory, which are pre calculated in the constructor.
   Peikert’s inversion algorithm is used in the methods GenerateInt,
   GenerateIntVector, GenerateVector and GenerateInteger(const IntType&
   modulus). These methods are not prone to timing attacks but they are
   usable for single center, single deviation only. It should be also
   noted that the memory requirement grows with the distribution
   parameter, therefore it is advised to use it with smaller deviations.

Since DiscreteGaussianGenerator contains both rejection based &
precomputation-based sampling algorithms, a different constructor must
be called based on the desired algorithm to be used. If Peikert’s method
is desired, then the object must be constructed with a distribution
parameter whereas using rejection or Karney’s method does not require
such constraint. (Refer to `How to Use Sampling
Methods <#how-to-use-sampling-methods>`__ section for example code) The
std parameter in the constructor is only used by Peikert’s method.

Samplers in DiscreteGaussianGeneratorGeneric
--------------------------------------------

The class
`DiscreteGaussianGeneratorGeneric <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/discretegaussiangeneratorgeneric.h>`__
is the constant-time generic sampler developed by UCSD, and it contains
the definitions for this new sampling method and base samplers required
for it.

-  **Peikert’s Inversion Method:** Peikert’s inversion method is the
   same one defined in
   `DiscreteGaussianGenerator <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/discretegaussiangenerator.h>`__, and
   it’s used in base samplers only. It is called from a BaseSampler
   object created with “PEIKERT” parameter by invoking GenerateInteger
   method.

-  **Knuth-Yao Sampling:** Knuth-Yao’s method for sampling integers was
   summarized in section 5 of `Sampling from discrete Gaussians for
   lattice-based cryptography on a constrained
   device <https://link.springer.com/content/pdf/10.1007%2Fs00200-014-0218-3.pdf>`__.
   It requires the calculation of probability matrix and then the
   Discrete Distribution Generating trees, which is handled in
   constructor. In order to use this method, it is required to call it
   from a BaseSampler object created with “KNUTH_YAO” parameter by
   invoking GenerateInteger method. Just like Peikert’s inversion
   method, it is usable for single center, single deviation only while
   having a memory requirement proportional to distribution parameter.

-  **Generic Constant Time Sampling:** The new generic sampler developed
   by UCSD was discussed in the paper `Gaussian Sampling over the
   Integers: Efficient, Generic,
   Constant-Time <https://eprint.iacr.org/2017/259>`__. It combines a
   set of base samplers centered around various means and a single
   distribution parameter to sample from arbitrary centers and
   distribution parameters. The parameter selection is discussed in
   detail in header file, but in general the sampler requires a set of
   base samplers given as parameters and few precomputations, which are
   handled in construction phase. This method can be called by creating
   a DiscreteGaussianGeneratorGeneric object and invoking
   GenerateInteger method. It is not vulnerable to timing attacks.

How to Use Sampling Methods
---------------------------

Rejection Sampling
~~~~~~~~~~~~~~~~~~

.. code-block::
   :linenos:

   /*Create the generator object, std is not important as we choose it arbitrarily during sampling*/
   DiscreteGaussianGenerator dggRejection;
   /*First parameter is the mean, second one is the distribution parameter and third one is the ring dimension.*/
   int64_t number = dggRejection.GenerateInteger(0,4,1024);

Karney’s Method
~~~~~~~~~~~~~~~

.. code-block::
   :linenos:

   /*Create the generator object, std is not important as we choose it arbitrarily during sampling*/
   DiscreteGaussianGenerator dggKarney;
   /*First parameter is the mean, second one is the distribution parameter*/
   int64_t number = dggKarney.GenerateIntegerKarney(0,4);

Peikert’s Inversion Method (As defined in DiscreteGaussianGenerator)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block::
   :linenos:

   /*Create the generator object, the parameter is the distribution parameter*/
   DiscreteGaussianGenerator dggPeikert(4);
   /*This will create a single number*/
   int64_t number = dggPeikert.GenerateInt();

Peikert’s Inversion Method (As defined in DiscreteGaussianGeneratorGeneric)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block::
   :linenos:

   /*Create a bit generator that will feed the random bits*/
   BitGenerator* bg = new BitGenerator();

   /*Mean and distribution parameter*/
   double std= 4;
   double mean = 0;

   /*Create the sampler object*/
   BaseSampler peikert_sampler(mean,std,bg,PEIKERT);

   /*Generate Integer */
   int64_t number = peikert_sampler.GenerateInteger();

Knuth-Yao’s Method (As defined in DiscreteGaussianGeneratorGeneric)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block::
   :linenos:

   /*Create a bit generator that will feed the random bits*/
   BitGenerator* bg = new BitGenerator();

   /*Mean and distribution parameter*/
   double std= 4;
   double mean = 0;

   /*Create the sampler object*/
   BaseSampler ky_sampler(mean,std,bg,KNUTH_YAO);

   /*Generate Integer */
   int64_t number = ky_sampler.GenerateInteger();

Generic Sampler
~~~~~~~~~~~~~~~

.. code-block::
   :linenos:

   /*Create a bit generator that will feed the random bits*/
   BitGenerator* bg = new BitGenerator();

   /*Distribution parameter of the base samplers, distribution parameter of the actual distribution, number of base samplers, mean of the actual distribution*/
   double stdBase = 34;
   double std = (1<<22);
   int CENTER_COUNT = 1024
   double mean = 0;

   /*Initialize base samplers*/
   BaseSampler **peikert_samplers;
   for(int i=0;i<CENTER_COUNT;i++){
       double center = ((double)i/(double)CENTER_COUNT);
       peikert_samplers[i]=new BaseSampler((double)center,stdBase,bg,PEIKERT);
   }

   /*Create the sampler object*/
   int base = std::log(CENTER_COUNT)/std::log(2);
   DiscreteGaussianGeneratorGeneric dggGeneric(peikert_samplers,stdBase,base,SMOOTHING_PARAMETER);

   /*Generate Integer */
   int64_t number = dggGeneric.GenerateInteger(mean,std);
