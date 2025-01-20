Application-Aware Homomorphic Encryption (AAHE): Proof-of-Concept Implementation of Example ASL
=====================================

This repository provides a proof-of-concept (PoC) implementation in OpenFHE v1.2.3 of the example ASL described in the paper, both for the CKKS (approximate) and BFV (exact) schemes.

## Installation

Follow the OpenFHE [Installation Instructions](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html).

Or refer to the following for your specific operating system:

- [Linux](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/linux.html)

- [MacOS](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/macos.html)

- [Windows](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/windows.html)

Note that the CKKS examples require compiling OpenFHE using

```
cmake -DNATIVE_SIZE=128 ..
```

## API Extensions

The PoC extends the OpenFHE API with the following AAHE-related methods.

**CCParams** API
* **SetEvalCircuit(string)** configures the circuit that the parameters are generated for.
* **SetEvalCircuits(vector<string>)** is added to support multiple circuits (motivated by CKKS where noise estimation is more complicated).

**CryptoContextImpl** API
* **ValidateCircuit(string)** checks whether a supplied circuit is compatible with the parameters.
In CKKS, the method checks whether this circuit was supplied to **SetEvalCircuit**. In BFV, the method estimates the noise
and checks whether current parameters are large enough to produce correct results for the supplied circuit.
* **EstimateCircuit(string,publicKey)** (CKKS only) computes noise by evaluating the circuit for low and high values of the range. Used during the estimation stage.
* **EstimateCircuits(publicKey)** (CKKS only) calls **EstimateCircuit** for all circuits configured with **SetEvalCircuits**.
* **EvaluateCircuit(string,vector<Ciphertext>)** evaluates a circuit using a supplied vector of ciphertexts as inputs. **ValidateCircuit** is always called first and generates an exception if the validation fails.
* **FindMaximumNoise(vector<Ciphertext>,privateKey)** finds the maximum noise norm using a vector ciphertexts generated with **EstimateCircuit(s)**.

There is also an auxiliary method **EstimateCircuitBFV()** that estimates the noise and finds the ciphertext modulus for a provided circuit (only for BFV).

## CKKS Examples

Two circuits are considered: addition and doubling, just like in Section 3 of https://www.usenix.org/system/files/sec24summer-prepub-822-guo.pdf (USENIX'24). The addition circuit adds 999 randomly generated inputs.
The doubling circuit adds the same ciphertext 999 times, i.e., it is equivalent to recursively doubling the input 10 times.

* [Addition Circuit Example](src/pke/examples/circuits-ckks-addition.cpp) The parameters are set using the addition circuit.
Then validation is performed for the addition circuit (passes). Finally, the program tries to execute
both circuits. The evaluation for the addition circuit succeeds. The evaluation for the doubling circuit fails (throws an exception because validation fails). This example shows
that the attack of https://www.usenix.org/system/files/sec24summer-prepub-822-guo.pdf is no longer possible because the circuits for addition and doubling are different, and have different noise growths.
* [Doubling Circuit Example](src/pke/examples/circuits-ckks-doubling.cpp) The parameters are set using both the addition and doubling circuits (the maximum noise bound across both circuits is chosen).
Then validation is performed for the addition circuit (passes). Finally, the program tries to execute
both circuits. The evaluation for the addition circuit succeeds. The evaluation for the doubling circuit also succeeds.

## Outputs of CKKS Examples

* [Addition Circuit Example](src/pke/examples/circuits-ckks-addition.txt)
* [Doubling Circuit Example](src/pke/examples/circuits-ckks-doubling.txt)

Note that the noise estimate is 5 bits larger for the doubling case because the doubling
circuit has worst-case growth, i.e., it increases the input noise by 1000 vs roughly 1000^(1/2) for the addition circuit.

## BFV Examples

Two circuits are considered: addition and doubling, just like in Section 3 of https://eprint.iacr.org/2024/127 (CCS'24). The addition circuit adds 45 randomly generated inputs.
The doubling circuit doubles the input ciphertext 44 times.

* [Addition Circuit Example](src/pke/examples/circuits-addition.cpp) The parameters are set using the addition circuit.
Then validation is performed for both addition (passes) and doubling (fails) circuits. Finally, the program tries to execute
both circuits. The evaluation for the addition circuit succeeds. The evaluation for the doubling circuit fails (throws an exception). This example shows
that the attack of https://eprint.iacr.org/2024/127 is no longer possible because the circuits for addition and doubling are different, and have different noise growths.
* [Doubling Circuit Example](src/pke/examples/circuits-doubling.cpp) The parameters are set using the doubling circuit.
Then validation is performed for both addition (passes) and doubling (passes) circuits. Finally, the program tries to execute
both circuits. The evaluation for the addition circuit succeeds. The evaluation for the doubling circuit also succeeds.

## Outputs of BFV Examples

* [Addition Circuit Example](src/pke/examples/circuits-addition.txt)
* [Doubling Circuit Example](src/pke/examples/circuits-doubling.txt)
