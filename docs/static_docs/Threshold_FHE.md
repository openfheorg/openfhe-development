Threshold FHE is currently supported for BGV, BFV, and CKKS. To use the threshold functionality in OpenFHE, the MULTIPARTY feature needs to be enabled for the cryptocontext with the line `cc->Enable(MULTIPARTY)`, where `cc` is the cryptocontext object.

The MULTIPARTY feature has been implemented in two modes for BGV/BFV. The modes are implemented as an enum -
**MultipartyMode multipartyMode**

```
	- FIXED_NOISE_MULTIPARTY which is the default mode if not set, adds a fixed 20 bits noise
	- The NOISE_FLOODING_MULTIPARTY mode adds extra noise and gives enhanced security compared to the FIXED_NOISE_MULTIPARTY mode.  This is the most secure mode of threshold FHE for BFV and BGV.
```
The mode can be configured using the `SetMultipartyMode` method to the parameters passed to cryptocontext. For example, the following code creates a parameters object for a BGVRNS cryptocontext and sets the multiparty mode to `NOISE_FLOODING_MULTIPARTY`.

```
CCParams<CryptoContextBGVRNS> parameters;
parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);
```

The modes are implemented to provide security against the type of attacks in [Li and Micciancio](https://link.springer.com/chapter/10.1007/978-3-030-77870-5_23) and [Kluczniak and Santato](https://eprint.iacr.org/2023/301).
More on the attack and the solution with noise flooding for CKKS decryption in provided in [CKKS_NOISE_FLOODING.MD](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/CKKS_NOISE_FLOODING.md).
The same kind of attacks also apply in the threshold scenario for all three schemes since the approximate decryption shares from each party are shared before they can be aggregated to decrypt the final result.
The decryption share of a ciphertext $c = (c_0, c_1)$ for party $i$ is $\mathsf{d_i} = c_0 + c_1s_i$.
Similar to the CKKS decryption attack, the noise in the decryption share $d_i$ leaks information about the secret $s_i$.

The FIXED_NOISE_MODE for all schemes is implemented to add a fixed $20$-bit noise to the decryption share to increase the attack complexity.

The NOISE_FLOODING_MODE provides provable security against such attacks as in the IND-CPA^D model. The technique to choose the modulus to accomodate the extra noise from noise flooding is implemented in BGV and BFV differently as follows:

1. BFV:
In this case, additional two towers of moduli are added to the CRT moduli to accomodate the error, which increases the size of the modulus by about $128$ bits. This is automatically done by OpenFHE during parameter generation if the NOISE_FLOODING_MULTIPARTY mode is set in the parameters as above.

The protocol for BFV threshold noise flooding is as follows:
Let our current RNS basis for decryption be $Q=q_0 * q_1 * ... * q_k$. Add two more 60-bit primes $p_0$ and $p_1$. The extended basis is $QP = q_0 * p_1 * p_2 * q_1 * ... * q_k$.

For an input ciphertext $c mod QP$, the decryption shares by each party $i$ are created as follows:

	- We first generate a random uniform ring element $b$ w.r.t. to mod $Qprime = QP/q_0$. Then we do exact RNS basis extension from $Qprime$ to $QP$.

	- Then we do flooding with $b$ as $c_1 * s_i + b mod QP$.

2. BGV: For BGV threshold noise flooding, the protocol is exactly the same as BFV, except we use $b' = tb$ for flooding instead of $b$ for plaintext modulus $t$.


3. CKKS:

IND-CPA^D mode can be used to instantiate threshold FHE for the mode similar to NOISE_FLOODING_MULTIPARTY. Please look at [the CKKS noise flooding example](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/ckks-noise-flooding.cpp) for more details.

# Threshold decryption with Aborts:

In addition to the multiparty modes that can be set in the parameters for Threshold FHE, there is an aborts option to get a $t$-out-of-N threshold decryption where $t > N/2 + 1$. This can be achieved with an additional secret sharing step after keygen by each party. We use the aborts approach described [here](https://eprint.iacr.org/2011/613.pdf) to use a secret sharing scheme to allow $t$ out of $N$ decryption. The secret sharing and recovery (of an aborted party) are done using the `ShareKeys` and `RecoverSharedKey` functions respectively. Using this approach, we are able to decrypt a ciphertext computed using the joint evaluation keys of $N$ parties even if upto $N-t$ parties drop out from the network. We consider two secret sharing options with the aborts approach:

1. Additive sharing: With this option, we let each party secret share its secret key additively to all other parties, resulting in $N - 1$ additive shares. When one party drops out, the other parties can collaborate and generate the dropped parties' secret key using these shares. Note that this directly allows to decrypt with $N - 1$ parties with one party dropping out. To allow decryption with multiple parties dropping out using this option, we would need each party to generate shares of their secret for all possible combinations of the participating parties. This could lead to very expensive communication.

2. Shamir sharing: We use this option to allow for multiple parties (minority) to drop out from the decryption and still be able to decrypt with $t$-out-of-N where $t > N/2$.

The unittest [UnitTestMultiparty](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/unittest/UnitTestMultiparty.cpp) has a small example that uses these functions for threshold computation with 3 parties.
