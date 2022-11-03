# Static Estimation
Here we describe static noise estimation in FHE and how it relates
to noise flooding. We focus on CKKS, but the same applies to
threshold decryption in [threshold FHE](https://link.springer.com/chapter/10.1007/978-3-642-29011-4_29).

# Li and Micciancio's CKKS attack
[Li and Micciancio](https://link.springer.com/chapter/10.1007/978-3-030-77870-5_23) showed that 
approximate FHE schemes (e.g., CKKS) can leak information about the secret key.
In short, CKKS decryptions give
direct access to the secret key given a ciphertext and a decryption
since the user gets $\mathsf{ct} = (as + m + e, -a)$ and its decryption is $m+e$.
Therefore, we can recover the secret $s$ given the above and we should
always think of the RLWE ciphertext error as part of the secret key.

# Solution: Noise Flooding
One solution to the above issue is to change the decryption algorithm
in CKKS to add [additional error to the output](https://link.springer.com/chapter/10.1007/978-3-031-15802-5_20). That is, given a
CKKS ciphertext $\mathsf{ct} = (c_0, c_1)$, decryption is a \emph{randomized}
procedure given as $$\mathsf{Dec}(\mathsf{ct}): \text{ Sample } z \gets D_{R, \sigma}.\text{ Return } c_0 + c_1s + z \pmod q$$
where $D_{R, \sigma}$ is a discrete gaussian over the polynomial ring,
represented in its coefficient form, and 
$\sigma$ is a standard deviation set by a security level
and the noise estimate. If we want $s>0$ bits of statistical
security, then the standard deviation is
$$\sigma = \sqrt{12\tau}2^{s/2}\mathsf{ct}.t$$
where $\tau$ is the number of adversarial queries the application
is expecting and $\mathsf{ct}.t$ is the ciphertext error estimate (described below).
For the statistical security parameter $s$, one would want this to be
at least $30$, which would bound any (potentially inefficient)
adversary's success probability to at most $2^{-30}$, or about one in
a billion [^1].
Note that this is the same as "noise-smudging" in [threshold FHE](https://link.springer.com/chapter/10.1007/978-3-642-29011-4_29) but has a much
tighter analysis.

# Static Noise Estimation
Notice that the number of queries $\tau$ and the statistical security $s$
in the equation for $\sigma$ are determined by the application or user.
However, the ciphertext noise bound is difficult to determine before
the homomorphic computation is performed. This is because CKKS noise
growth depends on the input message as soon as the computation
involves a multiplication.

# Noise Flooding and Static Estimation in OpenFHE
OpenFHE enables the user to do the following for static estimation, i.e. 
determining a good bound for $\mathsf{ct}.t$.
1. It first runs the computation on a fresh secret key-public key
pair, independent of the user's key pair, and a message determined
by the user. Here, the user can use the actual message or a
message picked from a suitable set of messages (representing
real data the homomorphic computation is supposed to be computed on).
2. OpenFHE estimates the error in the computation by measuring
the noise/precision-loss in the imaginary slots of the decrypted
plaintext. [Costache et al.](https://eprint.iacr.org/2022/162) argue that this method accurately estimates noise growth in
FHE according to their heuristics and experiments. It also
has long been used in PALISADE. Note, this means that
OpenFHE only supports real number arithmetic in CKKS.
The parameter $\mathsf{ct}.t$ is now set according to this estimate.
We call this step the
$\mathsf{EXEC}\textunderscore\mathsf{NOISE}\textunderscore\mathsf{ESTIMATION}$ execution mode.
3. Finally, OpenFHE runs the actual computation, with the
users ciphertexts under her secret key, and applies
noise flooding with discrete gaussian noise with
standard deviation $\sigma = \sqrt{12\tau}2^{s/2}\mathsf{ct}.t$.
We call this mode $\mathsf{EXEC}\textunderscore\mathsf{EVALUATION}$.

The code for this procedure is in
  src/examples/pke/ckks-noise-flooding.cpp
in OpenFHE. 
For leveled computations, the code allows for the user to run the 
static estimation using 64-bit CKKS and the actual computation in 128-bit CKKS.

[^1]:The formula for $\sigma$ in Corollary 2 of [the state of the art in noise flooding security](https://link.springer.com/chapter/10.1007/978-3-031-15802-5_20) has an incorrect $\sqrt{2n}$ factor since the indistinguishablility game is played over the coefficient embedding.
