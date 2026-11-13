# Building applications with OpenFHE

This directory is a guide for AI coding agents, and for people, writing a C++ application on top of OpenFHE. It
describes OpenFHE 1.6. To change the library itself, read `AGENTS.md` in the repository root instead.

Read this file first, then the reference file for the scheme you pick.

## Workflow

1. Choose a scheme from the table below.
2. Write the computation in the clear first. From it, read off the multiplicative depth, the rotation indices and the
   range of the values.
3. Copy `template/` and check that it builds and runs before changing it. Its `CMakeLists.txt` works unchanged for
   every scheme, including binfhe. Its `main.cpp` is a CKKS program; for another scheme keep the structure and take
   the code from that scheme's reference file.

   ```bash
   mkdir build && cd build
   cmake -DCMAKE_PREFIX_PATH=<OpenFHE install prefix> ..
   make && ./app
   ```
4. Set the parameters, enable the features and generate the keys the computation needs.
5. Run on small inputs and compare the decrypted result with the cleartext result. Keep this check as a test.
6. Only then add serialization, a client/server split, or several parties.

## Choosing a scheme

| The application needs | Use | Read |
|---|---|---|
| Exact integer arithmetic on vectors, modulo a plaintext modulus | BFV or BGV | `reference/bfv-bgv.md` |
| Approximate arithmetic on real or complex vectors: statistics, ML inference | CKKS | `reference/ckks.md` |
| Boolean gates, comparisons or lookup tables on bits and small integers | binfhe | `reference/binfhe.md` |
| Unbounded depth on real numbers | CKKS with bootstrapping | `reference/ckks.md` |
| A key shared by several parties | threshold FHE | `reference/multiparty.md` |
| Re-encrypting to another party's key without decrypting | proxy re-encryption | `reference/multiparty.md` |

`reference/choosing-a-scheme.md` covers the borderline cases, such as comparisons inside a CKKS computation.

Other reference files:

- `reference/serialization.md` – sending contexts, keys and ciphertexts between processes
- `reference/troubleshooting.md` – wrong results, exceptions, slow runs
- `reference/examples-index.md` – which example program shows which task

## Rules

Enable every feature the computation uses, before generating keys. Most operations throw when their feature is
missing, and the message names it.

| Feature | Needed for |
|---|---|
| `PKE` | key generation, encryption, decryption |
| `KEYSWITCH` | key switching, which relinearization and rotation rely on |
| `LEVELEDSHE` | addition, multiplication, rotation and their key generation |
| `ADVANCEDSHE` | `EvalSum`, `EvalInnerProduct`, `EvalPoly`, `EvalChebyshevFunction`, `EvalLogistic`, `EvalMultMany` |
| `FHE` | CKKS bootstrapping and functional bootstrapping |
| `MULTIPARTY` | threshold FHE |
| `PRE` | proxy re-encryption |
| `SCHEMESWITCH` | switching between CKKS and binfhe |

Generate keys before using them. Multiplying two ciphertexts needs `EvalMultKeyGen`. Each rotation index needs a key
from `EvalRotateKeyGen`. A missing key throws.

Set the multiplicative depth to the deepest chain of multiplications in the computation, not the number of
multiplications. Going past it fails differently per scheme:

- BFV decrypts to wrong values with no error.
- BGV throws at the operation that runs out of levels ("Too few towers to support ModReduce").
- CKKS normally throws at `Decrypt` with "approximation error is too high".

BFV and BGV compute modulo the plaintext modulus `t`, on signed values from `-(t-1)/2` to `(t-1)/2`. A result outside
that range wraps around with no error. Pick a modulus larger than twice the largest absolute value of any intermediate
result.

CKKS is approximate. Compare results with a tolerance, and call `SetLength` on the decrypted plaintext before reading
it.

Use `HEORG24_128` as the security level for new applications: 128-bit security according to the 2024 Security
Guidelines for Implementing Homomorphic Encryption. The default, `HEStd_128_classic`, uses the older Homomorphic
Encryption Standard tables and is kept for compatibility. Let the library choose the ring dimension. `HEStd_NotSet`
turns the security check off and is for experiments only.

Include `openfhe.h` for BFV, BGV and CKKS, and `binfhecontext.h` for binfhe. Serialization needs extra headers; see
`reference/serialization.md`.

Build in Release mode. A Debug build is much slower.

## Examples

The example programs are in the OpenFHE source tree under `src/pke/examples` and `src/binfhe/examples`
(https://github.com/openfheorg/openfhe-development). They are not part of an installation, so fetch them from the
repository when the source tree is not at hand. Each is a single self-contained program. `reference/examples-index.md`
maps tasks to them.

## Using this guide with a coding agent

This directory is a skill in the `SKILL.md` format that Claude Code, Codex and Gemini CLI all load. Once it is
installed, the agent reads the guide whenever a task involves OpenFHE. `<guide>` below is the absolute path of this
directory: `<install prefix>/share/openfhe/agents` after `make install`, or `<checkout>/agents` in the source tree.

Claude Code, as a plugin:

```
/plugin marketplace add openfheorg/openfhe-development
/plugin install openfhe@openfhe
```

Codex and Gemini CLI, as a skill for your user account:

```bash
mkdir -p ~/.agents/skills
ln -s <guide> ~/.agents/skills/openfhe
```

The path must be absolute; a relative one makes a broken link.

Use `.agents/skills/openfhe` inside a project instead to share it with everyone who works on that project. Claude
Code also accepts the directory as a skill, at `~/.claude/skills/openfhe`.

Any other agent: add one line to the instruction file it reads, such as `AGENTS.md`:

```
For any work with OpenFHE, read <guide>/README.md first and follow it.
```
