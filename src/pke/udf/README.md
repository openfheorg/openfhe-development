/==============================================\
|          HPDIC MOD: Project Hermes           |
|         OpenFHE + MySQL Integration          |
|           <dzhao@cs.washington.edu>          |
\==============================================/

This directory contains a MySQL UDF plugin module named **Hermes_Singular**, built using
the OpenFHE library (BFV scheme). It demonstrates how single-slot homomorphic encryption
can be natively integrated into relational queries, including encryption, decryption, and
homomorphic evaluation operations inside MySQL.

-------------------------------------------------------------------------------

SUPPORTED UDFs (BFV, single-slot)
-------------------------------------------------------------------------------

The plugin registers the following UDFs:

- `HERMES_ENC_SINGULAR_BFV(INT)` → `LONGTEXT`  
  Encrypts a single integer into a base64-encoded BFV ciphertext.

- `HERMES_DEC_SINGULAR_BFV(LONGTEXT)` → `INT`  
  Decrypts a base64-encoded ciphertext and returns the original plaintext.

- `HERMES_SUM_BFV(LONGTEXT)` → `INT`  
  Aggregates ciphertexts using homomorphic addition and returns the decrypted total.
  Fully supports `GROUP BY` SQL queries as a native aggregate function.

- `HERMES_ENC_SINGULAR(INT|STRING)` → `STRING`  
  A debug-only variant that returns internal memory address, decrypted value,
  and ciphertext size as a printable string. Useful for pointer debugging and tracing.

-------------------------------------------------------------------------------

FILES IN THIS DIRECTORY
-------------------------------------------------------------------------------

- `hpdic_hermes_singular.cpp`  
  Main plugin source file. Implements the BFV-based UDFs with MySQL loadable function interface.

- `test_singular.sh`  
  One-click setup + demo script. Compiles the plugin, installs shared objects,
  configures MySQL environment, and runs full encryption/decryption/aggregation tests.

- `deploy_hermes_noinput.sh`  
  Minimal plugin load check (for `no-input` UDFs or debugging deployment issues).

- `register_hermes_udf.sql`  
  Registers the plugin’s UDFs inside MySQL via SQL commands.

- `tbl_create_employee.sh`  
  Initializes a demo table `employee(id, name, salary)` with sample values.

- `README.md`  
  This file.

-------------------------------------------------------------------------------

HOW TO RUN
-------------------------------------------------------------------------------

Simply execute:

```bash
./test_singular.sh
```

This will:

1. Build and install the plugin + OpenFHE shared libs.
2. Patch MySQL systemd service to support dynamic OpenFHE linkage.
3. Restart MySQL with new environment.
4. Register and invoke the following test queries:

#### Encrypt + insert

```sql
INSERT INTO employee_enc_bfv (id, name, salary_enc_bfv)
SELECT id, name, HERMES_ENC_SINGULAR_BFV(salary)
FROM employee;
```

#### Decrypt

```sql
SELECT id, name, HERMES_DEC_SINGULAR_BFV(salary_enc_bfv) AS salary_plain
FROM employee_enc_bfv;
```

#### Homomorphic sum

```sql
SELECT department, HERMES_SUM_BFV(salary_enc_bfv) AS total_salary
FROM employee_enc_grouped
GROUP BY department;
```

Expected output:

```
+-------------+--------------+
| department  | total_salary |
+-------------+--------------+
| ENG         |        11900 |
| HR          |        10000 |
+-------------+--------------+
```

-------------------------------------------------------------------------------

NOTES
-------------------------------------------------------------------------------

- This is a research prototype for **single-slot BFV** encryption. It does not yet support:
  - Multi-slot packed encodings
  - Rotation / EvalSum / SIMD slotwise operations
  - External key management or key separation

- All cryptographic state (context, keys) is stored statically in plugin memory.

- Base64 is used for serialization to ensure compatibility with `TEXT` and `LONGTEXT` SQL types.

- This prototype enables **true encrypted SQL workflows** inside MySQL, including encrypted insert, select, group-by aggregation, and round-trip decryption.

-------------------------------------------------------------------------------

CONTACT
-------------------------------------------------------------------------------

Dongfang Zhao  
High-Performance Data Intelligence Computing (HPDIC) Lab  
University of Washington  
Email: <dzhao@cs.washington.edu>  
Website: <https://faculty.washington.edu/dzhao>
