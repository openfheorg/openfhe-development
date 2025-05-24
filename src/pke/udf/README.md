/==============================================\
|          HPDIC MOD: Project Hermes           |
|         OpenFHE + MySQL Integration          |
|           dzhao@cs.washington.edu            |
\==============================================/

This directory contains a MySQL UDF plugin named HERMES_ENC_SINGULAR, developed using
the OpenFHE library (BFV scheme). The plugin demonstrates native homomorphic encryption
over integer inputs inside MySQL queries, with debug string output for verification.

-------------------------------------------------------------------------------
FILES IN THIS DIRECTORY
-------------------------------------------------------------------------------

  hpdic_hermes_encsingular.cpp
      Core plugin implementation. Registers a UDF named HERMES_ENC_SINGULAR,
      encrypts a single INT input using OpenFHE BFV, and returns a debug string
      (pointer + decrypted value + ciphertext size).

  test_encsingular.sh
      One-click test script. Builds the plugin, copies the .so and OpenFHE libs
      to the MySQL plugin directory, injects LD_LIBRARY_PATH via systemd,
      restarts MySQL, creates a test table, registers the UDF, and runs a SELECT query.

  deploy_hermes_noinput.sh
      Alternate setup script for testing a plugin that does not take input
      (used for isolated plugin loading tests).

  register_hermes_udf.sql
      SQL script to DROP + CREATE the UDF inside MySQL.

  tbl_create_employee.sh
      Initializes a toy table `employee(id, name, salary)` with example data.

  README.md
      This file.

-------------------------------------------------------------------------------
HOW TO RUN
-------------------------------------------------------------------------------

From this directory, execute:

    ./test_encsingular.sh

This will compile the plugin, set up the MySQL runtime environment, and run:

    SELECT id, name, CAST(HERMES_ENC_SINGULAR(salary) as CHAR) FROM employee;

You should see output like:

    +----+-------+--------------------------------------------+
    | id | name  | HERMES_ENC_SINGULAR(salary)                |
    +----+-------+--------------------------------------------+
    |  1 | Alice | 0x7fae0001b2c0 (5200, size=136)            |
    |  2 | Bob   | 0x7fae0001b2c0 (4800, size=136)            |
    +----+-------+--------------------------------------------+

Each output is a debug string showing:
  - the ciphertext pointer (only valid within this process)
  - the decrypted plaintext (verification)
  - the internal ciphertext object size in bytes

-------------------------------------------------------------------------------
NOTES
-------------------------------------------------------------------------------

- This is a research prototype, not a secure or persistent encryption layer.
- Ciphertexts are not serialized or stored between queries.
- All cryptographic state is held globally in memory and reused.

-------------------------------------------------------------------------------
CONTACT
-------------------------------------------------------------------------------

Dongfang Zhao  
HPDIC Lab, University of Washington  
Email: dzhao@cs.washington.edu  
Website: https://faculty.washington.edu/dzhao