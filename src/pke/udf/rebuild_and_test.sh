#!/bin/bash
set -e

# Resolve current script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(realpath "${SCRIPT_DIR}/../../../")"
BUILD_DIR="${PROJECT_ROOT}/build"
UDF_CPP_PATH="${PROJECT_ROOT}/src/pke/udf/hpdic_hermes.cpp"
DEPLOY_SCRIPT="${PROJECT_ROOT}/src/pke/udf/deploy_hermes_udf.sh"
MYSQL_TEST_SQL="/tmp/hermes_udf_test.sql"
MYSQL_USER="hpdic"
MYSQL_PASS="hpdic2023"

echo "[*] Project root: ${PROJECT_ROOT}"
echo "[*] Build dir: ${BUILD_DIR}"
echo "[*] UDF source: ${UDF_CPP_PATH}"

# Step 0: Validate
if [ ! -f "${UDF_CPP_PATH}" ]; then
    echo "[!] Source file not found: ${UDF_CPP_PATH}"
    exit 1
fi

# Step 1: Rebuild
echo "[*] Rebuilding OpenFHE plugin..."
cd "${BUILD_DIR}"
make -j $(nproc)

# Step 2: Re-deploy
echo "[*] Deploying updated .so to MySQL plugin directory..."
cd "${PROJECT_ROOT}/src/pke/udf"
bash "${DEPLOY_SCRIPT}"

# Step 3: Register UDF and test
echo "[*] Registering UDF and executing test query..."

cat <<EOF > ${MYSQL_TEST_SQL}
DROP FUNCTION IF EXISTS hermes_udf;
CREATE FUNCTION hermes_udf RETURNS INTEGER SONAME 'libhpdic_hermes.so';
SELECT hermes_udf();
EOF

mysql -u "${MYSQL_USER}" -p"${MYSQL_PASS}" < "${MYSQL_TEST_SQL}"
rm -f "${MYSQL_TEST_SQL}"