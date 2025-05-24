#!/bin/bash
# ============================================================================
# HERMES MySQL UDF Plugin: Build + Deployment + Encrypted Query Test Pipeline
# ----------------------------------------------------------------------------
# Author: Dr. Dongfang Zhao (dzhao@cs.washington.edu)
# Last Updated: 2025
#
# Description:
# This script automates the end-to-end workflow of building, installing,
# and testing a set of MySQL User Defined Functions (UDFs) for homomorphic
# encryption using the OpenFHE library and BFV scheme. It compiles the plugin,
# sets up environment dependencies, configures MySQL to load OpenFHE, and runs
# a series of tests on encrypted data stored and queried within MySQL tables.
#
# Key Capabilities:
# - CMake-based build and install of the OpenFHE-enabled MySQL plugin.
# - AppArmor workaround and systemd LD_LIBRARY_PATH injection for OpenFHE.
# - Initializes MySQL test tables and registers UDFs automatically.
# - Demonstrates:
#     - Plaintext-to-ciphertext encryption (single-slot BFV).
#     - Base64 serialization and ciphertext storage.
#     - Ciphertext decryption with plaintext recovery.
#     - Homomorphic aggregation via real SQL GROUP BY and UDF aggregation.
#
# UDFs Supported:
# - HERMES_ENC_SINGULAR_BFV(int) → base64 ciphertext string
# - HERMES_DEC_SINGULAR_BFV(base64) → int
# - HERMES_SUM_BFV(base64) → SQL aggregate: returns int
#
# Dependencies:
# - OpenFHE library compiled with serialization support
# - MySQL (server with plugin support)
# - Bash-compatible Linux environment
#
# Note:
# This pipeline is part of the HERMES system prototype for enabling encrypted
# data ingestion and vector computation within relational databases using
# homomorphic encryption.
# ============================================================================
set -e

# 配置
MYSQL_USER="hpdic"
MYSQL_PASS="hpdic2023"

PLUGIN_NAME="libhpdic_hermes_singular.so"
UDF_NAME="HERMES_ENC_SINGULAR"

# 工程路径
SRC_DIR="$(pwd)/../../../"
BUILD_DIR="${SRC_DIR}/build"
PLUGIN_OUTPUT_DIR="${BUILD_DIR}/lib/mysqlplugin"
OPENFHE_CORE_LIB_DIR="${BUILD_DIR}/lib"
PLUGIN_DIR="/usr/lib/mysql/plugin"

# systemd 环境配置
SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/mysql.service.d"
SYSTEMD_OVERRIDE_FILE="${SYSTEMD_OVERRIDE_DIR}/openfhe-env.conf"

echo "[*] Step 0: CMake 配置和构建..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake .. \
  -DCMAKE_INSTALL_PREFIX=/usr/local \
  -DWITH_BINFHE=ON \
  -DWITH_SERIALIZATION=ON \
  -DCMAKE_BUILD_TYPE=Release
make -j $(nproc)
sudo make install

echo "[*] Step 1: 拷贝插件和 OpenFHE 依赖到 MySQL 插件目录..."
sudo cp -v "${PLUGIN_OUTPUT_DIR}/${PLUGIN_NAME}" "${PLUGIN_DIR}"
sudo cp -v ${OPENFHE_CORE_LIB_DIR}/libOPENFHE*.so* "${PLUGIN_DIR}"

echo "[*] Step 2: 解除 AppArmor（如存在）..."
if [ -e /etc/apparmor.d/usr.sbin.mysqld ]; then
    sudo ln -sf /etc/apparmor.d/usr.sbin.mysqld /etc/apparmor.d/disable/ || true
    sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.mysqld || echo "[!] AppArmor 未完全清除，可能已处理过"
else
    echo "  [✓] 未检测到 AppArmor 配置，跳过"
fi

echo "[*] Step 3: 设置 MySQL 的 LD_LIBRARY_PATH..."
sudo mkdir -p "${SYSTEMD_OVERRIDE_DIR}"
sudo tee "${SYSTEMD_OVERRIDE_FILE}" >/dev/null <<EOF
[Service]
Environment=LD_LIBRARY_PATH=${PLUGIN_DIR}
EOF

echo "[*] Step 4: 重启 MySQL..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl restart mysql

echo "[*] Step 5: 初始化测试表 hpdic_db.employee ..."
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" <<EOF
CREATE DATABASE IF NOT EXISTS hpdic_db;
USE hpdic_db;

DROP TABLE IF EXISTS employee;
CREATE TABLE employee (
    id INT PRIMARY KEY,
    name VARCHAR(50),
    salary INT
);
INSERT INTO employee (id, name, salary) VALUES
    (1, 'Alice', 5200),
    (2, 'Bob', 4800);
EOF

echo "[*] Step 6: 注册并调用插件函数 ${UDF_NAME} ..."
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" <<EOF
USE hpdic_db;

DROP FUNCTION IF EXISTS ${UDF_NAME};
CREATE FUNCTION ${UDF_NAME} RETURNS STRING SONAME '${PLUGIN_NAME}';

SELECT id, name, ${UDF_NAME}(salary) AS enc_salary FROM employee;
EOF

echo "[✓] 插件 ${PLUGIN_NAME} 编译 + 部署 + 测试全部完成"

# ===========================================
# ✅ Step 7: Materialize Encrypted Table
# ===========================================

echo "[*] Step 7: 加密字段并生成 employee_enc 表 ..."
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" <<EOF
USE hpdic_db;

-- 创建新表（如已存在则重建）
DROP TABLE IF EXISTS employee_enc;
CREATE TABLE employee_enc (
    id INT,
    name VARCHAR(255),
    enc_salary TEXT
);

-- 插入加密数据
INSERT INTO employee_enc (id, name, enc_salary)
SELECT id, name, ${UDF_NAME}(salary)
FROM employee;

-- 可选：查看加密表内容
SELECT * FROM employee_enc LIMIT 5;
EOF

echo "[✓] 已完成加密表 employee_enc 的生成和填充"

# ===========================================
# ✅ Step 8: Test HERMES_ENC_SINGULAR_BFV 密文输出
# ===========================================

echo "[*] Step 8: 测试新的 UDF hermes_enc_singular_bfv 返回密文（base64 编码）..."
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" <<EOF
USE hpdic_db;

-- ✅ 注册新函数（只需执行一次，但为了脚本幂等可放这里）
DROP FUNCTION IF EXISTS HERMES_ENC_SINGULAR_BFV;
CREATE FUNCTION HERMES_ENC_SINGULAR_BFV RETURNS STRING SONAME '${PLUGIN_NAME}';

-- 单独调用新函数查看输出
SELECT id, name, salary, LEFT(HERMES_ENC_SINGULAR_BFV(salary), 16) AS enc_bfv_preview16
FROM employee;

-- 可选：将 base64 密文插入新表验证落库兼容性
DROP TABLE IF EXISTS employee_enc_bfv;
CREATE TABLE employee_enc_bfv (
    id INT,
    name VARCHAR(255),
    salary_enc_bfv LONGTEXT
);

INSERT INTO employee_enc_bfv (id, name, salary_enc_bfv)
SELECT id, name, HERMES_ENC_SINGULAR_BFV(salary)
FROM employee;

SELECT id, name, LEFT(salary_enc_bfv, 16) FROM employee_enc_bfv LIMIT 5;
EOF

echo "[✓] hermes_enc_singular_bfv 测试完成，密文成功插入 employee_enc_bfv 表"

# ===========================================
# ✅ Step 9: Test HERMES_DEC_SINGULAR_BFV 解密函数
# ===========================================

echo "[*] Step 9: 测试新的 UDF hermes_dec_singular_bfv 解密密文回原始明文..."
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" <<EOF
USE hpdic_db;

-- ✅ 注册解密函数（幂等）
DROP FUNCTION IF EXISTS HERMES_DEC_SINGULAR_BFV;
CREATE FUNCTION HERMES_DEC_SINGULAR_BFV RETURNS INTEGER SONAME '${PLUGIN_NAME}';

-- ✅ 查询加密 + 解密对比，验证 round-trip correctness
SELECT
    id,
    name,
    HERMES_DEC_SINGULAR_BFV(salary_enc_bfv) AS salary_plain
FROM employee_enc_bfv
LIMIT 5;
EOF

echo "[✓] hermes_dec_singular_bfv 测试完成，解密成功验证"

# ===========================================
# ✅ Step 10: Test HERMES_SUM_BFV 密文聚合支持 GROUP BY
# ===========================================

echo "[*] Step 10: 注册并测试聚合解密函数 hermes_sum_bfv + GROUP BY ..."

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" <<EOF
USE hpdic_db;

-- ✅ 注册聚合函数（幂等）
DROP FUNCTION IF EXISTS HERMES_SUM_BFV;
CREATE AGGREGATE FUNCTION HERMES_SUM_BFV RETURNS INTEGER SONAME '${PLUGIN_NAME}';

-- ✅ 创建含 department 字段的新表
DROP TABLE IF EXISTS employee_enc_grouped;
CREATE TABLE employee_enc_grouped (
    id INT,
    name VARCHAR(255),
    department VARCHAR(64),
    salary_enc_bfv LONGTEXT
);

-- ✅ 插入两个部门的密文员工数据（HR, ENG 各两人）
INSERT INTO employee_enc_grouped (id, name, department, salary_enc_bfv)
VALUES
  (1, 'Alice', 'HR',  HERMES_ENC_SINGULAR_BFV(5200)),
  (2, 'Bob',   'HR',  HERMES_ENC_SINGULAR_BFV(4800)),
  (3, 'Carol', 'ENG', HERMES_ENC_SINGULAR_BFV(6000)),
  (4, 'Dave',  'ENG', HERMES_ENC_SINGULAR_BFV(5900));

-- ✅ 分组聚合解密：每个部门的工资总和
SELECT department, HERMES_SUM_BFV(salary_enc_bfv) AS total_salary
FROM employee_enc_grouped
GROUP BY department 
ORDER BY department desc;
EOF

echo "[✓] hermes_sum_bfv + GROUP BY 测试完成，按部门解密总和成功"