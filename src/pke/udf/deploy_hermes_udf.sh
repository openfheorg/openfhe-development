#!/bin/bash
set -e

MYSQL_USER="hpdic"
MYSQL_PASS="hpdic2023"

PLUGIN_NAME="libhpdic_hermes.so"
PLUGIN_DIR="/usr/lib/mysql/plugin"
OPENFHE_PLUGIN_LIB_DIR="$(pwd)/../../../build/lib/mysqlplugin"
OPENFHE_CORE_LIB_DIR="$(pwd)/../../../build/lib"

SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/mysql.service.d"
SYSTEMD_OVERRIDE_FILE="${SYSTEMD_OVERRIDE_DIR}/openfhe-env.conf"

echo "[*] Step 1: Copy shared object and OpenFHE libs into MySQL plugin directory..."
sudo cp -v "${OPENFHE_PLUGIN_LIB_DIR}/${PLUGIN_NAME}" "${PLUGIN_DIR}"

# Copy OpenFHE core libraries
sudo cp -v ${OPENFHE_CORE_LIB_DIR}/libOPENFHE*.so* "${PLUGIN_DIR}"

echo "[*] Step 2: Disable AppArmor for mysqld..."
if [ -e /etc/apparmor.d/usr.sbin.mysqld ]; then
    sudo ln -sf /etc/apparmor.d/usr.sbin.mysqld /etc/apparmor.d/disable/ || true
    sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.mysqld || echo "[!] Warning: AppArmor profile removal reported already removed."
else
    echo "  [✓] No AppArmor profile found for mysqld. Skipping."
fi

echo "[*] Step 3: Set LD_LIBRARY_PATH for MySQL via systemd override..."
sudo mkdir -p "${SYSTEMD_OVERRIDE_DIR}"
sudo tee "${SYSTEMD_OVERRIDE_FILE}" >/dev/null <<EOF
[Service]
Environment=LD_LIBRARY_PATH=${PLUGIN_DIR}
EOF

echo "[*] Step 4: Reload systemd and restart MySQL..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl restart mysql

echo "[*] Step 5: Register UDF in MySQL..."
mysql -u "${MYSQL_USER}" -p"${MYSQL_PASS}" <<EOF
DROP FUNCTION IF EXISTS hermes_udf;
CREATE FUNCTION hermes_udf RETURNS INTEGER SONAME '${PLUGIN_NAME}';
SELECT hermes_udf();
EOF