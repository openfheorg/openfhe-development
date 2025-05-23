#!/bin/bash

# 配置
USER="hpdic"
PASS="hpdic2023"
DB="hpdic_db"

# 初始化数据库和测试表
mysql -u "$USER" -p"$PASS" -e "
-- 创建数据库（如果不存在）
CREATE DATABASE IF NOT EXISTS $DB;
USE $DB;

-- 删除旧表（如果存在）
DROP TABLE IF EXISTS employee;

-- 创建新表
CREATE TABLE employee (
    id INT PRIMARY KEY,
    name VARCHAR(50),
    salary INT
);

-- 插入两行数据
INSERT INTO employee (id, name, salary) VALUES
    (1, 'Alice', 5200),
    (2, 'Bob', 4800);
SELECT * FROM employee;

-- 测试插件函数
-- SELECT id, name, HERMES_ENC_SINGULAR(salary) AS enc_salary
-- FROM employee;
"