DROP FUNCTION IF EXISTS hermes_udf;
CREATE FUNCTION hermes_udf RETURNS STRING SONAME 'libhpdic_hermes.so';