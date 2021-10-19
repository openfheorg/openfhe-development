function quote(str) {
	return "\"" str "\""
}

BEGIN {
	C=","
	hdr = "******"
	backend=""
	cmd="INSERT INTO test_status (platform,backend,date,cases,passed)"
}

$1 == hdr && $2 == "Date" {
	datestamp = quote($3)
}

$1 == hdr && $2 == "Begin" && $3 == "Backend" {
	backend = quote($4)
}

$1 == hdr && $2 == "End" {
	print cmd, "VALUES ('PLATFORM'" C backend C datestamp C $5 C $3 ");"
	backend = ""
}

END {
	if( backend != "" )
		print cmd, "VALUES ('PLATFORM'" C backend C datestamp C 0 C 0 ");"
}
