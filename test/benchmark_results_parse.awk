function quote(str) {
	return "\"" str "\""
}

BEGIN {
	C=","
	backend=""
	runOn=""
	datestamp=""

	lead="platform,backend,runOn,datestamp"
	fields="name,iterations,real_time,cpu_time,time_unit,bytes_per_second,items_per_second,label,error_occurred,error_message"
	cmd="INSERT INTO benchmarks (" lead C fields ")"

	unquoted[1]=1
	unquoted[8]=1
}

$1 == "Run" && $2 == "on" {
	runOn = quote( $0 )
	getline datestamp
	datestamp = quote( datestamp )
	plat = quote(platform)
	next
}

$1 == "Benchmarking" && $2 == "MATHBACKEND" {
	backend = quote($3)
	next
}

$0 == fields || $0 == "****************************" || $0 == "DONE" || $1 ~ /:$/ || $0 ~ /No such file or/ {
	next
}

{
	ne=split($0,items,",")
	if( ne != 10 ) next

	str = cmd " VALUES (" plat C backend C runOn C datestamp

	for(i=1; i<=ne; i++)
		if( i in unquoted && length(items[i]) != 0 )
			str = str C items[i]
		else
			str = str C quote(items[i])
	str = str ");"

	print str
}
