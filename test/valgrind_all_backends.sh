
backends="2 4 6"

if [ "$1" != "" ];
then
	backends=$1
fi

for i in $backends
do
	ex=bin/backend-$i/unittest/tests

	echo "****************************"
	echo valgrind MATHBACKEND $i
	echo "****************************"
	if [[ -x $ex ]]
	then
		(
			# set paths for mac or linux or win
		export DYLD_LIBRARY_PATH=bin/backend-$i/lib:third-party/lib:$DYLD_LIBRARY_PATH
		export LD_LIBRARY_PATH=bin/backend-$i/lib:third-party/lib:$LD_LIBRARY_PATH
		export PATH=bin/backend-$i/lib:third-party/lib:$PATH
		valgrind --log-file=valgrind-backend-$i.out $ex -t
		)
		echo "****************************"
		echo valgrind DONE
		echo "****************************"
	else
		echo " ******** $ex for MATHBACKEND $i not found"
	fi
done
