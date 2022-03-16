
backends="2 4 6"

if [ "$1" != "" ];
then
	backends=$1
fi

for i in $backends
do
	lib=bin/backend-${i}-cov/lib
	ex=bin/backend-${i}-cov/unittest/tests

	echo "****************************"
	echo Coverage test MATHBACKEND $i
	echo "****************************"
	if [[ -x $ex ]]
	then
		(
			# set paths for mac or linux or win
		export DYLD_LIBRARY_PATH=$lib:third-party/lib:$DYLD_LIBRARY_PATH
		export LD_LIBRARY_PATH=$lib:third-party/lib:$LD_LIBRARY_PATH
		export PATH=$lib:third-party/lib:$PATH
		$ex -t

		lcov -q --capture --directory bin/backend-${i}-cov -o bin/backend-${i}-cov/coverage.full.out
		lcov -q --remove bin/backend-${i}-cov/coverage.full.out '/usr/include/*' '/opt/local/*' '*rapidjson*' '*/test/include/gtest/*' -o bin/backend-${i}-cov/coverage.out
		genhtml -q -o bin/backend-${i}-cov/html bin/backend-${i}-cov/coverage.out
		)
		echo "****************************"
		echo COVERAGE TEST DONE
		echo "****************************"
	else
		echo " ******** $ex for MATHBACKEND $i not found"
	fi
done

genhtml -q -o bin/cov bin/backend-*-cov/coverage.out
