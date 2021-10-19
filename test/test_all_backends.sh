
backends="2 4 6"

if [ "$1" != "" ];
then
	backends=$1
fi
if [ "$2" != "" ];
then
	nloops=$2
else
	nloops=1
fi

if [ "$3" != "" ];
then
	gtestargs=$3
fi

for i in $backends
do
	ex=bin/backend-$i/unittest/tests

	echo "*************************************"
	echo Testing MATHBACKEND $i $nloops Iterations
	echo "*************************************"
	if [[ -x $ex ]]
	then
		(
			# set paths for mac or linux or win
		export DYLD_LIBRARY_PATH=bin/backend-$i/lib:third-party/lib:$DYLD_LIBRARY_PATH
		export LD_LIBRARY_PATH=bin/backend-$i/lib:third-party/lib:$LD_LIBRARY_PATH
		export PATH=bin/backend-$i/lib:third-party/lib:$PATH
		echo $ex -t --gtest_repeat=$nloops $gtestargs |tee testout.be$i
		$ex -t --gtest_repeat=$nloops $gtestargs |tee testout.be$i
		)
		echo "****************************"
		echo TEST DONE
		echo "****************************"
	else
		echo " ******** $ex for MATHBACKEND $i not found"
	fi
done
