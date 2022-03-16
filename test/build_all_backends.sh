
backends="2 4 6"

if [ "$1" != "" ];
then
	backends=$1
else
	for i in $backends
	do
		rm -fr bin/backend-$i
	done
fi

echo "****************************"
echo Building backends $backends
echo "****************************"

for i in $backends
do
	echo "****************************"
	echo Building MATHBACKEND $i
	echo "****************************"

	touch ../src/core/lib/math/backend.h
	result=build-backend-$i-result

	make -j8  BINDIR=bin/backend-$i BACKEND=$i all benchmark >build-backend-$i-result 2>&1
	if [ $? -eq 0 ];
	then
		echo "****************************"
		echo BUILT
		echo "****************************"
		rm -f $result
	else
		echo " ******** build for MATHBACKEND $i failed!!! result is in " $result
	fi
done
