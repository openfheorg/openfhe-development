
smallbmargs="--benchmark_report_aggregates_only=true --benchmark_format=csv"
largebmargs="--benchmark_repetitions=20 --benchmark_report_aggregates_only=true --benchmark_format=csv"

backends="2 4 6"

if [ "$1" != "" ];
then
	backends=$1
fi

for i in $backends
do
	(
	BINDIR=bin/backend-$i
	BMDIR=$BINDIR/benchmark

	export DYLD_LIBRARY_PATH=bin/backend-$i/lib:third-party/lib:$DYLD_LIBRARY_PATH
	export LD_LIBRARY_PATH=bin/backend-$i/lib:third-party/lib:$LD_LIBRARY_PATH
	export PATH=bin/backend-$i/lib:third-party/lib:$PATH

	echo "****************************"
	echo "Benchmarking MATHBACKEND $i"
	echo "****************************"

	for bm in BigIntegerMath NativeIntegerMath BigVectorMath NativeVectorMath NbTheory Lattice LatticeNative
	do
		echo $bm:
		"$BMDIR/${bm}" "${smallbmargs}"
	done

	for bm in Encoding Crypto SHE
	do
		echo $bm:
		"$BMDIR/${bm}" "${largebmargs}"
	done

	echo "****************************"
	echo DONE
	echo "****************************"
	)
done
