#!/bin/bash
while getopts ":r:j:t:" OPTION
do
	case $OPTION in
		t)
			TAG=$OPTARG;;
		j)
			THREADS=$OPTARG;;
		r)
			REPOSITORY=$OPTARG;;

		\?)
			echo "Please use the -r tag to set a repository, -j tag to set the number of threads for make and -t flag to set a tag"
			exit
			;;
	esac
done

docker build -t $REPOSITORY . --build-arg no_threads=$THREADS --build-arg repository=$REPOSITORY --build-arg tag=$TAG
docker run -dit --name palisade -p 80:80 $REPOSITORY
docker commit palisade palisade:$TAG
docker login registry.gitlab.com
docker image tag palisade:$TAG registry.gitlab.com/palisade/$REPOSITORY/$TAG:$TAG
docker push registry.gitlab.com/palisade/$REPOSITORY/$TAG:$TAG
