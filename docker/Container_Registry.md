# Container Registry instructions
1. Before you are able to use an image from the container registry, you will need to have docker engine installed. Follow the steps [here](https://docs.docker.com/engine/install/) to install.
2. Find the image you would like to run in the [container registry](https://gitlab.com/palisade/palisade-development/container_registry) and click the copy icon to the right of the title. If you hover over the copy icon it should be similar to this format *registry.example.com/group/project/image*. 
3. Once you've selected your image, run the command ```sudo docker run -dit --name imageName registry.example.com/group/project/image``` where imageName is the name you want for your image.
4. Run ```sudo docker exec -it imageName /bin/bash``` to use the command line.

