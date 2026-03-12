<div align="center">
<img alt="Docker Image Version (tag)" src="https://img.shields.io/docker/v/maxldwg/bicep-hamstring/latest?style=for-the-badge&logo=docker&label=Latest%20Version&link=https%3A%2F%2Fhub.docker.com%2Fr%2Fmaxldwg%2Fbicep-hamstring">
<img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/maxldwg/bicep-hamstring?style=for-the-badge&logo=docker&logoColor=blue&link=https%3A%2F%2Fhub.docker.com%2Fr%2Fmaxldwg%2Fbicep-hamstring">
<img alt="Codecov" src="https://img.shields.io/codecov/c/github/maldwg/BICEP-Hamstring-image?style=for-the-badge">
<img alt="GitHub branch status" src="https://img.shields.io/github/checks-status/maldwg/BICEP-hamstring-image/main?style=for-the-badge&label=Tests">
<br>

</div>

# BICEP-hamstring-image
Hamstring image adapted for BICEP 


The image holds every dependency necessary along with the necessary interface implemented, in order to work with the BICEP application

The main BICEP project is available [here](https://github.com/maldwg/BICEP/tree/main) <br>
The official Hamstring Project is available [here](https://github.com/orgs/Hamstring-NDR/repositories)

## Initialize project

In order to be able to start the project you will need to initialize it first. Do this by running:

```
git submodule update --init --recursive
```
This fetches the newest version of the submodule for the backend code and is necessary for the application to work seamlessly.


## Building the project
TO build a local version of the image for testing purposes, simply run:
``` 
cd ./bicep-hamstring
docker buildx build . --build-arg BASE_IMAGE=ghcr.io/hamstring --build-arg VERSION=1.1.9 -t maxldwg/bicep-hamstring:latest --no-cache
```
Change the version to your desried one
