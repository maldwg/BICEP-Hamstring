<div align="center">
  <a href="https://github.com/users/maldwg/packages/container/package/bicep-hamstring">
    <img alt="Published on GHCR" src="https://img.shields.io/badge/Published%20on-GHCR-2088FF?style=for-the-badge&logo=github">
  </a>
  <a href="https://github.com/users/maldwg/packages/container/package/bicep-hamstring">
    <img alt="Container Image" src="https://img.shields.io/badge/Image-bicep--hamstring-0db7ed?style=for-the-badge&logo=docker">
  </a>
  <a href="https://app.codecov.io/gh/maldwg/BICEP-Hamstring">
    <img alt="Codecov" src="https://img.shields.io/codecov/c/github/maldwg/BICEP-Hamstring?style=for-the-badge">
  </a>
  <a href="https://github.com/maldwg/BICEP-Hamstring/actions/workflows/on_push.yml">
    <img alt="Tests" src="https://img.shields.io/github/actions/workflow/status/maldwg/BICEP-Hamstring/on_push.yml?branch=main&style=for-the-badge&label=Tests">
  </a>
</div>


# BICEP-Hamstring
Hamstring image adapted for BICEP 


The image holds every dependency necessary along with the necessary interface implemented, in order to work with the BICEP application

The main BICEP project is available [here](https://github.com/maldwg/BICEP/tree/main) <br>
The Hamstring Zeek image used as the base image is available [here](https://github.com/ASTRAOS-de/hamstring-zeek)

## Initialize project

In order to be able to start the project you will need to initialize it first. Do this by running:

```
git submodule update --init --recursive
```
This fetches the newest version of the submodule for the backend code and is necessary for the application to work seamlessly.


## Building the project
To build a local version of the image for testing purposes, run:
```bash
cd ./bicep-hamstring
docker buildx build . \
  --build-arg BASE_IMAGE=ghcr.io/astraos-de/hamstring-zeek \
  --build-arg VERSION=<upstream-hamstring-version> \
  -t ghcr.io/maldwg/bicep-hamstring:<version> \
  --no-cache
```
Replace `<upstream-hamstring-version>` with a published `hamstring-zeek` tag. The CI pipeline resolves the latest upstream version automatically when it publishes the image. This image now wraps the C++ `/opt/hamstring_zeek` implementation from the upstream base image.

To pull the published image from GHCR, run:
```bash
docker pull ghcr.io/maldwg/bicep-hamstring:latest
```
