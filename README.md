# APISIX plugins

Install Go, TinyGo 0.40.1, and Binaryen (`wasm-opt`), then run `make` to
build the WASM plugins. The build uses TinyGo's `wasi-legacy` mode so APISIX
can initialize the plugins without terminating them.

GitHub Actions builds and pushes `fr6nco/apisix` when `main` or a Git tag is
pushed. Native AMD64 and ARM64 runners build the images, which are published
under one multi-architecture tag. The image tag combines the APISIX base image
tag from the Dockerfile with the branch or Git tag name, for example
`3.21.0-ubuntu-main` or `3.21.0-ubuntu-v1.0.0`. Ref names must form valid
Docker tags.

Set the repository secrets `DOCKER_LOGIN` and `DOCKER_PASSWORD` to Docker Hub
credentials with permission to push to `fr6nco/apisix`.
