# Build both architectures from this single Dockerfile:
#   docker build --build-arg ARCH=aarch64 --target package -t WireGuard_Server-aarch64 .
#   docker build --build-arg ARCH=armv7hf --target package -t WireGuard_Server-armv7hf .
#
# Prefer ./build.sh, which does both and collects the .eap files in ./releases.
ARG ARCH=aarch64
ARG GO_VERSION=1.27.3
ARG SDK_VERSION=12.10.0
ARG UBUNTU_VERSION=24.04
ARG SDK_REPO=axisecp
ARG SDK=acap-native-sdk

FROM --platform=linux/amd64 golang:${GO_VERSION} AS gobuilder
ARG ARCH
ENV CGO_ENABLED=0
WORKDIR /src
# go.sum is optional until the first external dependency is added.
COPY go.mod go.su[m] ./
RUN go mod download
COPY daemon ./daemon
RUN if [ "${ARCH}" = "aarch64" ]; then export GOARCH=arm64; else export GOARCH=arm GOARM=7; fi; \
    GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/service ./daemon

FROM ${SDK_REPO}/${SDK}:${SDK_VERSION}-${ARCH}-ubuntu${UBUNTU_VERSION} AS package
ARG ARCH
COPY app /opt/app/
COPY LICENSE /opt/app/LICENSE
COPY --from=gobuilder /out/service /opt/app/lib/WireGuard_Serverd
WORKDIR /opt/app
RUN sed -i "s/\"BUILDARCH\"/\"${ARCH}\"/" manifest.json && \
    find . -name .DS_Store -delete && \
    chmod 755 lib/WireGuard_Serverd && \
    . /opt/axis/acapsdk/environment-setup* && acap-build ./

FROM scratch
COPY --from=package /opt/app/*.eap /
