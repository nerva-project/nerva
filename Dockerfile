# Multistage docker build, requires docker 17.05

# builder stage: same release as the depends CI job, so the static build
# this image ships is the one CI tests
FROM ubuntu:20.04 as builder

RUN set -ex && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends --yes install \
        automake \
        autotools-dev \
        bsdmainutils \
        build-essential \
        ca-certificates \
        ccache \
        cmake \
        curl \
        git \
        libtool \
        pkg-config \
        gperf

WORKDIR /src
COPY . .

ARG NPROC
ARG TARGETARCH
RUN set -ex && \
    case "$TARGETARCH" in \
        arm64) BUILD_TARGET="aarch64-linux-gnu" ;; \
        *)     BUILD_TARGET="x86_64-linux-gnu" ;; \
    esac && \
    if [ "$TARGETARCH" = "arm64" ]; then \
        for tool in gcc g++ ar ranlib strip nm; do \
            ln -sf /usr/bin/$tool /usr/local/bin/aarch64-linux-gnu-$tool ; \
        done ; \
    fi && \
    git submodule init && git submodule update && \
    rm -rf build && \
    if [ -z "$NPROC" ] ; \
    then make -j$(nproc) depends target=$BUILD_TARGET ; \
    else make -j$NPROC depends target=$BUILD_TARGET ; \
    fi && \
    cp -r /src/build/${BUILD_TARGET}/release/bin /src/build/out

# runtime stage
FROM ubuntu:24.04

RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install ca-certificates adduser && \
    apt-get clean && \
    rm -rf /var/lib/apt
COPY --from=builder /src/build/out /usr/local/bin/

# Create nerva user
RUN adduser --system --group --disabled-password nerva && \
	mkdir -p /wallet /home/nerva/.nerva && \
	chown -R nerva:nerva /home/nerva/.nerva && \
	chown -R nerva:nerva /wallet

# Contains the blockchain
VOLUME /home/nerva/.nerva

# Generate your wallet via accessing the container and run:
# cd /wallet
# nerva-wallet-cli
VOLUME /wallet

EXPOSE 17565
EXPOSE 17566

# switch to user nerva
USER nerva

# The RPC listens on every interface so a published port reaches it, and it
# runs restricted: wallets and explorers work, administrative calls (stopping
# the daemon, mining, bans, peer limits) are refused. For an unrestricted RPC,
# pass your own arguments to the container and do not publish 17566.
ENTRYPOINT ["nervad"]
CMD ["--p2p-bind-ip=0.0.0.0", "--p2p-bind-port=17565", "--rpc-bind-ip=0.0.0.0", "--rpc-bind-port=17566", "--restricted-rpc", "--non-interactive", "--confirm-external-bind"]
