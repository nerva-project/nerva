# Multistage docker build, requires docker 17.05

# builder stage
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
RUN set -ex && \
    git submodule init && git submodule update && \
    rm -rf build && \
    if [ -z "$NPROC" ] ; \
    then make -j$(nproc) depends target=x86_64-linux-gnu ; \
    else make -j$NPROC depends target=x86_64-linux-gnu ; \
    fi

# runtime stage
FROM ubuntu:20.04

RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt
COPY --from=builder /src/build/x86_64-linux-gnu/release/bin /usr/local/bin/

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

ENTRYPOINT ["nervad"]
CMD ["--p2p-bind-ip=0.0.0.0", "--p2p-bind-port=17565", "--rpc-bind-ip=0.0.0.0", "--rpc-bind-port=17566", "--non-interactive", "--confirm-external-bind"]
