FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        ninja-build \
        pkg-config \
        python3 \
        python3-pip \
        libssl-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/lantern

COPY . .

RUN ./scripts/bootstrap.sh

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
RUN cmake --build build --target lantern_cli --parallel "$(nproc)"

RUN cmake --build build --target lantern_client_test --parallel "$(nproc)" || true

RUN mkdir -p /opt/lantern/bin \
    && cp build/lantern_cli /opt/lantern/bin/lantern \
    && mkdir -p /opt/lantern/lib \
    && find build -maxdepth 2 -type f -name "*.so*" -exec cp {} /opt/lantern/lib/ \;

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        libstdc++6 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/lantern /opt/lantern
COPY docker/entrypoint.sh /usr/local/bin/lantern-entrypoint.sh

ENV PATH="/opt/lantern/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/lantern/lib:${LD_LIBRARY_PATH}"

WORKDIR /data

ENTRYPOINT ["/usr/local/bin/lantern-entrypoint.sh"]
CMD []
