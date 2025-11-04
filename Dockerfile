FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        bison \
        ca-certificates \
        cmake \
        git \
        ninja-build \
        pkg-config \
        flex \
        python3 \
        python3-pip \
        libtommath-dev \
        libssl-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/lantern

COPY . .

RUN LANTERN_BOOTSTRAP_SKIP_SUBMODULE_SYNC=1 ./scripts/bootstrap.sh

RUN cmake -S external/c-libp2p/external/libtommath -B deps/libtommath -DBUILD_SHARED_LIBS=ON \
    && cmake --build deps/libtommath --parallel "$(nproc)" \
    && cmake --install deps/libtommath

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo

ARG LANTERN_FORCE_REBUILD=0
RUN echo "LANTERN_FORCE_REBUILD=${LANTERN_FORCE_REBUILD}"
RUN cmake --build build --target lantern_cli --parallel "$(nproc)"

RUN cmake --build build --target lantern_client_test --parallel "$(nproc)" || true

RUN mkdir -p /opt/lantern/bin \
    && cp build/lantern_cli /opt/lantern/bin/lantern \
    && mkdir -p /opt/lantern/lib \
    && find build -maxdepth 2 -type f -name "*.so*" -exec cp {} /opt/lantern/lib/ \; \
    && python3 - <<'PY'
import os
import pathlib
libdir = pathlib.Path("/opt/lantern/lib")
for path in libdir.glob("*.so.*"):
    name = path.name
    stem, _, suffix = name.partition(".so.")
    if not suffix:
        continue
    major = suffix.split(".", 1)[0]
    target = libdir / name
    for link_name in {f"{stem}.so", f"{stem}.so.{major}"}:
        link_path = libdir / link_name
        try:
            if link_path.is_symlink() or link_path.exists():
                link_path.unlink()
            link_path.symlink_to(target.name)
        except FileExistsError:
            pass
PY

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
