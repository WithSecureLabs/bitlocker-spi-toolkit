FROM alpine:3.12 AS build

RUN apk add --update-cache \
    git \
    gcc \
    g++ \
    cmake \
    make \
    fuse-dev \
    mbedtls-dev

RUN git clone https://github.com/Aorimn/dislocker.git /dislocker \
    && cd /dislocker \
    && git checkout tags/v0.7.3 \
    && rm -rf .git \
    && [ "$(find . -type f | xargs -P0 -n1 sha256sum | sort |sha256sum |cut -d' ' -f1)" \
        == "40211653afe39cf1c7db4338b1c89250ca2bd0eaf63980e0340179e899cbf203" ] \
        || { printf 1>&2 "\nINTEGRITY MISMATCH: The checksum of the cloned repo did not matched the expected one!\n"; exit 1; } \
    && cmake . \
    && make \
    && make DESTDIR=/tmp/build install 

COPY run.sh /tmp/build/
RUN chmod +x /tmp/build/run.sh

FROM alpine:3.12

RUN apk add --update-cache \
    fuse \
    mbedtls \
    xxd \
    ntfs-3g \
    bash

COPY --from=build /tmp/build /
ENTRYPOINT ["/run.sh"]
