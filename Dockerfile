FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache gcc make musl-dev linux-headers

COPY . /opt/etherdfs
WORKDIR /opt/etherdfs

# Build and install
RUN make && cp ethersrv-linux /usr/local/bin/ethersrv-linux && chmod +x /usr/local/bin/ethersrv-linux && \
    ln -s /usr/local/bin/ethersrv-linux /usr/local/bin/ethersrv

# Cleanup
RUN apk del gcc make musl-dev linux-headers && rm -rf /opt/etherdfs

RUN mkdir -p /data
VOLUME /data

# Logging and startup sequence
CMD ["ethersrv", "-f", "vlan2", "/data"]