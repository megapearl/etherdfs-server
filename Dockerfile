FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache gcc make musl-dev linux-headers

COPY . /opt/etherdfs
WORKDIR /opt/etherdfs

# Build and install
RUN make && cp ethersrv-linux /usr/local/bin/ethersrv-linux && chmod +x /usr/local/bin/ethersrv-linux

# Copy entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Cleanup
RUN apk del gcc make musl-dev linux-headers && rm -rf /opt/etherdfs

RUN mkdir -p /data
VOLUME /data

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]