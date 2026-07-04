FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache gcc make musl-dev linux-headers libpcap-dev libpcap

COPY . /opt/etherdfs
WORKDIR /opt/etherdfs

# Build and install
ARG APP_VERSION=
RUN make ${APP_VERSION:+VERSION="$APP_VERSION"} && cp ethersrv /usr/local/bin/ethersrv && chmod +x /usr/local/bin/ethersrv

# Copy entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Cleanup
RUN apk del gcc make musl-dev linux-headers libpcap-dev && rm -rf /opt/etherdfs

RUN mkdir -p /data
VOLUME /data

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]