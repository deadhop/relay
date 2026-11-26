# deadhop relay: one static binary on an empty base.
# Build context: this repository's root.
#
#   docker build -t deadhop-relay .
FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY assets assets
RUN cargo build --release --locked --bin deadhop-relay && cp target/release/deadhop-relay /deadhop-relay

FROM scratch
COPY --from=build /deadhop-relay /deadhop-relay
USER 10001:10001
# The operator page listens on loopback by default; inside a container that
# is unreachable, so expose it on 7448 and publish it to the host's loopback only.
ENV DEADHOP_RELAY_LISTEN=0.0.0.0:7447 DEADHOP_RELAY_STATS_LISTEN=0.0.0.0:7448
EXPOSE 7447 7448
ENTRYPOINT ["/deadhop-relay"]
