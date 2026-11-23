# deadhop relay: one static binary on an empty base.
# Build context: the repository root (the status pages embed the brand's fonts and mark).
#
#   docker build -f relay/Dockerfile -t deadhop-relay .
FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY brand/logo/mark-currentcolor.svg brand/logo/
COPY brand/icons/favicon.svg brand/icons/
COPY brand/fonts/*.woff2 brand/fonts/
COPY relay/Cargo.toml relay/Cargo.lock relay/
COPY relay/src relay/src
COPY relay/assets relay/assets
RUN cd relay && cargo build --release --locked --bin deadhop-relay && cp target/release/deadhop-relay /deadhop-relay

FROM scratch
COPY --from=build /deadhop-relay /deadhop-relay
USER 10001:10001
# The operator page listens on loopback by default; inside a container that
# is unreachable, so expose it on 7448 and publish it to the host's loopback only.
ENV DEADHOP_RELAY_LISTEN=0.0.0.0:7447 DEADHOP_RELAY_STATS_LISTEN=0.0.0.0:7448
EXPOSE 7447 7448
ENTRYPOINT ["/deadhop-relay"]
