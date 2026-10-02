# syntax=docker/dockerfile:1.7

# --- Build stage --------------------------------------------------------------
FROM rust:1-bookworm AS build
WORKDIR /src

# Build dependencies against a stub first so they cache independently of
# source edits.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin \
    && echo 'fn main() {}' > src/bin/kt-sfu.rs \
    && echo 'fn main() {}' > src/bin/kt-probe.rs \
    && touch src/lib.rs \
    && cargo build --release --locked --bin kt-sfu \
    && rm -rf src

COPY src ./src
RUN touch src/lib.rs src/bin/kt-sfu.rs \
    && cargo build --release --locked --bin kt-sfu \
    && install -D target/release/kt-sfu /out/kt-sfu

# --- Runtime stage ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/kt-sfu /usr/local/bin/kt-sfu

# Unprivileged ports; the Service maps 443 -> 8443 and 80 -> 8080.
USER 65532:65532
EXPOSE 8080/tcp 8443/tcp 7842/udp 9702/udp
ENTRYPOINT ["/usr/local/bin/kt-sfu"]
CMD ["--relay-http-bind", "[::]:8080", "--relay-https-bind", "[::]:8443", \
     "--relay-quic-bind", "[::]:7842", "--sfu-bind", "[::]:9702"]
