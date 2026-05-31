# syntax=docker/dockerfile:1.7

# --- Build stage --------------------------------------------------------------
FROM swift:6.3-noble AS build

WORKDIR /src

# Resolve dependencies first so the checkouts layer caches independently
# of source edits. We deliberately do NOT use a buildkit cache mount on
# `.build`: swift-nio-ssl's CNIOBoringSSL uses `#include "../internal.h"`
# relative paths that fail to resolve under overlayfs-backed cache mounts.
COPY Package.swift Package.resolved ./
RUN swift package resolve

COPY Sources ./Sources
COPY Tests ./Tests

RUN swift build -c release --product KeepTalkingSFU -Xswiftc -g \
    && mkdir -p /out \
    && install .build/release/KeepTalkingSFU /out/KeepTalkingSFU

# --- Runtime stage ------------------------------------------------------------
FROM swift:6.3-noble-slim AS runtime

RUN groupadd --system ktsfu \
    && useradd --system --gid ktsfu --home-dir /app --shell /usr/sbin/nologin ktsfu \
    && mkdir -p /app \
    && chown ktsfu:ktsfu /app

COPY --from=build /out/KeepTalkingSFU /usr/local/bin/KeepTalkingSFU

USER ktsfu
WORKDIR /app

EXPOSE 9701/tcp

ENTRYPOINT ["/usr/local/bin/KeepTalkingSFU"]
CMD ["--bind", "0.0.0.0", "--port", "9701"]
