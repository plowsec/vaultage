# syntax=docker/dockerfile:1
# Build from the repo root:  docker build -f deploy/Dockerfile -t vaultaged:0.1.0 .

FROM rust:1.99.0-slim-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p vaultage-server \
 && install -D -m 0755 target/release/vaultaged /out/vaultaged \
 && mkdir -p /out/data

# distroless has no version tags; pinned by digest. Refresh deliberately.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2
COPY --from=build /out/vaultaged /usr/local/bin/vaultaged
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV VAULTAGE_DATA=/data \
    VAULTAGE_LISTEN=0.0.0.0:8787
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/vaultaged"]
