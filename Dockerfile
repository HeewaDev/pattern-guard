# Pattern-Guard gateway image.
#   docker build -t pattern-guard .
#   docker run --rm -p 8080:8080 -v ./gateway.toml:/etc/pattern-guard/gateway.toml:ro pattern-guard
# See deploy/docker/ for a compose example and docs/DEPLOYMENT.md.

FROM rust:1.85-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p pattern-guard-gateway -p pattern-guard-cli \
 && strip target/release/pattern-guard-gateway target/release/pattern-guard

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin pattern-guard \
 && mkdir -p /etc/pattern-guard /var/log/pattern-guard \
 && chown pattern-guard:pattern-guard /var/log/pattern-guard
COPY --from=build /src/target/release/pattern-guard-gateway /src/target/release/pattern-guard /usr/local/bin/
COPY config/gateway.toml.example config/guard.toml.example /etc/pattern-guard/
COPY deploy/docker/gateway.toml /etc/pattern-guard/gateway.toml
USER pattern-guard
# 8080: traffic. 9901: /metrics, /healthz, /inventory, /bans (publish it privately only).
EXPOSE 8080 9901
VOLUME ["/var/log/pattern-guard"]
ENTRYPOINT ["pattern-guard-gateway"]
CMD ["--config", "/etc/pattern-guard/gateway.toml"]
