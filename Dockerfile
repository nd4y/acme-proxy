FROM golang:1.25-alpine AS build

WORKDIR /src

ARG VERSION=dev

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/acme-proxy ./cmd/acme-proxy

# distroless/static carries CA certificates (needed to reach provider APIs over
# TLS) and nothing else: no shell, no package manager, nothing to exec into.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="acme-proxy"
LABEL org.opencontainers.image.description="DNS-01 broker: holds the DNS provider credentials, publishes only ACME validation records"
LABEL org.opencontainers.image.source="https://github.com/nd4y/acme-proxy"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=build /out/acme-proxy /acme-proxy

USER nonroot:nonroot

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/acme-proxy", "-healthcheck"]

ENTRYPOINT ["/acme-proxy"]
CMD ["-config", "/etc/acme-proxy/config.yaml"]
