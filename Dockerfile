FROM node:24.21.0-alpine3.24 AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run check && npm run build

FROM golang:1.27.1-alpine3.24 AS backend
WORKDIR /src/backend
RUN apk add --no-cache ca-certificates git
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    set -eu; \
    attempt=1; \
    while ! go mod download; do \
      if [ "$attempt" -ge 4 ]; then \
        echo "go mod download failed after ${attempt} attempts" >&2; \
        exit 1; \
      fi; \
      sleep $((attempt * 5)); \
      attempt=$((attempt + 1)); \
    done; \
    go mod verify
COPY backend/cmd ./cmd
COPY backend/internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/zentssh ./cmd/zentssh

FROM alpine:3.24.1
LABEL org.opencontainers.image.source="https://github.com/ZentWorks/ZentSSH"
RUN apk add --no-cache ca-certificates tzdata && addgroup -S zentssh && adduser -S -G zentssh -h /app zentssh
WORKDIR /app
COPY --from=backend /out/zentssh /app/zentssh
COPY --from=ui /src/frontend/dist /app/web
RUN mkdir -p /data && chown -R zentssh:zentssh /app /data
USER zentssh
EXPOSE 8080
ENV DATA_DIR=/data WEB_DIR=/app/web LISTEN_ADDR=:8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1
ENTRYPOINT ["/app/zentssh"]
