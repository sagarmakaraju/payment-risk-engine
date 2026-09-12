# Multi-stage build for FS-2601 Payment Authorization Server
FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/server ./cmd/server

# Minimal scratch runtime
FROM alpine:3.20

WORKDIR /app
RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder /app/server /app/server

EXPOSE 8080
VOLUME ["/data"]

ENV PORT=8080
ENTRYPOINT ["/app/server"]
