FROM golang:1.25.8-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa AS builder

RUN apk --no-cache add build-base git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN VERSION_RAW=$(tail -n 1 .release-version 2>/dev/null || echo "dev") && \
    CGO_ENABLED=0 go build -ldflags="-X 'main.Version=${VERSION_RAW}'" -o yed ./cmd/yaml-encrypter-decrypter

# Final stage with scratch image
FROM scratch
COPY --from=builder /app/yed /yed
ENTRYPOINT ["/yed"]
CMD ["--version"]
