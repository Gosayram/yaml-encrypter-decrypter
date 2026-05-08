FROM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS builder

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
