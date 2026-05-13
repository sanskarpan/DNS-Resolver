# Stage 1: Build frontend bundle
FROM node:22-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./frontend/
WORKDIR /app/frontend
RUN npm ci
WORKDIR /app
COPY frontend/ ./frontend/
COPY internal/api/web ./internal/api/web
WORKDIR /app/frontend
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.25-alpine AS go-builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /app/frontend/build ./frontend/build
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /bin/dns-resolver ./cmd/server

# Stage 3: Minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go-builder /bin/dns-resolver /dns-resolver
COPY blocklist.txt /blocklist.txt
EXPOSE 53/udp 53/tcp 853/tcp 8080/tcp
USER nonroot:nonroot
ENTRYPOINT ["/dns-resolver"]
