# syntax=docker/dockerfile:1

FROM golang:1.22

WORKDIR /app

COPY cmd/ ./cmd
COPY internal/ ./internal
COPY pkg/ ./pkg
COPY web/ /web
COPY go.mod ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /basicgopot ./cmd/basicgopot

WORKDIR /
CMD ["/basicgopot"]