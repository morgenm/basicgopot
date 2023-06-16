# syntax=docker/dockerfile:1

FROM golang:1.20

WORKDIR /app

COPY cmd/ ./cmd
COPY internal/ ./internal
COPY web/ ./web
COPY go.mod ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /basicgopot ./cmd/basicgopot

# Default port
EXPOSE 8080 

WORKDIR /
CMD ["/basicgopot"]