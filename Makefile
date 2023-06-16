ifeq ($(OS),Windows_NT)
	BINARY_FILE=basicgopot.exe
else
	BINARY_FILE=basicgopot
endif

all: golangci gosec compile test

golangci:
	golangci-lint run ./...

gosec:
	gosec run ./...

compile:
	go build -o ${BINARY_FILE} ./cmd/basicgopot

test:
	go test ./...

docker:
	docker build -t basicgopot -f build/Dockerfile .

release:
	goreleaser release --clean

clean:
	go clean
	rm ${BINARY_FILE}