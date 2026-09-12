.PHONY: all build cli test bench run clean sim

all: build cli test

build:
	go build -o bin/server.exe ./cmd/server

cli:
	go build -o bin/fs2601-cli.exe ./cmd/cli


test:
	go test -v -count=1 ./tests/...

bench:
	go test -bench='.' -benchmem ./tests/...

run: build
	./bin/server.exe

sim:
	powershell.exe -ExecutionPolicy Bypass -File ./scripts/partition_simulation.ps1

bench-py:
	python ./scripts/benchmark_concurrency.py

clean:
	rm -rf bin/ *.log
