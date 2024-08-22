all: clean build

build:
	(cd examples/client; go build -o client client.go)
	(cd examples/scanfiles; go build -o scanfiles scanfiles.go)

clean:
	rm -f examples/client/client examples/scanfiles/scanfiles

.PHONY: all build clean
