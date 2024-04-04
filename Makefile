all: clean build

build:
	(cd tools/client; go build -o client client.go)
	(cd tools/scanfiles; go build -o scanfiles scanfiles.go)

clean:
	rm -f tools/client/client tools/scanfiles/scanfiles

.PHONY: all build clean
