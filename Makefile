all: clean build

build:
	(cd tools; go build -o client client.go)
	(cd tools; go build -o scanfiles scanfiles.go)

clean:
	rm -f tools/client tools/scanfiles

.PHONY: all build clean
