# GAPS

Graph Automatic Path Synthesis

## Requirements

* `docker`
* `docker compose`

## How To

Build the docker image.
```
$ make build
```

Spawn a shell in a container.
```
$ make run
```

Inside docker.

Compile tests.
```
cd /opt/test/smoke_test
make
```

Run gaps.
```
python3 -m gaps -i ./test/smoke_test/classes.dex -o /opt/io/
```
