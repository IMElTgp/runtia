# Runtia

Runtia is a CLI for exploring and analyzing container runtime state from the host side.

The goal is to resolve a container into the Linux runtime information behind it, extract useful profile data, and present that data in a form that is easy to inspect or process further.

## Current Status

This project is still an early prototype.

At the moment, given a container ID, it:

1. resolves the container's main PID with `docker inspect`
2. reads that process's cgroup path from `/proc/<pid>/cgroup`
3. maps the result to `/sys/fs/cgroup`
4. lists the files in that cgroup directory with basic metadata

## Requirements

- Linux host
- Docker CLI available and permission to talk to the Docker daemon
- Go installed if you want to build from source

## Build

Build the binary with:

```bash
make build
```

This creates:

```bash
./bin/runtia
```

You can also build directly without `make`:

```bash
go build -ldflags="-s -w" -o ./bin/runtia ./src
```

## Install

Install the binary to `~/.local/bin` with:

```bash
make install
```

Make sure `~/.local/bin` is on your `PATH`.

## Usage

Find the container ID:

```bash
docker ps
```

Then run:

```bash
runtia --container-id <container-id>
```

## Current Limitations

- Docker only
- Assumes a Linux cgroup layout compatible with the current implementation
- Reads and displays cgroup directory contents only
- No JSON export or visualization yet

## Roadmap

- extract more useful runtime profile data from the container's cgroup files
- serialize the collected data to JSON
- add clearer reporting or visualization
