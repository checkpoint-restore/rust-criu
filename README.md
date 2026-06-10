# rust-criu

[![crates.io](https://img.shields.io/crates/v/rust-criu.svg)](https://crates.io/crates/rust-criu)
[![ci](https://github.com/checkpoint-restore/rust-criu/actions/workflows/test.yml/badge.svg)](https://github.com/checkpoint-restore/rust-criu/actions)

`rust-criu` provides an interface to use [CRIU](https://criu.org/) in the
same way as [go-criu](https://github.com/checkpoint-restore/go-criu) does.

## Generate protobuf bindings

The CRIU RPC protobuf bindings are pre-generated and part of the rust-criu
repository. The bindings can be re-generated with

```shell
GENERATE_PROTOBUF=1 cargo build
```

## Run tests

To run the included tests please use the following commands:

```shell
GENERATE_TEST_PROCESS=1 cargo build
sudo -E env PATH=$PATH CRIU_BINARY=/path/to/criu/binary cargo test -- --test-threads=1
```
