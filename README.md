
# Docker Registry and Auto-Generated TLS Cert Demo

This crate has a single integration test that would otherwise be a part
of the 
[passivized_docker_engine_client](https://github.com/iamjpotts/passivized_docker_engine_client)
crate, except that the 
[rcgen](https://github.com/est31/rcgen)
crate used for auto-generation of certs depends on the
[ring](https://github.com/briansmith/ring)
crate, which has a 
[non-trivial license](https://github.com/briansmith/ring/blob/abe9529fc063f575759f8166bba02db171a3a0f6/LICENSE).

This crate's integration test demonstrates:

1. Auto-generating a CA and a server TLS cert/key pair using
[rcgen](https://github.com/est31/rcgen) 
2. Creating a temporary Docker image registry secured by that certificate
3. Pushing and pulling images with the temporary secured registry

## Source

* [cert_gen.rs](./tests/test_utils/cert_gen.rs)
* [test_registry.rs](./tests/test_registry.rs)

## Requirements

Demo must be run on Linux with a Docker Engine installed.

Mac and Windows are not supported.

## How to Run

    $ cargo t


## The Static Certificates Version of This Test

In `passivized_docker_engine_client` the same test exists, but uses static SSL
certificates that were generated using `cfssl` and committed into git.

* [test_registry.rs](https://github.com/iamjpotts/passivized_docker_engine_client/blob/master/tests/test_registry.rs)
in `passivized_docker_engine_client`