# edera-attester
Edera Zone &amp; Workload attester

## Running with the Container Image

The attester is published as a container image to `ghcr.io/carabiner-labs/edera-attester`.

### Generate a zone attestation

```sh
docker run --rm \
  -v /var/lib/edera/protect/daemon.socket:/var/lib/edera/protect/daemon.socket \
  ghcr.io/carabiner-labs/edera-attester \
  zone a307513d-70d3-4b74-aed8-f07a0db83f58
```

### Generate a workload attestation

```sh
docker run --rm \
  -v /var/lib/edera/protect/daemon.socket:/var/lib/edera/protect/daemon.socket \
  ghcr.io/carabiner-labs/edera-attester \
  workload e601d3e3-cf51-48af-b7ac-54ed9798cadd
```

### Sign the attestation

Add `--sign` to sign the attestation using the default sigstore backend:

```sh
docker run --rm \
  -v /var/lib/edera/protect/daemon.socket:/var/lib/edera/protect/daemon.socket \
  ghcr.io/carabiner-labs/edera-attester \
  workload --sign e601d3e3-cf51-48af-b7ac-54ed9798cadd
```

To sign with a private key instead:

```sh
docker run --rm \
  -v /var/lib/edera/protect/daemon.socket:/var/lib/edera/protect/daemon.socket \
  -v "$PWD/key.pem":/key.pem:ro \
  ghcr.io/carabiner-labs/edera-attester \
  workload --sign --signing-key /key.pem e601d3e3-cf51-48af-b7ac-54ed9798cadd
```
