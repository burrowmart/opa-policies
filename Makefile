BUNDLE_DIR := bundle
DIST_DIR   := dist

.PHONY: test build clean fmt check

## Run all OPA tests with verbose output.
test:
	opa test $(BUNDLE_DIR)/ -v

## Build the bundle tarball that gets published to S3.
## The publish step (S3 upload + OPAL webhook) is handled by CI.
##
## Unsigned, deliberately for now: integrity rests on the S3 bucket being
## private and reachable only through the PDP's IRSA role. Signing it would
## mean `opa build --signing-key <pem> --signing-alg RS256`, which produces a
## .signatures.json inside the tarball, plus a matching `keys:` block in the
## PDP config (platform-infra/k8s/opa/configmap.yaml.template) so OPA rejects
## a bundle it cannot verify — and therefore a private key in CI and its
## public half distributed to every PDP. Worth doing if the bucket ever stops
## being the only trust boundary.
build:
	mkdir -p $(DIST_DIR)
	opa build -b $(BUNDLE_DIR)/ -o $(DIST_DIR)/bundle.tar.gz

## Format all Rego files in-place.
fmt:
	opa fmt --write $(BUNDLE_DIR)/

## Static check — catches undefined references before tests run.
check:
	opa check $(BUNDLE_DIR)/

clean:
	rm -rf $(DIST_DIR)
