BUNDLE_DIR := bundle
DIST_DIR   := dist

.PHONY: test build clean fmt check

## Run all OPA tests with verbose output.
test:
	opa test $(BUNDLE_DIR)/ -v

## Build the signed bundle tarball that gets published to S3.
## The publish step (S3 upload + OPAL webhook) is handled by CI.
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
