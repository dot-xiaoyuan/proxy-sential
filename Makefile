.PHONY: deploy package status doctor logs backup rollback

VERSION ?= $(shell git rev-parse --short HEAD)

deploy:
	@test -n "$(TARGET)" || (echo "TARGET is required, for example root@192.168.0.30" >&2; exit 2)
	@test -n "$(ENV_FILE)" || (echo "ENV_FILE is required" >&2; exit 2)
	@./scripts/deploy/deploy-openeuler.sh --target "$(TARGET)" --version "$(VERSION)" --env-file "$(ENV_FILE)"

package:
	@./scripts/deploy/build-release.sh --version "$(VERSION)" --output "dist/proxy-sentinel-$(VERSION).tar.gz"

status doctor logs backup rollback:
	@test -n "$(TARGET)" || (echo "TARGET is required" >&2; exit 2)
	@ssh -t "$(TARGET)" sudo proxy-sentinelctl $@
