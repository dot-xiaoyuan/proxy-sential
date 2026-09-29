.PHONY: deploy deploy-ui deploy-backend deploy-dev package package-airgap deploy-airgap status doctor logs backup rollback

VERSION ?= $(shell git rev-parse --short HEAD)

# 开发环境前端快捷更新，默认目标为 30。
deploy-ui:
	@./scripts/deploy/deploy-ui.sh "$(or $(TARGET),root@192.168.0.30)"

deploy-backend:
	@./scripts/deploy/deploy-backend.sh "$(or $(TARGET),root@192.168.0.30)"

# 前后端依次更新，适用于已安装的开发环境。
deploy-dev:
	@$(MAKE) deploy-backend
	@$(MAKE) deploy-ui

deploy:
	@test -n "$(TARGET)" || (echo "TARGET is required, for example root@192.168.0.30" >&2; exit 2)
	@test -n "$(ENV_FILE)" || (echo "ENV_FILE is required" >&2; exit 2)
	@./scripts/deploy/deploy-openeuler.sh --target "$(TARGET)" --version "$(VERSION)" --env-file "$(ENV_FILE)"

package:
	@./scripts/deploy/build-release.sh --version "$(VERSION)" --output "dist/proxy-sentinel-$(VERSION).tar.gz"

package-airgap:
	@test -n "$(DEPENDENCY_HOST)" || (echo "DEPENDENCY_HOST is required, for example root@192.168.0.30" >&2; exit 2)
	@./scripts/deploy/build-airgap-bundle.sh --version "$(VERSION)" --dependency-host "$(DEPENDENCY_HOST)" --output "dist/proxy-sentinel-airgap-$(VERSION).tar.gz"

deploy-airgap:
	@test -n "$(TARGET)" || (echo "TARGET is required" >&2; exit 2)
	@test -n "$(BUNDLE)" || (echo "BUNDLE is required" >&2; exit 2)
	@test -n "$(INTERFACE)" || (echo "INTERFACE is required" >&2; exit 2)
	@./scripts/deploy/deploy-airgap-openeuler.sh --target "$(TARGET)" --bundle "$(BUNDLE)" --interface "$(INTERFACE)" --sensor-id "$(or $(SENSOR_ID),office-30)"

status doctor logs backup rollback:
	@test -n "$(TARGET)" || (echo "TARGET is required" >&2; exit 2)
	@ssh -t "$(TARGET)" sudo proxy-sentinelctl $@
