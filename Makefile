.PHONY: update-grype-release
update-grype-release:
	@LATEST_VERSION=$$(gh release view --json name -q '.name' -R anchore/grype) && \
		echo "export const GRYPE_VERSION = \"$$LATEST_VERSION\";" > GrypeVersion.js && \
		npm ci && \
		npm run build
