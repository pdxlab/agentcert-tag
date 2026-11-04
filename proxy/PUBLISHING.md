# Publishing the MCP Trust Proxy

Proxy releases use `proxy-vX.Y.Z`; Python `v*` and Kong `kong-v*` tags do not
publish proxy images. Never move a published tag or overwrite `0.1.0`.

The next version is **0.1.1**. Its image is not available until the release
workflow succeeds. Do not submit `server.json` to the registry before then.

After merging the listing/workflow changes, run from a fresh checkout:

```bash
set -euo pipefail
git fetch origin main --tags
git switch --detach origin/main
python scripts/verify-proxy-release.py proxy-v0.1.1
python scripts/verify-proxy-release.py --require-unpublished
git tag proxy-v0.1.1
git push origin refs/tags/proxy-v0.1.1
```

The tag triggers `publish-proxy`: it checks the commit is on main, validates
version alignment, refuses existing image versions, builds and checks the
ownership label before pushing, then verifies the published image. It never
writes `latest` or `0.1.0`. A failed post-publish check must be investigated;
do not overwrite the image to retry. Use a new version if the artifact is wrong.

Wait for the workflow to succeed, then run:

```bash
set -euo pipefail
python scripts/verify-proxy-release.py --verify-published
cd proxy
mcp-publisher validate
mcp-publisher login github
mcp-publisher publish
```

Registry publication requires an authorized pdxlab identity. Prepare the
trust-anchor bundle as `anchors/roots.pem` before using the Docker or Compose
examples. Helm receives the same bundle through `anchorsPem`.
