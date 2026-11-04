# Publishing the Kong plugin

Kong releases use `kong-vX.Y.Z` tags. The existing `v0.2.0` tag belongs to
the Python library; never move it or use it for this Kong release.

After this PR merges, run from a fresh checkout of the intended main commit:

```bash
set -euo pipefail
git fetch origin main --tags
git switch --detach origin/main
luarocks lint kong/agentcert-tag/kong-plugin-agentcert-tag-0.2.0-1.rockspec
git tag kong-v0.2.0
git push origin refs/tags/kong-v0.2.0
```

Before uploading, build from the published source tag into an isolated tree:

```bash
set -euo pipefail
tree=$(mktemp -d)
luarocks build kong/agentcert-tag/kong-plugin-agentcert-tag-0.2.0-1.rockspec --tree="$tree"
grep -F 'VERSION  = "0.2.0"' "$tree"/share/lua/*/kong/plugins/agentcert-tag/handler.lua
```

Only after lint and the tagged-source build pass, upload the rockspec using
your LuaRocks account. Keep its API key out of source control. Kong Hub
submission is a separate human step: confirm Kong's current partner submission
process before submitting the package URL, repository and documentation.
