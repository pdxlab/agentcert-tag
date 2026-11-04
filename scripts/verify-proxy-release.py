"""Check the proxy release contract; registry checks are opt-in and read-only."""
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'pdxlab/agentcert-tag/mcp-trust-proxy'


def metadata():
    data = json.loads((ROOT / 'proxy/server.json').read_text())
    version = data['version']
    assert re.fullmatch(r'\d+\.\d+\.\d+', version), 'Expected a stable proxy version'
    assert data['packages'][0]['identifier'] == f'ghcr.io/{REPOSITORY}:{version}'
    label = f'LABEL io.modelcontextprotocol.server.name="{data["name"]}"'
    assert label in (ROOT / 'proxy/Dockerfile').read_text(), 'Missing registry ownership label'
    return data


def registry_get(path, token):
    request = urllib.request.Request(
        f'https://ghcr.io/v2/{REPOSITORY}/{path}',
        headers={'Authorization': f'Bearer {token}', 'Accept':
                 'application/vnd.oci.image.index.v1+json, '
                 'application/vnd.oci.image.manifest.v1+json, '
                 'application/vnd.docker.distribution.manifest.v2+json'},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    data = metadata()
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if arg and not arg.startswith('--'):
        assert arg == f'proxy-v{data["version"]}', 'Tag must match proxy/server.json version'
    elif arg in ('--require-unpublished', '--verify-published'):
        with urllib.request.urlopen(
            f'https://ghcr.io/token?scope=repository:{REPOSITORY}:pull', timeout=30
        ) as response:
            token = json.load(response)['token']
        try:
            manifest = registry_get(f'manifests/{data["version"]}', token)
        except urllib.error.HTTPError as exc:
            if arg == '--require-unpublished' and exc.code == 404:
                print('Version is not published; safe to create')
                return
            raise
        assert arg != '--require-unpublished', 'Version already exists; bump it instead of overwriting'
        manifests = manifest.get('manifests', [])
        if manifests:
            digest = next(m['digest'] for m in manifests
                          if m.get('platform', {}).get('architecture') == 'amd64')
            manifest = registry_get(f'manifests/{digest}', token)
        config = registry_get(f'blobs/{manifest["config"]["digest"]}', token)
        assert config['config'].get('Labels', {}).get('io.modelcontextprotocol.server.name') == data['name'], 'Published image is missing the registry ownership label'
    elif arg:
        raise ValueError(f'Unknown argument: {arg}')
    print('Proxy release checks passed')


if __name__ == '__main__':
    main()
