"""Release guard regression tests: never overwrite or mistake auth failures for absence."""
import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

spec = importlib.util.spec_from_file_location(
    'proxy_release', Path(__file__).resolve().parents[1] / 'scripts/verify-proxy-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def token_response():
    return io.BytesIO(json.dumps({'token': 'test-token'}).encode())


def test_existing_image_is_never_overwritten():
    with patch.object(sys, 'argv', ['check', '--require-unpublished']), \
         patch.object(release.urllib.request, 'urlopen', return_value=token_response()), \
         patch.object(release, 'registry_get', return_value={}):
        with pytest.raises(AssertionError, match='already exists'):
            release.main()


@pytest.mark.parametrize('code', [401, 403, 429, 500])
def test_registry_errors_do_not_allow_publish(code):
    with patch.object(sys, 'argv', ['check', '--require-unpublished']), \
         patch.object(release.urllib.request, 'urlopen', return_value=token_response()), \
         patch.object(release, 'registry_get', side_effect=urllib.error.HTTPError('url', code, 'error', {}, None)):
        with pytest.raises(urllib.error.HTTPError):
            release.main()


def test_only_missing_manifest_allows_new_version():
    with patch.object(sys, 'argv', ['check', '--require-unpublished']), \
         patch.object(release.urllib.request, 'urlopen', return_value=token_response()), \
         patch.object(release, 'registry_get', side_effect=urllib.error.HTTPError('url', 404, 'missing', {}, None)):
        release.main()


def test_python_release_tag_is_rejected():
    with patch.object(sys, 'argv', ['check', 'v0.1.1']):
        with pytest.raises(AssertionError, match='Tag must match'):
            release.main()


def test_published_image_without_ownership_label_is_rejected():
    with patch.object(sys, 'argv', ['check', '--verify-published']), \
         patch.object(release.urllib.request, 'urlopen', return_value=token_response()), \
         patch.object(release, 'registry_get', side_effect=[{'config': {'digest': 'sha256:test'}}, {'config': {'Labels': {}}}]):
        with pytest.raises(AssertionError, match='ownership label'):
            release.main()
