"""Tests for the FastAPI integration."""

import base64

import pytest

fastapi = pytest.importorskip('fastapi')
from fastapi.testclient import TestClient  # noqa: E402

from weasyprint.api import app


@pytest.fixture()
def client():
    return TestClient(app)


def test_generate_pdf_with_logs(client):
    response = client.post('/v1/pdf', json={
        'html': '<html><body><h1>Hello</h1><p>API</p></body></html>',
        'stylesheets': [{'string': 'body { color: #333 } h1 { color: #900; }'}],
    })
    assert response.status_code == 200
    payload = response.json()
    pdf_bytes = base64.b64decode(payload['pdf'])
    assert pdf_bytes.startswith(b'%PDF')
    for step in range(1, 8):
        assert f'Step {step}' in payload['progress_log']
    assert 'WARNING:' not in payload['log']
    assert payload['warnings'] == []


def test_invalid_pdf_options_are_rejected(client):
    response = client.post('/v1/pdf', json={
        'html': '<p>Oops</p>',
        'pdf_options': {'unknown_option': True},
    })
    assert response.status_code == 422
    detail = response.json()['detail']
    assert 'Unsupported pdf_options' in detail[0]['msg']
