from __future__ import annotations

import base64
import http.client
import json
import threading
import time

import pytest

from weasyprint.replica_api import create_replica_api_server


@pytest.fixture(name='replica_api_server')
def fixture_replica_api_server():
    server = create_replica_api_server(host='127.0.0.1', port=0)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={'poll_interval': 0.1},
        daemon=True,
    )
    thread.start()

    try:
        _wait_for_server(server)
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _wait_for_server(server, timeout: float = 5.0) -> None:
    port = server.server_address[1]
    deadline = time.time() + timeout
    while time.time() < deadline:
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
        try:
            connection.request('GET', '/health')
            response = connection.getresponse()
            response.read()
            if response.status == 200:
                return
        except OSError:
            time.sleep(0.05)
        finally:
            connection.close()
    raise RuntimeError('Replica API test server did not start in time')


def _post_json(
    port: int, path: str, payload: dict[str, object]
) -> tuple[http.client.HTTPResponse, http.client.HTTPConnection]:
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    body = json.dumps(payload)
    headers = {'Content-Type': 'application/json'}
    connection.request('POST', path, body=body, headers=headers)
    response = connection.getresponse()
    return response, connection


def test_replica_api_returns_pdf(replica_api_server):
    port = replica_api_server.server_address[1]
    response, connection = _post_json(
        port,
        '/replica/convert',
        {
            'source': '<!DOCTYPE html><html><body><p>Hello Replica API</p></body></html>',
        },
    )

    body = response.read()
    response.close()
    connection.close()

    assert response.status == 200
    assert response.getheader('Content-Type') == 'application/pdf'
    assert response.getheader('Content-Disposition') == 'attachment'
    assert body.startswith(b'%PDF')


def test_replica_api_json_response(replica_api_server):
    port = replica_api_server.server_address[1]
    encoded_source = base64.b64encode(
        b'<!DOCTYPE html><html><body><p>JSON response</p></body></html>'
    ).decode('ascii')

    response, connection = _post_json(
        port,
        '/replica/convert',
        {
            'source': encoded_source,
            'source_is_base64': True,
            'response': 'json',
            'filename': 'custom.pdf',
        },
    )

    body = response.read()
    response.close()
    connection.close()

    assert response.status == 200
    assert response.getheader('Content-Type') == 'application/json'

    payload = json.loads(body.decode('utf-8'))
    pdf_bytes = base64.b64decode(payload['pdf'])
    assert pdf_bytes.startswith(b'%PDF')
