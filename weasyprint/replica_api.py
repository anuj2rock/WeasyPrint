"""Minimal HTTP API exposing :mod:`weasyprint.replica` helpers."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

from .logger import LOGGER
from .replica import ReplicaConverter

__all__ = [
    'ReplicaAPIHandler',
    'create_replica_api_server',
    'serve_replica_api',
]


def _build_handler(
    *,
    logger: logging.Logger,
    converter: ReplicaConverter,
) -> type['ReplicaAPIHandler']:
    class CustomReplicaAPIHandler(ReplicaAPIHandler):
        pass

    CustomReplicaAPIHandler.logger = logger
    CustomReplicaAPIHandler.converter = converter
    return CustomReplicaAPIHandler


class ReplicaAPIHandler(BaseHTTPRequestHandler):
    """Expose :class:`ReplicaConverter` through HTTP endpoints."""

    converter: ClassVar[ReplicaConverter] = ReplicaConverter()
    logger: ClassVar[logging.Logger] = LOGGER

    protocol_version = 'HTTP/1.1'
    server_version = 'WeasyPrintReplicaAPI/1.0'
    sys_version = ''

    def do_GET(self) -> None:  # noqa: D401 - inherited documentation
        path = self._normalized_path()
        if path in {'/', '/replica', '/replica/'}:
            self._json_response(HTTPStatus.OK, {'service': 'weasyprint-replica', 'status': 'ok'})
            return
        if path in {'/health', '/replica/health'}:
            self._json_response(HTTPStatus.OK, {'status': 'ok'})
            return
        self._json_response(HTTPStatus.NOT_FOUND, {'error': 'Endpoint not found'})

    def do_POST(self) -> None:  # noqa: D401 - inherited documentation
        path = self._normalized_path()
        if path == '/replica/convert':
            self._handle_convert()
            return
        self._json_response(HTTPStatus.NOT_FOUND, {'error': 'Endpoint not found'})

    def _handle_convert(self) -> None:
        try:
            payload = self._read_json_body()
        except ValueError as exc:
            self._json_response(HTTPStatus.BAD_REQUEST, {'error': str(exc)})
            return

        source = payload.get('source')
        if not isinstance(source, str) or not source:
            self._json_response(
                HTTPStatus.BAD_REQUEST,
                {'error': 'Request payload must include a non-empty "source" string'},
            )
            return

        source_format = str(payload.get('format', 'html')).lower()
        if source_format not in {'html', 'mhtml'}:
            self._json_response(
                HTTPStatus.BAD_REQUEST,
                {'error': '"format" must be either "html" or "mhtml"'},
            )
            return

        encoding = payload.get('encoding', 'utf-8')
        if not isinstance(encoding, str) or not encoding:
            self._json_response(
                HTTPStatus.BAD_REQUEST,
                {'error': '"encoding" must be a non-empty string'},
            )
            return

        extra_css = payload.get('extra_css')
        if extra_css is not None:
            if not isinstance(extra_css, list) or not all(isinstance(item, str) for item in extra_css):
                self._json_response(
                    HTTPStatus.BAD_REQUEST,
                    {'error': '"extra_css" must be a list of strings when provided'},
                )
                return

        pdf_options = payload.get('pdf_options') or {}
        if not isinstance(pdf_options, dict):
            self._json_response(
                HTTPStatus.BAD_REQUEST,
                {'error': '"pdf_options" must be an object containing PDF options'},
            )
            return

        source_is_base64 = bool(payload.get('source_is_base64', False))
        try:
            with tempfile.TemporaryDirectory(prefix='weasyprint-replica-api-') as tempdir:
                workdir = Path(tempdir)
                input_target = self._write_request_payload(
                    source,
                    source_format,
                    encoding,
                    source_is_base64,
                    workdir,
                )
                output_target = workdir / 'document.pdf'

                presentational_hints = payload.get('presentational_hints', True)
                check_fonts = payload.get('check_fonts', True)
                base_url = payload.get('base_url')

                if not isinstance(presentational_hints, bool):
                    self._json_response(
                        HTTPStatus.BAD_REQUEST,
                        {'error': '"presentational_hints" must be a boolean when provided'},
                    )
                    return
                if not isinstance(check_fonts, bool):
                    self._json_response(
                        HTTPStatus.BAD_REQUEST,
                        {'error': '"check_fonts" must be a boolean when provided'},
                    )
                    return
                if base_url is not None and not isinstance(base_url, str):
                    self._json_response(
                        HTTPStatus.BAD_REQUEST,
                        {'error': '"base_url" must be a string when provided'},
                    )
                    return

                response_mode = str(payload.get('response', 'pdf')).lower()
                if response_mode not in {'pdf', 'json'}:
                    self._json_response(
                        HTTPStatus.BAD_REQUEST,
                        {'error': '"response" must be either "pdf" or "json"'},
                    )
                    return

                filename = payload.get('filename')
                if filename is not None and not isinstance(filename, str):
                    self._json_response(
                        HTTPStatus.BAD_REQUEST,
                        {'error': '"filename" must be a string when provided'},
                    )
                    return

                try:
                    self.converter.convert(
                        input_target,
                        output_target,
                        base_url=base_url,
                        presentational_hints=presentational_hints,
                        check_fonts=check_fonts,
                        extra_css=extra_css,
                        **pdf_options,
                    )
                except Exception as exc:  # noqa: BLE001
                    self.logger.exception('Replica conversion failed')
                    self._json_response(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {'error': f'Conversion failed: {exc}'},
                    )
                    return

                pdf_bytes = output_target.read_bytes()
        except ValueError as exc:
            self._json_response(HTTPStatus.BAD_REQUEST, {'error': str(exc)})
            return

        if response_mode == 'json':
            encoded = base64.b64encode(pdf_bytes).decode('ascii')
            self._json_response(HTTPStatus.OK, {'pdf': encoded})
            return

        disposition = f'attachment; filename="{filename}"' if filename else 'attachment'
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', 'application/pdf')
        self.send_header('Content-Length', str(len(pdf_bytes)))
        self.send_header('Content-Disposition', disposition)
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(pdf_bytes)

    # -- helpers -----------------------------------------------------
    def _normalized_path(self) -> str:
        parsed = urlparse(self.path)
        normalized = parsed.path or '/'
        if normalized != '/' and normalized.endswith('/'):
            normalized = normalized[:-1]
        return normalized or '/'

    def _read_json_body(self) -> dict[str, Any]:
        content_length = self.headers.get('Content-Length')
        if content_length is None:
            raise ValueError('Missing Content-Length header')
        try:
            length = int(content_length)
        except ValueError as exc:
            raise ValueError('Invalid Content-Length header') from exc

        data = self.rfile.read(length)
        if not data:
            raise ValueError('Request body is empty')
        try:
            return json.loads(data.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError('Request body must be valid UTF-8 encoded JSON') from exc

    def _write_request_payload(
        self,
        source: str,
        source_format: str,
        encoding: str,
        source_is_base64: bool,
        target_directory: Path,
    ) -> Path:
        suffix = '.html' if source_format == 'html' else '.mhtml'
        target = target_directory / f'upload{suffix}'

        if source_format == 'html':
            html_text = self._decode_html_source(source, encoding, source_is_base64)
            target.write_text(html_text, encoding='utf-8')
        else:
            raw_bytes = self._decode_binary_source(source, encoding, source_is_base64)
            target.write_bytes(raw_bytes)

        return target

    def _decode_html_source(
        self, source: str, encoding: str, source_is_base64: bool
    ) -> str:
        if source_is_base64:
            try:
                raw = base64.b64decode(source)
            except (ValueError, binascii.Error) as exc:
                raise ValueError('Unable to decode base64 HTML payload') from exc
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError as exc:
                raise ValueError('Unable to decode HTML payload using the given encoding') from exc
        return source

    def _decode_binary_source(
        self, source: str, encoding: str, source_is_base64: bool
    ) -> bytes:
        if source_is_base64:
            try:
                return base64.b64decode(source)
            except (ValueError, binascii.Error) as exc:
                raise ValueError('Unable to decode base64 payload') from exc
        return source.encode(encoding)

    def _json_response(self, status: HTTPStatus, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - BaseHTTPRequestHandler API
        self.logger.info('%s - - [%s] %s', self.client_address[0], self.log_date_time_string(), format % args)


def create_replica_api_server(
    *,
    host: str = '127.0.0.1',
    port: int = 8080,
    logger: logging.Logger | None = None,
    converter: ReplicaConverter | None = None,
) -> ThreadingHTTPServer:
    """Create a configured :class:`ThreadingHTTPServer` instance."""

    effective_logger = logger or LOGGER
    effective_converter = converter or ReplicaConverter()
    handler = _build_handler(logger=effective_logger, converter=effective_converter)
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve_replica_api(
    *,
    host: str = '127.0.0.1',
    port: int = 8080,
    logger: logging.Logger | None = None,
    converter: ReplicaConverter | None = None,
) -> None:
    """Start serving the Replica API until interrupted."""

    server = create_replica_api_server(
        host=host,
        port=port,
        logger=logger,
        converter=converter,
    )

    effective_logger = logger or LOGGER
    effective_logger.info('Replica API listening on http://%s:%d', host, server.server_address[1])

    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - manual interruption
        effective_logger.info('Replica API shutdown requested')
    finally:
        server.server_close()
