"""FastAPI application that exposes WeasyPrint as an HTTP service."""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List, Optional

from . import DEFAULT_OPTIONS, HTML, Attachment, CSS, LOGGER, PROGRESS_LOGGER, __version__

try:  # pragma: no cover - exercised in tests when dependency is installed
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field, model_validator
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        'FastAPI support requires the "weasyprint[api]" extra. '
        'Install it with "pip install \"weasyprint[api]\"".'
    ) from exc


class _BaseSource(BaseModel):
    """Common descriptor for string/URL/filename inputs."""

    string: Optional[str] = None
    url: Optional[str] = None
    filename: Optional[str] = None
    base_url: Optional[str] = None

    @model_validator(mode='after')
    def _check_source(self):  # noqa: B902
        fields = ['string', 'url', 'filename']
        defined = [name for name in fields if getattr(self, name) is not None]
        if len(defined) != 1:
            raise ValueError('Provide exactly one of string, url or filename.')
        return self


class StylesheetDescriptor(_BaseSource):
    """Descriptor used to build CSS objects from API requests."""


class AttachmentDescriptor(_BaseSource):
    """Descriptor used to build Attachment objects from API requests."""

    name: Optional[str] = None
    description: Optional[str] = None
    relationship: Optional[str] = None


def _decode_html_payload(html: Optional[str], html_base64: Optional[str]) -> str:
    """Return normalized HTML payload from raw or base64 input."""

    provided = [value is not None for value in (html, html_base64)]
    if sum(provided) != 1:
        raise ValueError('Provide exactly one of html or html_base64.')
    if html is not None:
        return html
    assert html_base64 is not None
    try:
        decoded = base64.b64decode(html_base64, validate=True).decode('utf-8')
    except (ValueError, UnicodeDecodeError) as exc:  # pragma: no cover - tiny helper
        raise ValueError('Invalid base64-encoded html payload.') from exc
    return decoded


class PdfRequest(BaseModel):
    """Request body for PDF generation."""

    html: Optional[str] = None
    html_base64: Optional[str] = None
    base_url: Optional[str] = None
    stylesheets: List[StylesheetDescriptor] = Field(default_factory=list)
    attachments: List[AttachmentDescriptor] = Field(default_factory=list)
    pdf_options: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode='after')
    def _filter_pdf_options(self):  # noqa: B902
        options = self.pdf_options
        unknown = set(options) - set(DEFAULT_OPTIONS)
        if unknown:
            raise ValueError(
                'Unsupported pdf_options: ' + ', '.join(sorted(unknown)))
        filtered = {
            key: value for key, value in options.items()
            if value is not None and key in DEFAULT_OPTIONS}
        self.pdf_options = filtered
        return self

    @model_validator(mode='after')
    def _normalize_html_payload(self):  # noqa: B902
        self.html = _decode_html_payload(self.html, self.html_base64)
        self.html_base64 = None
        return self


class PdfResponse(BaseModel):
    """Response returned by the API."""

    pdf: str
    log: str
    progress_log: str
    warnings: List[str]


class _BufferHandler(logging.Handler):
    """Logging handler storing formatted records in memory."""

    def __init__(self, formatter: logging.Formatter):
        super().__init__()
        self._formatter = formatter
        self.records: List[str] = []

    def emit(self, record: logging.LogRecord):  # pragma: no cover - tiny helper
        self.records.append(self._formatter.format(record))

    def flush_messages(self) -> str:
        return '\n'.join(self.records).strip()

    def flush_warnings(self) -> List[str]:
        return [record for record in self.records if record.startswith('WARNING:')]


def _build_css(descriptor: StylesheetDescriptor) -> CSS:
    kwargs: Dict[str, Any] = {'base_url': descriptor.base_url}
    if descriptor.string is not None:
        kwargs['string'] = descriptor.string
    elif descriptor.url is not None:
        kwargs['url'] = descriptor.url
    else:
        kwargs['filename'] = descriptor.filename
    return CSS(**kwargs)


def _build_attachment(descriptor: AttachmentDescriptor) -> Attachment:
    kwargs: Dict[str, Any] = {
        'base_url': descriptor.base_url,
        'name': descriptor.name,
        'description': descriptor.description,
        'relationship': descriptor.relationship,
    }
    kwargs = {key: value for key, value in kwargs.items() if value is not None}
    if descriptor.string is not None:
        kwargs['string'] = descriptor.string
    elif descriptor.url is not None:
        kwargs['url'] = descriptor.url
    else:
        kwargs['filename'] = descriptor.filename
    return Attachment(**kwargs)


def _configure_loggers() -> None:
    """Ensure WeasyPrint loggers emit INFO messages."""

    LOGGER.setLevel(logging.INFO)
    PROGRESS_LOGGER.setLevel(logging.INFO)


_configure_loggers()

app = FastAPI(title='WeasyPrint API', version=__version__)


@app.post('/v1/pdf', response_model=PdfResponse)
def create_pdf(request: PdfRequest) -> PdfResponse:  # pragma: no cover - covered via tests
    log_handler = _BufferHandler(logging.Formatter('%(levelname)s: %(message)s'))
    progress_handler = _BufferHandler(logging.Formatter('%(message)s'))

    LOGGER.addHandler(log_handler)
    PROGRESS_LOGGER.addHandler(progress_handler)

    try:
        css = [_build_css(descriptor) for descriptor in request.stylesheets]
        attachments = [
            _build_attachment(descriptor) for descriptor in request.attachments]
        options = DEFAULT_OPTIONS.copy()
        options.update(request.pdf_options)
        options['stylesheets'] = css or None
        options['attachments'] = attachments or None
        pdf_bytes = HTML(string=request.html, base_url=request.base_url).write_pdf(
            **options,
        )
    except Exception as exc:  # pragma: no cover - error path
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        LOGGER.removeHandler(log_handler)
        PROGRESS_LOGGER.removeHandler(progress_handler)

    pdf_base64 = base64.b64encode(pdf_bytes).decode('ascii')
    log = log_handler.flush_messages()
    progress_log = progress_handler.flush_messages()

    return PdfResponse(
        pdf=pdf_base64,
        log=log,
        progress_log=progress_log,
        warnings=log_handler.flush_warnings(),
    )


def main() -> None:  # pragma: no cover - exercised manually
    """Run the FastAPI application using Uvicorn."""

    import uvicorn

    uvicorn.run('weasyprint.api:app', host='127.0.0.1', port=8000, reload=False)


__all__ = ['app', 'main', 'PdfRequest', 'PdfResponse']
