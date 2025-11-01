"""High-level helpers to render pixel-perfect PDFs from legacy HTML."""

from __future__ import annotations

import argparse
import base64
import logging
import os
import tempfile
import textwrap
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import urljoin

import tinycss2
import tinyhtml5
from xml.etree import ElementTree as etree

from . import CSS, DEFAULT_OPTIONS, HTML
from .logger import LOGGER
from .urls import default_url_fetcher

__all__ = [
    'ReplicaConversionResult',
    'ReplicaConverter',
    'convert_html_to_pdf',
    'create_replica_demo_bundle',
]


SANITIZED_DOCTYPE = '<!DOCTYPE html>'
RESOURCE_ATTRIBUTES = {
    'img': ('src',),
    'image': ('href', 'xlink:href'),
    'script': ('src',),
    'link': ('href',),
    'source': ('src', 'srcset'),
    'video': ('poster',),
    'audio': ('src',),
    'use': ('href', 'xlink:href'),
}

DEMO_IMAGE = base64.b64decode(
    'iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJ'
    'bWFnZVJlYWR5ccllPAAAAGNJREFUeNrs0cENgDAMQ9GNtN1rFCxgOznKXSPBDUY5lJQAAAAAAAPgE'
    '3u9nCx8AAAAAAAAAAAAAAD4J/AKAAAD//wMAAAH+AQYAAMycA2AAAAAASUVORK5CYII='
)

DEMO_HTML_TEMPLATE = textwrap.dedent(
    """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>Legacy Report Demo</title>
        <style>
          body {
            font-family: "Helvetica Neue", Arial, sans-serif;
            background: #f2f4f8;
            margin: 0;
            padding: 32px;
            color: #1f2933;
          }
          header {
            background: linear-gradient(135deg, #1d4ed8, #3b82f6);
            color: white;
            padding: 24px 32px;
            border-radius: 16px;
            box-shadow: 0 12px 24px rgba(29, 78, 216, 0.3);
          }
          header h1 {
            margin: 0;
            font-size: 32px;
          }
          main {
            background: white;
            margin-top: 24px;
            padding: 24px 32px;
            border-radius: 16px;
            box-shadow: 0 6px 18px rgba(15, 23, 42, 0.08);
          }
          .hero {
            display: grid;
            grid-template-columns: 240px 1fr;
            gap: 24px;
            align-items: center;
            margin-bottom: 32px;
          }
          .hero img {
            width: 240px;
            border-radius: 12px;
            box-shadow: 0 6px 20px rgba(15, 23, 42, 0.24);
          }
          .hero p {
            font-size: 15px;
            line-height: 1.6;
            margin: 0;
          }
          table {
            border-collapse: collapse;
            width: 100%;
            font-size: 14px;
          }
          thead th {
            background: #1d4ed8;
            color: white;
            padding: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
          }
          tbody td {
            padding: 12px;
            border-bottom: 1px solid #d5dce6;
          }
          tbody tr:nth-child(odd) td {
            background: #f8fafc;
          }
          .svg-card {
            margin-top: 32px;
            padding: 24px;
            border: 2px solid #2563eb;
            border-radius: 16px;
            background: radial-gradient(circle at top, rgba(59, 130, 246, 0.12), white);
          }
          .svg-card h2 {
            margin: 0 0 16px;
            font-size: 20px;
            color: #1d4ed8;
          }
          svg text {
            font-size: 14px;
            font-weight: 600;
            fill: #1f2933;
          }
        </style>
      </head>
      <body>
        <header>
          <h1>Quarterly Field Report</h1>
          <p>Generated from a legacy HTML export and rendered with WeasyPrint.</p>
        </header>
        <main>
          <section class="hero">
            <img src="__IMAGE_PATH__" alt="A scenic overlook">
            <p>
              This sample demonstrates how ReplicaConverter preserves legacy layouts.
              It includes text, tabular data, raster imagery, and layered SVG graphics
              that would typically appear in hand-crafted HTML reports.
            </p>
          </section>
          <section>
            <table>
              <thead>
                <tr>
                  <th scope="col">Site</th>
                  <th scope="col">Status</th>
                  <th scope="col">Notes</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>North Ridge</td>
                  <td>On Track</td>
                  <td>Equipment upgrades completed on schedule.</td>
                </tr>
                <tr>
                  <td>Harbor View</td>
                  <td>Attention</td>
                  <td>Awaiting updated permits from the city office.</td>
                </tr>
                <tr>
                  <td>South Valley</td>
                  <td>Completed</td>
                  <td>All milestones approved by stakeholders.</td>
                </tr>
              </tbody>
            </table>
          </section>
          <section class="svg-card">
            <h2>Telemetry Overview</h2>
            <svg viewBox="0 0 420 160" role="img" aria-label="Progress metrics">
              <rect x="24" y="32" width="360" height="16" fill="#dbeafe" />
              <rect x="24" y="32" width="280" height="16" fill="#3b82f6" />
              <rect x="24" y="80" width="360" height="16" fill="#dbeafe" />
              <rect x="24" y="80" width="180" height="16" fill="#38bdf8" />
              <text x="24" y="28">Deployment Progress</text>
              <text x="320" y="28">78%</text>
              <text x="24" y="124">Calibration Coverage</text>
              <text x="280" y="124">50%</text>
            </svg>
          </section>
        </main>
      </body>
    </html>
    """
)

@dataclass
class ReplicaConversionResult:
    """Details about the sanitization stage."""

    html: str
    tree: etree.Element
    base_url: Optional[str]
    work_directory: Optional[Path] = None
    extra_stylesheets: List[CSS] = field(default_factory=list)


class ReplicaConverter:
    """Normalize foreign HTML before letting WeasyPrint render it."""

    def __init__(
        self,
        *,
        url_fetcher=default_url_fetcher,
        logger: logging.Logger = LOGGER,
    ) -> None:
        self.url_fetcher = url_fetcher
        self.logger = logger

    # -- Public API -----------------------------------------------------
    def convert(
        self,
        input_path: os.PathLike[str] | str,
        output_path: os.PathLike[str] | str,
        *,
        base_url: Optional[str] = None,
        presentational_hints: bool = True,
        check_fonts: bool = True,
        extra_css: Optional[Sequence[str]] = None,
        **pdf_options,
    ) -> None:
        """Convert ``input_path`` into ``output_path`` as a PDF."""

        with self._prepare_document(Path(input_path)) as result:
            normalized_base_url = base_url or result.base_url
            if normalized_base_url is None and result.work_directory is not None:
                normalized_base_url = result.work_directory.as_uri()

            stylesheets = list(result.extra_stylesheets)
            if extra_css:
                stylesheets.extend(CSS(string=string) for string in extra_css)

            if check_fonts:
                self._check_fonts(result.tree, normalized_base_url)

            options = dict(DEFAULT_OPTIONS)
            options.update(pdf_options)
            options['presentational_hints'] = presentational_hints
            if stylesheets:
                options['stylesheets'] = stylesheets

            html = HTML(
                string=result.html,
                base_url=normalized_base_url,
                url_fetcher=self.url_fetcher,
            )
            html.write_pdf(output_path, **options)

    # -- Helpers --------------------------------------------------------
    @contextmanager
    def _prepare_document(self, source: Path) -> Iterator[ReplicaConversionResult]:
        if not source.exists():
            raise FileNotFoundError(source)

        with tempfile.TemporaryDirectory(prefix='weasyprint-replica-') as tempdir:
            workdir = Path(tempdir)
            html_text, base_url = self._load_source(source, workdir)
            tree = self._sanitize_html(html_text, workdir)
            normalized_html = self._serialize_tree(tree)
            result = ReplicaConversionResult(
                html=normalized_html,
                tree=tree,
                base_url=base_url,
                work_directory=workdir,
                extra_stylesheets=[],
            )
            yield result

    def _load_source(self, source: Path, workdir: Path) -> Tuple[str, Optional[str]]:
        if source.suffix.lower() in {'.mhtml', '.mht'}:
            return self._load_mhtml(source, workdir)
        return self._load_html(source)

    def _load_html(self, source: Path) -> Tuple[str, Optional[str]]:
        data = source.read_bytes()
        element = tinyhtml5.parse(data, namespace_html_elements=False)
        html = self._serialize_tree(element)
        absolute_source = source.resolve()
        try:
            base_url = absolute_source.parent.as_uri()
        except ValueError:
            base_url = None
        return html, base_url

    def _load_mhtml(self, source: Path, workdir: Path) -> Tuple[str, Optional[str]]:
        with source.open('rb') as file_obj:
            message = BytesParser(policy=policy.default).parse(file_obj)
        html_payload, resources, base_url = self._extract_mhtml_parts(message, workdir)
        sanitized_html = self._rewrite_resource_references(html_payload, resources)
        return sanitized_html, base_url

    def _extract_mhtml_parts(
        self, message: Message, workdir: Path
    ) -> Tuple[str, Mapping[str, Path], Optional[str]]:
        html_payload: Optional[str] = None
        resources: MutableMapping[str, Path] = {}
        base_url: Optional[str] = None
        counter = defaultdict(int)
        used_names: set[str] = set()

        for part in message.walk():
            if part.is_multipart():
                continue

            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            charset = part.get_content_charset() or 'utf-8'
            content_location = part.get('Content-Location')
            content_id = part.get('Content-ID')

            if content_type == 'text/html' and html_payload is None:
                html_payload = payload.decode(charset, errors='replace')
                if content_location:
                    try:
                        base_url = Path(content_location).parent.as_uri()
                    except ValueError:
                        base_url = None
                continue

            filename = part.get_filename()
            name = filename or content_location or (content_id or '').strip('<>')
            suffix = Path(filename or '').suffix
            counter_key = suffix or part.get_content_subtype()
            counter[counter_key] += 1
            if not name:
                name = f'resource-{counter[counter_key]}'
                if suffix:
                    name += suffix

            safe_name = self._safe_filename(name, counter[counter_key], used_names)
            target = workdir / safe_name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)

            if content_location:
                resources[content_location] = target
            if content_id:
                resources[f'cid:{content_id.strip("<>")}'] = target
            if filename:
                resources[filename] = target

        if html_payload is None:
            raise ValueError('MHTML archive does not contain an HTML part')
        if base_url is None:
            base_url = workdir.as_uri()
        return html_payload, resources, base_url

    def _safe_filename(
        self, name: str, counter: int, used_names: set[str]
    ) -> str:
        candidate = Path(name).name or f'resource-{counter}'
        stem = Path(candidate).stem or 'resource'
        suffix = Path(candidate).suffix
        unique_candidate = candidate
        while unique_candidate in used_names:
            counter += 1
            unique_candidate = f'{stem}-{counter}{suffix}'
        used_names.add(unique_candidate)
        return unique_candidate

    def _rewrite_resource_references(
        self, html_payload: str, resources: Mapping[str, Path]
    ) -> str:
        rewritten = html_payload
        for original, target in resources.items():
            relative = target.name
            if original in rewritten:
                rewritten = rewritten.replace(original, relative)
            encoded_original = original.replace(' ', '%20')
            if encoded_original in rewritten:
                rewritten = rewritten.replace(encoded_original, relative)
        return rewritten

    def _sanitize_html(self, html: str, workdir: Path) -> etree.Element:
        root = tinyhtml5.parse(html, namespace_html_elements=False)
        self._ensure_document_structure(root)
        self._normalize_resources(root)
        self._inject_charset(root)
        return root

    def _ensure_document_structure(self, root: etree.Element) -> None:
        head = root.find('head')
        body = root.find('body')
        if head is None:
            head = etree.Element('head')
            root.insert(0, head)
        if body is None:
            body = etree.Element('body')
            root.append(body)
        if head.find('title') is None:
            title = etree.SubElement(head, 'title')
            title.text = 'Document'

    def _inject_charset(self, root: etree.Element) -> None:
        head = root.find('head')
        if head is None:
            return
        existing = next((
            element for element in head.findall('meta')
            if element.get('charset') or element.get('http-equiv', '').lower() == 'content-type'
        ), None)
        if existing is None:
            meta = etree.Element('meta', charset='utf-8')
            head.insert(0, meta)

    def _normalize_resources(self, root: etree.Element) -> None:
        for element in root.iter():
            attributes = RESOURCE_ATTRIBUTES.get(element.tag)
            if not attributes:
                continue
            for attribute in attributes:
                value = element.get(attribute)
                if not value:
                    continue
                if attribute == 'srcset':
                    candidates = [part.strip() for part in value.split(',') if part.strip()]
                    element.set(attribute, ', '.join(candidates))

    def _serialize_tree(self, root: etree.Element) -> str:
        html = etree.tostring(root, encoding='unicode', method='html')
        return f'{SANITIZED_DOCTYPE}\n{html}'

    def _check_fonts(self, tree: etree.Element, base_url: Optional[str]) -> None:
        stylesheets = list(self._iter_css(tree, base_url))
        if not stylesheets:
            return
        missing_sources: List[str] = []
        for css_text, origin in stylesheets:
            for font_url in self._extract_font_urls(css_text):
                resolved = self._resolve_url(font_url, base_url)
                if resolved is None:
                    missing_sources.append(font_url)
                    continue
                result = None
                try:
                    result = self.url_fetcher(resolved)
                except Exception as exc:  # noqa: BLE001
                    self.logger.warning(
                        'Unable to load font %s referenced from %s: %s',
                        font_url,
                        origin,
                        exc,
                    )
                    missing_sources.append(font_url)
                    continue
                if result is not None:
                    file_obj = result.get('file_obj')
                    if file_obj is not None:
                        file_obj.close()
        if missing_sources:
            unique = sorted(set(missing_sources))
            self.logger.warning(
                'The following fonts are missing. Bundle them with the input '
                'HTML to avoid fallbacks: %s',
                ', '.join(unique),
            )

    def _iter_css(
        self, tree: etree.Element, base_url: Optional[str]
    ) -> Iterator[Tuple[str, str]]:
        for element in tree.iter('style'):
            if element.text:
                yield element.text, '<style>'
        for link in tree.iter('link'):
            rel = link.get('rel', '').lower()
            href = link.get('href')
            if 'stylesheet' not in rel or not href:
                continue
            resolved = self._resolve_url(href, base_url)
            if resolved is None:
                continue
            try:
                result = self.url_fetcher(resolved)
            except Exception:  # noqa: BLE001
                self.logger.warning('Unable to fetch stylesheet %s', href)
                continue
            css_text = self._read_url_fetcher_result(result)
            if css_text:
                yield css_text, href

    def _read_url_fetcher_result(self, result: Mapping[str, object]) -> Optional[str]:
        if 'string' in result and result['string'] is not None:
            return result['string']  # type: ignore[return-value]
        file_obj = result.get('file_obj')
        if file_obj is not None:
            data = file_obj.read()
            file_obj.close()
            if isinstance(data, bytes):
                return data.decode('utf-8', errors='replace')
            return str(data)
        filename = result.get('filename')
        if filename:
            return Path(filename).read_text('utf-8', errors='replace')
        return None

    def _resolve_url(self, url: str, base_url: Optional[str]) -> Optional[str]:
        cleaned = url.strip(' "\'')
        if cleaned.startswith('data:'):
            return cleaned
        if cleaned.startswith('cid:'):
            cleaned = cleaned.replace('cid:', '')
        if cleaned.startswith('file:') or cleaned.startswith('http'):
            return cleaned
        if base_url is None:
            return None
        return urljoin(base_url + ('/' if not base_url.endswith('/') else ''), cleaned)

    def _extract_font_urls(self, css_text: str) -> Iterator[str]:
        try:
            rules = tinycss2.parse_stylesheet(
                css_text,
                skip_comments=True,
                skip_whitespace=True,
            )
        except Exception:  # noqa: BLE001
            return
        for rule in rules:
            if rule.type != 'at-rule' or rule.lower_at_keyword != 'font-face':
                continue
            if not rule.content:
                continue
            declarations = tinycss2.parse_declaration_list(
                rule.content,
                skip_comments=True,
                skip_whitespace=True,
            )
            for declaration in declarations:
                if declaration.name.lower() != 'src':
                    continue
                for token in declaration.value:
                    token_type = getattr(token, 'type', None)
                    if token_type == 'url' and token.value:
                        yield token.value
                    elif (
                        token_type == 'function'
                        and getattr(token, 'lower_name', None) == 'url'
                    ):
                        for argument in getattr(token, 'arguments', []) or []:
                            if getattr(argument, 'type', None) == 'string':
                                yield argument.value
                                break


def convert_html_to_pdf(
    input_path: os.PathLike[str] | str,
    output_path: os.PathLike[str] | str,
    **kwargs,
) -> None:
    """Convenience wrapper around :class:`ReplicaConverter`."""

    converter = ReplicaConverter()
    converter.convert(input_path, output_path, **kwargs)


def create_replica_demo_bundle(target_dir: os.PathLike[str] | str) -> Path:
    """Create a demo legacy HTML bundle ready for PDF conversion.

    The returned directory contains an HTML entry point and supporting assets that
    exercise text, tables, raster images, and inline SVG overlays. The function
    returns the path to the generated HTML document.
    """

    root = Path(target_dir)
    root.mkdir(parents=True, exist_ok=True)
    assets = root / 'assets'
    assets.mkdir(parents=True, exist_ok=True)

    image_path = assets / 'legacy-photo.png'
    image_path.write_bytes(DEMO_IMAGE)

    html_path = root / 'legacy-report.html'
    html_path.write_text(
        DEMO_HTML_TEMPLATE.replace('__IMAGE_PATH__', f'assets/{image_path.name}'),
        encoding='utf-8',
    )
    return html_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='weasyprint-replica',
        description=(
            'Render legacy HTML archives into PDFs while preserving their layout.'
        ),
    )
    parser.add_argument('input', nargs='?', help='Path to the HTML or MHTML document')
    parser.add_argument('output', nargs='?', help='Destination PDF path')
    parser.add_argument(
        '--no-font-check',
        action='store_true',
        help='Skip validation that all referenced fonts are available',
    )
    parser.add_argument(
        '--no-presentational-hints',
        action='store_true',
        help='Disable HTML presentational hints',
    )
    parser.add_argument(
        '--extra-css',
        action='append',
        dest='extra_css',
        help='Add an additional stylesheet string applied after sanitization',
    )
    parser.add_argument(
        '--demo',
        action='store_true',
        help=(
            'Generate a sample legacy report bundle and render it to a PDF. '
            'When used, the input path is created automatically.'
        ),
    )
    parser.add_argument(
        '--demo-dir',
        help=(
            'Directory where the demo HTML and assets will be written. '
            'Defaults to a temporary folder when --demo is provided.'
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    converter = ReplicaConverter()

    if args.demo:
        if args.extra_css:
            parser.error('--extra-css cannot be combined with --demo')
        if args.input:
            parser.error('input path must not be provided when using --demo')
        demo_root = (
            Path(args.demo_dir)
            if args.demo_dir is not None
            else Path(tempfile.mkdtemp(prefix='weasyprint-replica-demo-'))
        )
        html_path = create_replica_demo_bundle(demo_root)
        output_path = Path(args.output or (demo_root / 'legacy-report.pdf'))
        LOGGER.info('Demo HTML written to %s', html_path)
        LOGGER.info('Rendering PDF demo to %s', output_path)
        converter.convert(
            html_path,
            output_path,
            presentational_hints=not args.no_presentational_hints,
            check_fonts=not args.no_font_check,
        )
        return

    if not args.input or not args.output:
        parser.error('input and output are required unless --demo is used')

    converter.convert(
        args.input,
        args.output,
        presentational_hints=not args.no_presentational_hints,
        check_fonts=not args.no_font_check,
        extra_css=args.extra_css,
    )


if __name__ == '__main__':  # pragma: no cover
    main()
