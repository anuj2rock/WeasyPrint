import logging
from email.generator import BytesGenerator
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import tinyhtml5

from weasyprint.replica import ReplicaConverter, create_replica_demo_bundle


def _write_message(path: Path, message: MIMEMultipart) -> None:
    with path.open('wb') as file_obj:
        generator = BytesGenerator(file_obj)
        generator.flatten(message)


def test_sanitizes_document_structure(tmp_path):
    converter = ReplicaConverter()
    html = '<p>Hello world</p>'
    root = converter._sanitize_html(html, tmp_path)
    assert root.find('head') is not None
    assert root.find('body') is not None
    title = root.find('head').find('title')
    assert title is not None
    assert title.text == 'Document'


def test_mhtml_resources_are_extracted(tmp_path):
    message = MIMEMultipart('related')
    html_part = MIMEText('<html><body><img src="cid:image1"></body></html>', 'html', 'utf-8')
    html_part.add_header('Content-Location', 'index.html')
    message.attach(html_part)

    image_part = MIMEBase('image', 'png')
    image_part.add_header('Content-ID', '<image1>')
    image_part.add_header('Content-Location', 'image.png')
    image_part.set_payload(b'binary-data')
    message.attach(image_part)

    archive = tmp_path / 'archive.mhtml'
    _write_message(archive, message)

    converter = ReplicaConverter()
    workdir = tmp_path / 'work'
    workdir.mkdir()
    html, base_url = converter._load_source(archive, workdir)

    assert 'cid:' not in html
    assert 'image.png' in html
    assert base_url is not None
    extracted = next(workdir.iterdir())
    assert extracted.read_bytes() == b'binary-data'


def test_html_base_url_uses_absolute_path(tmp_path, monkeypatch):
    html_path = tmp_path / 'report.html'
    html_path.write_text('<html><body>hi</body></html>')
    monkeypatch.chdir(tmp_path)

    converter = ReplicaConverter()
    html, base_url = converter._load_source(Path('report.html'), tmp_path / 'work')

    assert '<body>hi</body>' in html
    assert base_url == tmp_path.as_uri()


def test_missing_fonts_trigger_warning(tmp_path, caplog):
    html = (
        '<html><head><style>@font-face { src: url("fonts/Missing.woff2"); }'
        '</style></head><body></body></html>'
    )
    tree = tinyhtml5.parse(html, namespace_html_elements=False)

    converter = ReplicaConverter()
    caplog.set_level(logging.WARNING, logger='weasyprint')
    converter._check_fonts(tree, tmp_path.as_uri())

    messages = ' '.join(record.getMessage() for record in caplog.records)
    assert 'fonts/Missing.woff2' in messages
    assert 'Bundle them' in messages


def test_demo_bundle_generates_pdf(tmp_path):
    html_path = create_replica_demo_bundle(tmp_path)
    converter = ReplicaConverter()
    output_pdf = tmp_path / 'demo.pdf'
    converter.convert(html_path, output_pdf, check_fonts=False)

    assert html_path.exists()
    assert output_pdf.exists()
