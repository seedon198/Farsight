"""Tests for farsight.modules.report_writer."""

import pytest

from farsight.modules.report_writer import ReportWriter, PDF_SUPPORT


@pytest.fixture
def report_writer(tmp_path):
    return ReportWriter(output_dir=tmp_path)


def test_generate_report_writes_markdown_file(report_writer, tmp_path):
    results = {
        "org": {
            "whois": {"registrar": "Example Registrar"},
            "related_domains": ["example.net"],
            "certificate_transparency": ["www.example.com"],
        }
    }
    output_file = tmp_path / "report.md"

    path = report_writer.generate_report(
        results=results,
        target="example.com",
        depth=1,
        modules=["org"],
        output_file=output_file,
    )

    assert path == output_file
    content = output_file.read_text()
    assert "FARSIGHT Reconnaissance Report" in content
    assert "example.com" in content
    assert "Example Registrar" in content


@pytest.mark.skipif(not PDF_SUPPORT, reason="reportlab not installed")
def test_convert_to_pdf_handles_special_characters_without_crashing(
    report_writer, tmp_path
):
    """Regression test: unescaped '<', '&', etc. passed straight into
    reportlab's Paragraph (which parses a mini-XML markup language)
    used to raise and get swallowed, silently producing no PDF.
    """
    md_file = tmp_path / "report.md"
    md_file.write_text(
        "# Test Report\n\n"
        "Findings for R&D <admin@example.com> include AT&T style entries "
        "and a <script>alert(1)</script> tag.\n"
    )

    pdf_path = report_writer.convert_to_pdf(md_file)

    assert pdf_path is not None
    assert pdf_path.exists()
    assert pdf_path.suffix == ".pdf"
    assert pdf_path.read_bytes().startswith(b"%PDF")


@pytest.mark.skipif(not PDF_SUPPORT, reason="reportlab not installed")
def test_convert_to_pdf_missing_file_returns_none(report_writer, tmp_path):
    missing = tmp_path / "does_not_exist.md"
    assert report_writer.convert_to_pdf(missing) is None


def test_render_org_section_handles_empty_results(report_writer):
    section = report_writer._render_org_section({})
    assert "No related domains discovered." in section
    assert "No certificate transparency data available." in section
