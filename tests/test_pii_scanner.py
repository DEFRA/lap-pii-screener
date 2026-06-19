"""Tests for scanners.pii_scanner — pure helpers, validators, regex patterns, parsing."""
from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

import pytest

from models.finding import ScanConfig
from scanners.pii_scanner import (
    PIIScanner,
    _classify_name_columns,
    _content_findings_for_pattern,
    _detect_csv_delimiter,
    _extract_binary_doc_from_bytes,
    _extract_eml_text,
    _find_csv_header_row,
    _findings_for_pattern,
    _is_archive_name,
    _is_archive_path,
    _is_separator_row,
    _iter_archive_members,
    _luhn,
    _make_name_finding,
    _nhs_check,
    _PATTERNS,
    _reparse_csv_if_misaligned,
    _scan_base64_blobs,
    _scan_csv_columns,
    _scan_decoded_payloads,
    _scan_jwt_payloads,
    _scan_url_encoded,
    _should_scan,
    _should_scan_name,
    _strict_column_findings,
    _strip_comments_from_content,
    _text_chunks_from_line,
)


def _pat(rule_id: str):
    """Return the _PATTERNS tuple for a given rule_id."""
    for p in _PATTERNS:
        if p[0] == rule_id:
            return p
    raise KeyError(rule_id)


# --------------------------------------------------------------------------- #
# Check-digit validators                                                       #
# --------------------------------------------------------------------------- #


class TestLuhn:
    def test_valid_visa(self) -> None:
        assert _luhn("4111111111111111") is True

    def test_invalid_number(self) -> None:
        assert _luhn("4111111111111112") is False

    def test_too_short(self) -> None:
        assert _luhn("411111") is False

    def test_ignores_separators(self) -> None:
        assert _luhn("4111-1111-1111-1111") is True


class TestNhsCheck:
    def test_valid_nhs_number(self) -> None:
        # 943 476 5919 is a well-known valid synthetic NHS number
        assert _nhs_check("9434765919") is True

    def test_invalid_check_digit(self) -> None:
        assert _nhs_check("9434765918") is False

    def test_wrong_length(self) -> None:
        assert _nhs_check("12345") is False

    def test_check_digit_ten_is_invalid(self) -> None:
        # Weighted sum % 11 == 1 makes the check digit compute to 10 -> invalid.
        assert _nhs_check("0500000000") is False


# --------------------------------------------------------------------------- #
# _should_scan / _should_scan_name                                             #
# --------------------------------------------------------------------------- #


class TestShouldScan:
    def test_skips_excluded_dir(self, tmp_path: Path) -> None:
        d = tmp_path / "node_modules"
        d.mkdir()
        f = d / "a.py"
        f.write_text("x = 1", encoding="utf-8")
        assert _should_scan(f) is False

    def test_skips_unknown_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "image.png"
        f.write_text("x", encoding="utf-8")
        assert _should_scan(f) is False

    def test_accepts_text_file(self, tmp_path: Path) -> None:
        f = tmp_path / "a.py"
        f.write_text("x = 1", encoding="utf-8")
        assert _should_scan(f) is True

    def test_skips_oversized_file(self, tmp_path: Path) -> None:
        f = tmp_path / "big.txt"
        f.write_text("a" * (2 * 1024 * 1024 + 10), encoding="utf-8")
        assert _should_scan(f) is False


class TestShouldScanName:
    def test_text_extension(self) -> None:
        assert _should_scan_name("dir/app.py") is True

    def test_binary_doc_extension(self) -> None:
        assert _should_scan_name("dir/report.docx") is True

    def test_skip_dir(self) -> None:
        assert _should_scan_name("node_modules/x.js") is False

    def test_unknown_extension(self) -> None:
        assert _should_scan_name("dir/photo.png") is False


# --------------------------------------------------------------------------- #
# Comment / chunk extraction                                                   #
# --------------------------------------------------------------------------- #


class TestStripComments:
    def test_strips_hash_comment(self) -> None:
        out = _strip_comments_from_content('x = 1  # secret note\n')
        assert "secret" not in out
        assert "x = 1" in out

    def test_strips_inline_block_comment(self) -> None:
        out = _strip_comments_from_content("a /* hidden */ b")
        assert "hidden" not in out
        assert out.startswith("a ")

    def test_preserves_line_count(self) -> None:
        content = "line1 # c\nline2\nline3 // c"
        out = _strip_comments_from_content(content)
        assert out.count("\n") == content.count("\n")


class TestTextChunksFromLine:
    def test_extracts_string_literal(self) -> None:
        chunks = _text_chunks_from_line('name = "Jane Smith";')
        assert "Jane Smith" in chunks

    def test_extracts_comment(self) -> None:
        chunks = _text_chunks_from_line("x = 1  # contact Jane Smith")
        assert any("Jane Smith" in c for c in chunks)

    def test_skip_comments_flag(self) -> None:
        chunks = _text_chunks_from_line("x = 1  # contact Jane Smith", skip_comments=True)
        assert all("Jane Smith" not in c for c in chunks)


# --------------------------------------------------------------------------- #
# CSV helpers                                                                  #
# --------------------------------------------------------------------------- #


class TestDetectCsvDelimiter:
    def test_tsv_extension(self) -> None:
        assert _detect_csv_delimiter(["a\tb"], ".tsv") == "\t"

    def test_psv_extension(self) -> None:
        assert _detect_csv_delimiter(["a|b"], ".psv") == "|"

    def test_comma_default(self) -> None:
        assert _detect_csv_delimiter(["a,b,c"], ".csv") == ","

    def test_picks_pipe_when_dominant(self) -> None:
        assert _detect_csv_delimiter(["a|b|c|d"], ".csv") == "|"

    def test_falls_back_to_comma_when_no_delimiter(self) -> None:
        assert _detect_csv_delimiter(["singletoken"], ".csv") == ","


class TestFindCsvHeaderRow:
    def test_first_meaningful_row(self) -> None:
        rows = [[""], ["---", "---"], ["Name", "Email"], ["Jane", "j@x.com"]]
        assert _find_csv_header_row(rows) == 2

    def test_zero_when_first_is_header(self) -> None:
        rows = [["Name", "Email"]]
        assert _find_csv_header_row(rows) == 0


class TestClassifyNameColumns:
    def test_strict_column(self) -> None:
        strict, broad = _classify_name_columns(["id", "Full Name", "email"])
        assert strict == [1]
        assert broad == []

    def test_broad_column(self) -> None:
        strict, broad = _classify_name_columns(["id", "AssignedTo"])
        assert strict == []
        assert broad == [1]

    def test_skip_column(self) -> None:
        strict, broad = _classify_name_columns(["SystemID", "ClassName"])
        assert strict == []
        assert broad == []


class TestIsSeparatorRow:
    def test_separator_only(self) -> None:
        assert _is_separator_row(["---", "===", "|"]) is True

    def test_has_data(self) -> None:
        assert _is_separator_row(["---", "data"]) is False


class TestReparseCsvIfMisaligned:
    def test_no_reparse_when_aligned(self) -> None:
        rows = [["Name", "Email"], ["Jane", "j@x.com"], ["Bob", "b@x.com"]]
        lines = ["Name,Email", "Jane,j@x.com", "Bob,b@x.com"]
        out_rows, idx, headers = _reparse_csv_if_misaligned(rows, lines, ",", 0)
        assert out_rows == rows
        assert idx == 0
        assert headers == ["Name", "Email"]

    def test_reparse_when_misaligned(self) -> None:
        # csv.reader badly split the data rows (1 col) vs the 2-col header — a
        # plain split on the raw comma-delimited lines realigns them.
        rows = [["Name", "Email"], ["JaneOnly"], ["BobOnly"], ["AlOnly"]]
        lines = ["Name,Email", "Jane,j@x.com", "Bob,b@x.com", "Al,a@x.com"]
        out_rows, idx, headers = _reparse_csv_if_misaligned(rows, lines, ",", 0)
        assert headers == ["Name", "Email"]
        assert out_rows[1] == ["Jane", "j@x.com"]


class TestStrictColumnFindings:
    def test_flags_title_case_name(self) -> None:
        headers = ["id", "Name"]
        row = ["1", "Jane Smith"]
        out = _strict_column_findings("data.csv", headers, row, 3, [1], show_secrets=True)
        assert len(out) == 1
        assert out[0].match == "Jane Smith"
        assert out[0].line == 3

    def test_skips_non_name_value(self) -> None:
        out = _strict_column_findings("data.csv", ["id", "Name"], ["1", "n/a"], 3, [1], show_secrets=True)
        assert out == []

    def test_skips_out_of_range_col(self) -> None:
        out = _strict_column_findings("data.csv", ["id", "Name"], ["1"], 3, [1], show_secrets=True)
        assert out == []


class TestMakeNameFinding:
    def test_redacts_when_not_show_secrets(self) -> None:
        f = _make_name_finding("data.csv", 2, "Jane Smith", False, "sfx", "rule", "msg")
        assert f.match == "Jane****"
        assert f.rule_id == "rule"

    def test_shows_when_show_secrets(self) -> None:
        f = _make_name_finding("data.csv", 2, "Jane Smith", True, "sfx", "rule", "msg")
        assert f.match == "Jane Smith"


class TestScanCsvColumns:
    def test_strict_name_column_flagged(self) -> None:
        content = "id,Name,email\n1,Jane Smith,j@x.com\n2,Bob Jones,b@x.com\n"
        out = _scan_csv_columns("people.csv", content, show_secrets=True)
        matches = {f.match for f in out}
        assert "Jane Smith" in matches
        assert "Bob Jones" in matches

    def test_no_name_column_returns_empty(self) -> None:
        content = "id,email\n1,j@x.com\n2,b@x.com\n"
        assert _scan_csv_columns("people.csv", content, show_secrets=True) == []

    def test_empty_content_returns_empty(self) -> None:
        assert _scan_csv_columns("people.csv", "", show_secrets=True) == []

    def test_skips_leading_separator_rows(self) -> None:
        content = "---,---\nName,email\nJane Smith,j@x.com\n"
        out = _scan_csv_columns("people.csv", content, show_secrets=True)
        assert any(f.match == "Jane Smith" for f in out)


# --------------------------------------------------------------------------- #
# Regex pattern matching via _content_findings_for_pattern                     #
# --------------------------------------------------------------------------- #


class TestPatternMatching:
    def test_email_pattern(self) -> None:
        out = _content_findings_for_pattern("a.txt", "contact me at jane@example.com today",
                                            True, _pat("pii_email"))
        assert len(out) == 1
        assert out[0].match == "jane@example.com"
        assert out[0].category == "pii_email"

    def test_credit_card_luhn_pass(self) -> None:
        out = _content_findings_for_pattern("a.txt", "card 4111111111111111", True,
                                            _pat("pii_credit_card"))
        assert len(out) == 1

    def test_credit_card_luhn_reject(self) -> None:
        # Passes the regex shape but fails Luhn -> validator rejects
        out = _content_findings_for_pattern("a.txt", "card 4111111111111112", True,
                                            _pat("pii_credit_card"))
        assert out == []

    def test_nhs_number_valid(self) -> None:
        out = _content_findings_for_pattern("a.txt", "NHS 943 476 5919", True,
                                            _pat("pii_nhs_number"))
        assert len(out) == 1

    def test_line_number_computed(self) -> None:
        content = "first line\nsecond\nemail jane@example.com here"
        out = _content_findings_for_pattern("a.txt", content, True, _pat("pii_email"))
        assert out[0].line == 3

    def test_private_key_pattern(self) -> None:
        out = _content_findings_for_pattern("a.txt", "-----BEGIN RSA PRIVATE KEY-----", True,
                                            _pat("private_key_pem"))
        assert len(out) == 1
        assert out[0].severity == "critical"

    def test_redaction_applied(self) -> None:
        out = _content_findings_for_pattern("a.txt", "jane@example.com", False, _pat("pii_email"))
        assert out[0].match == "jane****"


# --------------------------------------------------------------------------- #
# _findings_for_pattern (decoded chunk variant)                                #
# --------------------------------------------------------------------------- #


class TestFindingsForPattern:
    def test_tags_source(self) -> None:
        out = _findings_for_pattern("a.txt", 5, "jane@example.com", True, "url_decoded",
                                    _pat("pii_email"))
        assert len(out) == 1
        assert out[0].line == 5
        assert "url decoded" in out[0].message


# --------------------------------------------------------------------------- #
# Decode scanning: URL / JWT / Base64                                          #
# --------------------------------------------------------------------------- #


class TestScanUrlEncoded:
    def test_decodes_and_finds_email(self) -> None:
        # Fully percent-encode every byte so the regex sees one continuous %XX run.
        encoded = "".join(f"%{b:02X}" for b in b"jane@example.com")
        out = _scan_url_encoded("a.txt", 1, f"q={encoded}", True)
        assert any(f.match == "jane@example.com" for f in out)

    def test_no_encoded_sequence(self) -> None:
        assert _scan_url_encoded("a.txt", 1, "plain text", True) == []


class TestScanJwtPayloads:
    def test_decodes_jwt_payload(self) -> None:
        payload = base64.urlsafe_b64encode(b'{"email":"jane@example.com"}').decode().rstrip("=")
        token = f"eyJhbGc.{payload}.sig"
        out = _scan_jwt_payloads("a.txt", 1, token, True)
        assert any(f.category == "pii_email" for f in out)


class TestScanBase64Blobs:
    def test_decodes_base64_with_pii(self) -> None:
        blob = base64.b64encode(b"contact jane@example.com now").decode()
        out = _scan_base64_blobs("a.txt", 1, blob, True)
        assert any(f.category == "pii_email" for f in out)

    def test_ignores_non_base64(self) -> None:
        assert _scan_base64_blobs("a.txt", 1, "short", True) == []


class TestScanDecodedPayloads:
    def test_aggregates_all_decoders(self) -> None:
        encoded = "".join(f"%{b:02X}" for b in b"jane@example.com")
        content = f"url q={encoded}"
        out = _scan_decoded_payloads("a.txt", content, True)
        assert any(f.category == "pii_email" for f in out)


# --------------------------------------------------------------------------- #
# Archive predicates / iteration                                              #
# --------------------------------------------------------------------------- #


class TestArchivePredicates:
    def test_is_archive_path_zip(self, tmp_path: Path) -> None:
        assert _is_archive_path(tmp_path / "a.zip") is True

    def test_is_archive_path_tar_gz(self, tmp_path: Path) -> None:
        assert _is_archive_path(tmp_path / "a.tar.gz") is True

    def test_is_archive_path_plain(self, tmp_path: Path) -> None:
        assert _is_archive_path(tmp_path / "a.py") is False

    def test_is_archive_name_tgz(self) -> None:
        assert _is_archive_name("bundle.tgz") is True

    def test_is_archive_name_tar_bz2(self) -> None:
        assert _is_archive_name("bundle.tar.bz2") is True

    def test_is_archive_name_plain(self) -> None:
        assert _is_archive_name("notes.txt") is False


class TestIterArchiveMembers:
    def test_iterates_zip_members(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "hello")
            zf.writestr("b.txt", "world")
        members = dict(_iter_archive_members("bundle.zip", buf.getvalue()))
        assert members == {"a.txt": b"hello", "b.txt": b"world"}

    def test_gz_single_member(self) -> None:
        import gzip
        data = gzip.compress(b"secret content")
        members = list(_iter_archive_members("file.txt.gz", data))
        assert members == [("file.txt", b"secret content")]

    def test_bad_archive_yields_nothing(self) -> None:
        members = list(_iter_archive_members("broken.zip", b"not a zip"))
        assert members == []

    def test_iterates_tar_gz_members(self) -> None:
        import gzip
        import tarfile
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tf:
            info = tarfile.TarInfo(name="inner.txt")
            payload = b"email jane@example.com"
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        data = gzip.compress(raw.getvalue())
        members = list(_iter_archive_members("bundle.tar.gz", data))
        assert members == [("inner.txt", b"email jane@example.com")]


# --------------------------------------------------------------------------- #
# Binary doc dispatch (.eml uses stdlib — always available)                    #
# --------------------------------------------------------------------------- #


class TestEmlExtraction:
    def test_extracts_headers_and_body(self) -> None:
        raw = (
            b"From: jane@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Subject: Hello\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Body text with name John Smith.\r\n"
        )
        text = _extract_eml_text(raw)
        assert text is not None
        assert "jane@example.com" in text
        assert "Hello" in text

    def test_dispatch_to_eml(self) -> None:
        raw = b"From: a@b.com\r\nSubject: S\r\n\r\nbody\r\n"
        out = _extract_binary_doc_from_bytes(".eml", raw)
        assert out is not None
        assert "a@b.com" in out

    def test_dispatch_unknown_returns_none(self) -> None:
        assert _extract_binary_doc_from_bytes(".unknown", b"data") is None


# --------------------------------------------------------------------------- #
# PIIScanner integration                                                       #
# --------------------------------------------------------------------------- #


class TestPIIScannerIntegration:
    @pytest.mark.asyncio
    async def test_is_available(self) -> None:
        assert await PIIScanner().is_available() is True

    @pytest.mark.asyncio
    async def test_scan_finds_email_in_file(self, tmp_path: Path) -> None:
        (tmp_path / "data.txt").write_text("email: jane@example.com\n", encoding="utf-8")
        scanner = PIIScanner()
        findings = await scanner.scan(ScanConfig(path=str(tmp_path), show_secrets=True))
        assert any(f.category == "pii_email" for f in findings)
        assert scanner._files_scanned >= 1

    @pytest.mark.asyncio
    async def test_scan_respects_exclude_files(self, tmp_path: Path) -> None:
        (tmp_path / "skip.txt").write_text("email: jane@example.com\n", encoding="utf-8")
        scanner = PIIScanner()
        findings = await scanner.scan(
            ScanConfig(path=str(tmp_path), show_secrets=True, exclude_files=["skip.txt"])
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_scan_zip_archive(self, tmp_path: Path) -> None:
        buf = tmp_path / "bundle.zip"
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("inner.txt", "email jane@example.com")
        scanner = PIIScanner()
        findings = await scanner.scan(ScanConfig(path=str(tmp_path), show_secrets=True))
        assert any(f.category == "pii_email" for f in findings)

    @pytest.mark.asyncio
    async def test_scan_skip_comments_counts_skipped_lines(self, tmp_path: Path) -> None:
        # A comment-only line becomes empty after stripping -> counted as skipped.
        (tmp_path / "a.py").write_text(
            "# email jane@example.com\nclean = 2\n", encoding="utf-8"
        )
        scanner = PIIScanner()
        await scanner.scan(ScanConfig(path=str(tmp_path), show_secrets=True, skip_comments=True))
        assert scanner._lines_skipped >= 1

    @pytest.mark.asyncio
    async def test_scan_exclude_patterns(self, tmp_path: Path) -> None:
        (tmp_path / "secret.txt").write_text("email jane@example.com\n", encoding="utf-8")
        scanner = PIIScanner()
        findings = await scanner.scan(
            ScanConfig(path=str(tmp_path), show_secrets=True, exclude_patterns=["*.txt"])
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_scan_exclude_paths(self, tmp_path: Path) -> None:
        sub = tmp_path / "vendored"
        sub.mkdir()
        (sub / "a.txt").write_text("email jane@example.com\n", encoding="utf-8")
        scanner = PIIScanner()
        findings = await scanner.scan(
            ScanConfig(path=str(tmp_path), show_secrets=True, exclude_paths=["vendored"])
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_scan_skips_non_text_file(self, tmp_path: Path) -> None:
        (tmp_path / "image.png").write_text("not really scanned", encoding="utf-8")
        scanner = PIIScanner()
        await scanner.scan(ScanConfig(path=str(tmp_path), show_secrets=True))
        assert scanner._files_skipped >= 1

    @pytest.mark.asyncio
    async def test_scan_binary_doc_without_extractor_is_skipped(self, tmp_path: Path) -> None:
        # No optional extractor installed -> .docx yields no text and is skipped.
        (tmp_path / "report.docx").write_bytes(b"PK\x03\x04 not a real docx")
        scanner = PIIScanner()
        await scanner.scan(ScanConfig(path=str(tmp_path), show_secrets=True))
        assert scanner._files_skipped >= 1

    @pytest.mark.asyncio
    async def test_scan_nested_archive(self, tmp_path: Path) -> None:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("deep.txt", "email jane@example.com")
        outer = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("nested.zip", inner.getvalue())
        scanner = PIIScanner()
        findings = await scanner.scan(ScanConfig(path=str(tmp_path), show_secrets=True))
        assert any(f.category == "pii_email" for f in findings)

    @pytest.mark.asyncio
    async def test_scan_archive_depth_limit(self, tmp_path: Path) -> None:
        buf = tmp_path / "bundle.zip"
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("inner.txt", "email jane@example.com")
        data = buf.read_bytes()
        scanner = PIIScanner()
        scanner._files_scanned = 0
        # depth at the limit -> returns nothing
        out = scanner._scan_archive_data("bundle.zip", data, ScanConfig(path=str(tmp_path)), depth=10)
        assert out == []

