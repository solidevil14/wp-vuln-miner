# XmlScanner encoding-matrix results (2026-10-30, PHP 8.3.13)

23/23 variants BLOCKED. The Oct-27 batch fix = real:
- every declared-encoding path (16 encodings incl. ISO-2022-CN/KR, x-mac-*,
  HZ, CP-series, SJIS/EUC/GB18030): the ASCII ENTITY survives conversion →
  caught by the pattern check on the converted bytes
- BOM-lying declarations: caught (BOM-vs-declared cross-check)
- UTF-16-BOM with UTF-8 declaration: "Double encoding not permitted"
- NUL-interleaved + U+FFFE entity tricks: caught (\0*-tolerant pattern)

CLOSED: gap #1 (charset breadth) + gap #3 (NUL reassembly).
OPEN (needs full repo + composer on a real machine): gap #2 — the
reader-level re-read TOCTOU (trySimpleXMLLoadStringPrivate's re-read arm;
trace Xlsx shared-strings per-part + Ods + Html consistency).

Run: php83 -d memory_limit=512M run_tests.php (the scanner + stubs in this dir)
