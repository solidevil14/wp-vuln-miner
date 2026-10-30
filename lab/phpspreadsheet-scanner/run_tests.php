<?php
// XmlScanner isolation harness — byte-consistency tests (local research only)
namespace PhpOffice\PhpSpreadsheet\Reader {
    class Exception extends \Exception {}
    class Csv {
        public const UTF8_BOM = "\xEF\xBB\xBF";
        public const UTF8_BOM_LEN = 3;
        public static function guessEncodingBom(string $value = '', ?string $input = null): string {
            $xml = $input ?? $value;
            if (str_starts_with($xml, "\xEF\xBB\xBF")) return 'UTF-8';
            if (str_starts_with($xml, "\xFF\xFE")) return 'UTF-16LE';
            if (str_starts_with($xml, "\xFE\xFF")) return 'UTF-16BE';
            return '';
        }
    }
}

namespace {
    require __DIR__ . '/XmlScanner.php';

    use PhpOffice\PhpSpreadsheet\Reader\Security\XmlScanner;

    $tests = [];

    // [label, raw-bytes]
    $tests[] = ['baseline-utf8-entity', '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'];

    // declared encodings, no BOM, ENTITY in plain ASCII
    foreach (['ISO-2022-JP','ISO-2022-CN','ISO-2022-KR','UTF-16','UTF-16LE','UTF-16BE',
              'x-mac-roman','macintosh','HZ','CP936','CP949','CP950','CP1252','SJIS','EUC-JP','GB18030'] as $enc) {
        $tests[] = ["decl-$enc-nobom",
            "<?xml version=\"1.0\" encoding=\"$enc\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>"];
    }

    // UTF-8 BOM + lying declaration (the new cross-check)
    $tests[] = ['bom8-liar-iso2022kr', "\xEF\xBB\xBF" . '<?xml version="1.0" encoding="ISO-2022-KR"?><!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>'];
    $tests[] = ['bom8-liar-utf16', "\xEF\xBB\xBF" . '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>'];

    // UTF-16 BOM + ASCII-declared ENTITY (the interleaving question)
    $tests[] = ['bom16le-decl-utf8', "\xFF\xFE" . '<?xml version="1.0" encoding="UTF-8"?><r>ok</r>'];

    // NUL-interleaved entity (post-conversion survival)
    $tests[] = ['nul-entity', "<?xml version=\"1.0\"?><\x00!\x00D\x00O\x00C\x00T\x00Y\x00P\x00E\x00 r [<!ENTITY e \"x\">]><r>&e;</r>"];

    // numeric entity reassembly via fffe
    $tests[] = ['fffe-entity', "<?xml version=\"1.0\"?>\u{FFFE}<!DOCTYPE r [<!ENTITY e \"x\">]><r>&e;</r>"];

    // the scanner's own constant hook
    $scanner = new XmlScanner(XmlScanner::XML_PATTERN);

    foreach ($tests as [$label, $xml]) {
        $passed = true; $scanned = null; $err = '';
        try {
            $scanned = $scanner->scan($xml);
        } catch (\Throwable $e) {
            $passed = false;
            $err = $e->getMessage();
        }
        if ($passed) {
            // what does the PARSER see on the returned bytes?
            $prev = libxml_use_internal_errors(true);
            $parsed = @simplexml_load_string($scanned, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOENT);
            $perrs = array_map(fn($e) => $e->message, libxml_get_errors());
            libxml_clear_errors();
            libxml_use_internal_errors($prev);
            $entityAlive = is_string($scanned) && stripos($scanned, 'ENTITY') !== false;
            echo sprintf("[%s] SCAN=PASS len=%d ENTITY_SURVIVES=%s parsed=%s parseErr=%s\n",
                $label, strlen((string)$scanned), $entityAlive ? 'YES!!' : 'no',
                $parsed === false ? 'FAIL' : 'OK', $perrs ? json_encode($perrs[0]) : '-');
        } else {
            echo sprintf("[%s] SCAN=BLOCKED (%s)\n", $label, substr($err, 0, 70));
        }
    }
}
