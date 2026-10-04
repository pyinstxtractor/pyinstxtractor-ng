import contextlib
import importlib.util
import io
import marshal
import os
import struct
import sys
import unittest
import zlib
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util import Counter

import pyinstxtractor_ng as extractor


def pyz_bytes(entries):
    data = bytearray(b"PYZ\0" + importlib.util.MAGIC_NUMBER + b"\0" * 4)
    toc = []
    for name, typecode, payload in entries:
        toc.append((name, (typecode, len(data), len(payload))))
        data.extend(payload)
    data[8:12] = struct.pack("!i", len(data))
    data.extend(marshal.dumps(toc))
    return bytes(data)


class OutputFile(io.BytesIO):
    def close(self):
        pass


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.arch = extractor.PyInstArchive("fixture.exe")
        self.arch.pymaj, self.arch.pymin = sys.version_info[:2]
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def extract(self, entries, one_dir=False, data=None):
        raw = pyz_bytes(entries) if data is None else data
        outputs = {}

        def open_file(name, mode):
            if mode == "rb":
                return io.BytesIO(raw)
            outputs[name] = OutputFile()
            return outputs[name]

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("builtins.open", side_effect=open_file))
            stack.enter_context(
                patch.object(extractor.os.path, "exists", return_value=False)
            )
            stack.enter_context(patch.object(extractor.os, "mkdir"))
            directories = stack.enter_context(patch.object(extractor.os, "makedirs"))
            pycs = stack.enter_context(patch.object(self.arch, "_writePyc"))
            stack.enter_context(contextlib.redirect_stdout(self.stdout))
            stack.enter_context(contextlib.redirect_stderr(self.stderr))
            self.arch._extractPyz("PYZ.pyz", one_dir)
        return pycs, {name: output.getvalue() for name, output in outputs.items()}, directories

    def test_zero_length_module_and_package_do_not_decrypt(self):
        with patch.object(self.arch, "_tryDecrypt") as decrypt:
            pycs, raw_files, _ = self.extract(
                [("empty", 0, b""), ("package", 1, b"")]
            )
        decrypt.assert_not_called()
        self.assertEqual(pycs.call_count, 2)
        self.assertEqual(pycs.call_args_list[0].args[1], b"")
        self.assertEqual(pycs.call_args_list[1].args[1], b"")
        self.assertEqual(raw_files, {})
        self.assertIn("Empty file", self.stdout.getvalue())
        self.assertEqual(self.stderr.getvalue(), "")

    def test_namespace_package_has_directory_but_no_fake_pyc(self):
        for one_dir in (False, True):
            with self.subTest(one_dir=one_dir):
                pycs, raw_files, directories = self.extract(
                    [("namespace", 3, b"")], one_dir
                )
                pycs.assert_not_called()
                self.assertEqual(raw_files, {})
                root = "." if one_dir else "PYZ.pyz_extracted"
                directories.assert_any_call(os.path.join(root, "namespace"))

    def test_compressed_module_and_package(self):
        code = marshal.dumps(compile("value = 42", "fixture.py", "exec"))
        pycs, raw_files, _ = self.extract(
            [
                ("module", 0, zlib.compress(code)),
                ("package", 1, zlib.compress(code)),
            ]
        )
        self.assertEqual(pycs.call_count, 2)
        self.assertEqual(pycs.call_args_list[0].args[1], code)
        self.assertTrue(pycs.call_args_list[1].args[0].endswith("__init__.pyc"))
        self.assertEqual(pycs.call_args_list[1].args[1], code)
        self.assertEqual(raw_files, {})
        self.assertEqual(self.stderr.getvalue(), "")

    def test_existing_ctr_and_cfb_encryption(self):
        key = b"0123456789abcdef"
        iv = bytes(range(16))
        code = marshal.dumps(compile("value = 42", "fixture.py", "exec"))
        compressed = zlib.compress(code)
        for mode in ("ctr", "cfb"):
            with self.subTest(mode=mode):
                self.arch.cryptoKey = key.decode("ascii")
                if mode == "ctr":
                    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
                    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
                else:
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                pycs, raw_files, _ = self.extract(
                    [("encrypted", 0, iv + cipher.encrypt(compressed))]
                )
                self.assertEqual(pycs.call_args.args[1], code)
                self.assertEqual(raw_files, {})
        self.assertEqual(self.stderr.getvalue(), "")

    def test_corrupt_zlib_without_key_is_not_called_decryption_failure(self):
        compressed = zlib.compress(b"code")
        corrupt = compressed[:-1] + bytes([compressed[-1] ^ 1])
        with patch.object(self.arch, "_tryDecrypt") as decrypt:
            pycs, raw_files, _ = self.extract([("corrupt", 0, corrupt)])
        decrypt.assert_not_called()
        pycs.assert_not_called()
        self.assertEqual(list(raw_files.values()), [corrupt])
        self.assertIn("Failed to decompress", self.stderr.getvalue())
        self.assertIn("corrupt", self.stderr.getvalue())
        self.assertNotIn("Failed to decrypt", self.stderr.getvalue())
        self.assertTrue(self.arch.extractionFailed)

    def test_unknown_key_is_reported_without_claiming_encryption(self):
        unknown = bytes(range(32))
        with patch.object(self.arch, "_tryDecrypt") as decrypt:
            pycs, raw_files, _ = self.extract([("unknown", 0, unknown)])
        decrypt.assert_not_called()
        pycs.assert_not_called()
        self.assertEqual(list(raw_files.values()), [unknown])
        self.assertTrue(next(iter(raw_files)).endswith(".encrypted"))
        self.assertIn("no encryption key available", self.stderr.getvalue())
        self.assertIn("may be corrupt or encrypted", self.stderr.getvalue())
        self.assertTrue(self.arch.extractionFailed)

    def test_wrong_key_preserves_original_ciphertext(self):
        self.arch.cryptoKey = "wrong-key-1234567"
        unknown = bytes(range(32))
        pycs, raw_files, _ = self.extract([("unknown", 0, unknown)])
        pycs.assert_not_called()
        self.assertEqual(list(raw_files.values()), [unknown])
        self.assertIn("Failed to decrypt & decompress", self.stderr.getvalue())
        self.assertIn("key may be incorrect or data corrupt", self.stderr.getvalue())
        self.assertTrue(self.arch.extractionFailed)

    def test_invalid_pyz_toc_marks_extraction_incomplete(self):
        raw = b"PYZ\0" + importlib.util.MAGIC_NUMBER + struct.pack("!i", 12) + b"!"
        pycs, _, _ = self.extract([], data=raw)
        pycs.assert_not_called()
        self.assertTrue(self.arch.extractionFailed)

    def test_corrupt_carchive_marks_extraction_incomplete(self):
        self.arch.tocList = [extractor.CTOCEntry(0, 3, 8, 1, b"b", "bad")]
        self.arch.fPtr = io.BytesIO(b"bad")
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(extractor.os.path, "exists", return_value=True)
            )
            stack.enter_context(patch.object(extractor.os, "chdir"))
            stack.enter_context(contextlib.redirect_stdout(self.stdout))
            stack.enter_context(contextlib.redirect_stderr(self.stderr))
            self.arch.extractFiles(False)
        self.assertTrue(self.arch.extractionFailed)
        self.assertIn("Failed to decompress CArchive entry", self.stderr.getvalue())

    def test_cli_partial_extraction_has_nonzero_status_and_retains_good_files(self):
        self.arch.tocList = [
            extractor.CTOCEntry(0, 4, 4, 0, b"b", "good"),
            extractor.CTOCEntry(4, 3, 8, 1, b"b", "bad"),
        ]
        self.arch.fPtr = io.BytesIO(b"goodbad")
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(extractor, "PyInstArchive", return_value=self.arch)
            )
            for method in ("open", "checkFile", "getCArchiveInfo"):
                stack.enter_context(patch.object(self.arch, method, return_value=True))
            stack.enter_context(patch.object(self.arch, "parseTOC"))
            stack.enter_context(
                patch.object(
                    extractor.os.path, "exists",
                    side_effect=lambda path: path.endswith("_extracted"),
                )
            )
            stack.enter_context(patch.object(extractor.os, "chdir"))
            stack.enter_context(
                patch.object(sys, "argv", ["pyinstxtractor-ng", "fixture.exe"])
            )
            raw_files = stack.enter_context(patch.object(self.arch, "_writeRawData"))
            stack.enter_context(contextlib.redirect_stdout(self.stdout))
            stack.enter_context(contextlib.redirect_stderr(self.stderr))
            with self.assertRaises(SystemExit) as exit_status:
                extractor.main()
        self.assertEqual(exit_status.exception.code, 1)
        raw_files.assert_called_once_with("good", b"good")
        self.assertNotIn(
            "Successfully extracted pyinstaller archive", self.stdout.getvalue()
        )
        self.assertIn("Incomplete extraction", self.stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
