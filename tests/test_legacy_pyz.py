import io
import marshal
import os
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import pyinstxtractor_ng as extractor


class LegacyPyzTocPositionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write_pyz(self, byte_order):
        toc_position = 12
        header = (
            b"PYZ\0"
            + b"\x00\x00\x00\x00"
            + struct.pack(byte_order + "i", toc_position)
        )
        path = os.path.join(self.tmp.name, "archive.pyz")
        with open(path, "wb") as f:
            f.write(header + marshal.dumps({}))
        return path

    def _extract(self, byte_order):
        path = self._write_pyz(byte_order)
        archive = extractor.PyInstArchive(path)
        archive.pycMagic = b"\x00" * 4
        archive.pymaj, archive.pymin = 2, 2
        output = io.StringIO()
        with patch.object(
            extractor, "load_code", side_effect=lambda f, magic: marshal.load(f)
        ):
            with redirect_stdout(output):
                archive._extractPyz(path, one_dir=True)
        return output.getvalue()

    def test_native_little_endian_toc_position(self):
        output = self._extract("<")
        self.assertIn("[+] Found 0 files in PYZ archive", output)

    def test_network_big_endian_toc_position(self):
        output = self._extract(">")
        self.assertIn("[+] Found 0 files in PYZ archive", output)


if __name__ == "__main__":
    unittest.main()
