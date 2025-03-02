import os
import sys
import zlib
import struct
import argparse

from uuid import uuid4 as uniquename

from Crypto.Cipher import AES
from Crypto.Util import Counter

from xdis.unmarshal import load_code


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def pycHeader2Magic(header):
    header = bytearray(header)
    magicNumber = bytearray(header[:2])
    return magicNumber[1] << 8 | magicNumber[0]


def list_exe_files():
    exe_files = [f for f in os.listdir() if f.endswith('.exe')]
    if not exe_files:
        eprint("[!] No executable files found in the current directory.")
        sys.exit(1)
    return exe_files


def select_file(exe_files):
    print("[+] Found the following executable files:\n")
    for idx, file in enumerate(exe_files):
        print(f"{idx + 1}: {file}")
    while True:
        try:
            choice = int(input("\nSelect program to extract: "))
            if 1 <= choice <= len(exe_files):
                return exe_files[choice - 1]
            else:
                print("[!] Invalid choice, please select a valid number.")
        except ValueError:
            print("[!] Invalid input, please enter a number.")


class CTOCEntry:
    def __init__(
        self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name
    ):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24  # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64  # For pyinstaller 2.1+
    MAGIC = b"MEI\014\013\012\013\016"  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path
        self.pycMagic = b"\0" * 4
        self.barePycList = []  # List of pyc's whose headers have to be fixed
        self.cryptoKey = None
        self.cryptoKeyFileData = None

    def open(self):
        try:
            self.fPtr = open(self.filePath, "rb")
            self.fileSize = os.stat(self.filePath).st_size
        except:
            eprint("[!] Error: Could not open {0}".format(self.filePath))
            return False
        return True

    def close(self):
        try:
            self.fPtr.close()
        except:
            pass

    def checkFile(self):
        print("\n[+] Processing {0}".format(self.filePath))

        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            eprint("[!] Error: File is too short or truncated")
            return False

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            eprint(
                "[!] Error: Missing cookie, unsupported pyinstaller version or not a pyinstaller archive"
            )
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b"python" in self.fPtr.read(64).lower():
            print("[+] Pyinstaller version: 2.1+")
            self.pyinstVer = 21  # pyinstaller 2.1+
        else:
            self.pyinstVer = 20  # pyinstaller 2.0
            print("[+] Pyinstaller version: 2.0")

        return True

    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver) = struct.unpack(
                    "!8siiii", self.fPtr.read(self.PYINST20_COOKIE_SIZE)
                )

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = struct.unpack(
                    "!8sIIii64s", self.fPtr.read(self.PYINST21_COOKIE_SIZE)
                )

        except:
            eprint("[!] Error: The file is not a pyinstaller archive")
            return False

        self.pymaj, self.pymin = (
            (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        )
        print("[+] Python version: {0}.{1}".format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = (
            self.fileSize
            - self.cookiePos
            - (
                self.PYINST20_COOKIE_SIZE
                if self.pyinstVer == 20
                else self.PYINST21_COOKIE_SIZE
            )
        )

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        print("[+] Length of package: {0} bytes".format(lengthofPackage))
        return True

    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize,) = struct.unpack("!i", self.fPtr.read(4))
            nameLen = struct.calcsize("!iIIIBc")

            (
                entryPos,
                cmprsdDataSize,
                uncmprsdDataSize,
                cmprsFlag,
                typeCmprsData,
                name,
            ) = struct.unpack(
                "!IIIBc{0}s".format(entrySize - nameLen), self.fPtr.read(entrySize - 4)
            )

            try:
                name = name.decode("utf-8").rstrip("\0")
            except UnicodeDecodeError:
                newName = str(uniquename())
                print('[!] Warning: File name {0} contains invalid bytes. Using random name {1}'.format(name, newName))
                name = newName

            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())
                print(
                    "[!] Warning: Found an unamed file in CArchive. Using random name {0}".format(
                        name
                    )
                )

            self.tocList.append(
                CTOCEntry(
                    self.overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name,
                )
            )

            parsedLen += entrySize
        print("[+] Found {0} files in CArchive".format(len(self.tocList)))

    def _writeRawData(self, filepath, data):
        nm = (
            filepath.replace("\\", os.path.sep)
            .replace("/", os.path.sep)
            .replace("..", "__")
        )
        nmDir = os.path.dirname(nm)
        if nmDir != "" and not os.path.exists(
            nmDir
        ):  # Check if path exists, create if not
            os.makedirs(nmDir)

        with open(nm, "wb") as f:
            f.write(data)

    def extractFiles(self, one_dir):
        print("[+] Beginning extraction...please standby")
        extractionDir = os.path.join(
            os.getcwd(), os.path.basename(self.filePath) + "_extracted"
        )

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize  # Sanity Check

            if entry.typeCmprsData == b"d" or entry.typeCmprsData == b"o":
                # d -> ARCHIVE_ITEM_DEPENDENCY
                # o -> ARCHIVE_ITEM_RUNTIME_OPTION
                # These are runtime options, not files
                continue

            basePath = os.path.dirname(entry.name)
            if basePath != "":
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            if entry.typeCmprsData == b"s":
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts
                print("[+] Possible entry point: {0}.pyc".format(entry.name))

                if self.pycMagic == b"\0" * 4:
                    # if we don't have the pyc header yet, fix them in a later pass
                    self.barePycList.append(entry.name + ".pyc")
                self._writePyc(entry.name + ".pyc", data)

            elif entry.typeCmprsData == b"M" or entry.typeCmprsData == b"m":
                # M -> ARCHIVE_ITEM_PYPACKAGE
                # m -> ARCHIVE_ITEM_PYMODULE
                # packages and modules are pyc files with their header intact

                # From PyInstaller 5.3 and above pyc headers are no longer stored
                # https://github.com/pyinstaller/pyinstaller/commit/a97fdf
                if data[2:4] == b"\r\n":
                    # < pyinstaller 5.3
                    if self.pycMagic == b"\0" * 4:
                        self.pycMagic = data[0:4]
                    self._writeRawData(entry.name + ".pyc", data)

                    if entry.name.endswith("_crypto_key"):
                        # This is a pyc file with a header (8,12, or 16 bytes)
                        # Extract the code object after the header
                        self.cryptoKeyFileData = self._extractCryptoKeyObject(data)
                        co = load_code(self.cryptoKeyFileData, pycHeader2Magic(self.pycMagic))
                        self.cryptoKey = co.co_consts[0]
                        print(
                            "[+] Detected _crypto_key file, saving key for automatic decryption: " + self.cryptoKey
                        )

                else:
                    # >= pyinstaller 5.3
                    if self.pycMagic == b"\0" * 4:
                        # if we don't have the pyc header yet, fix them in a later pass
                        self.barePycList.append(entry.name + ".pyc")

                    self._writePyc(entry.name + ".pyc", data)

                    if entry.name.endswith("_crypto_key"):
                        # This is a plain code object without a header
                        self.cryptoKeyFileData = data
                        co = load_code(self.cryptoKeyFileData, pycHeader2Magic(self.pycMagic))
                        self.cryptoKey = co.co_consts[0]
                        print(
                            "[+] Detected _crypto_key file, saving key for automatic decryption: " + self.cryptoKey
                        )

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b"z" or entry.typeCmprsData == b"Z":
                    self._extractPyz(entry.name, one_dir)

        # Fix bare pyc's if any
        self._fixBarePycs()

    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            import re
            pycFile = re.sub(r'[^\x20-\x7E]', '', pycFile) ################################################################################################################ BwE Changes
            with open(pycFile, "r+b") as pycFile:
                # Overwrite the first four bytes
                pycFile.write(self.pycMagic)

    def _extractCryptoKeyObject(self, data):
        if self.pymaj >= 3 and self.pymin >= 7:
            # 16 byte header for 3.7 and above
            return data[16:]
        elif self.pymaj >= 3 and self.pymin >= 3:
            # 12 byte header for 3.3-3.6
            return data[12:]
        else:
            # 8 byte header for 2.x, 3.0-3.2
            return data[8:]

    def _writePyc(self, filename, data):
        import re
        filename = re.sub(r'[^\x20-\x7E]', '', filename) ################################################################################################################ BwE Changes
        with open(filename, "wb") as pycFile:
            pycFile.write(self.pycMagic)  # pyc magic

            if self.pymaj >= 3 and self.pymin >= 7:  # PEP 552 -- Deterministic pycs
                pycFile.write(b"\0" * 4)  # Bitfield
                pycFile.write(b"\0" * 8)  # (Timestamp + size) || hash

            else:
                pycFile.write(b"\0" * 4)  # Timestamp
                if self.pymaj >= 3 and self.pymin >= 3:
                    pycFile.write(b"\0" * 4)  # Size parameter added in Python 3.3

            pycFile.write(data)

    def _getCryptoKey(self):
        if self.cryptoKey:
            return self.cryptoKey

        if not self.cryptoKeyFileData:
            return None

        co = load_code(self.cryptoKeyFileData, pycHeader2Magic(self.pycMagic))
        self.cryptoKey = co.co_consts[0]
        return self.cryptoKey

    def _tryDecrypt(self, ct, aes_mode):
        CRYPT_BLOCK_SIZE = 16

        key = bytes(self._getCryptoKey(), "utf-8")
        assert len(key) == 16

        # Initialization vector
        iv = ct[:CRYPT_BLOCK_SIZE]

        if aes_mode == "ctr":
            # Pyinstaller >= 4.0 uses AES in CTR mode
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            return cipher.decrypt(ct[CRYPT_BLOCK_SIZE:])

        elif aes_mode == "cfb":
            # Pyinstaller < 4.0 uses AES in CFB mode
            cipher = AES.new(key, AES.MODE_CFB, iv)
            return cipher.decrypt(ct[CRYPT_BLOCK_SIZE:])            

    def _extractPyz(self, name, one_dir):
        if one_dir == True:
            dirName = "."
        else:
            dirName = name + "_extracted"
            # Create a directory for the contents of the pyz
            if not os.path.exists(dirName):
                os.mkdir(dirName)

        with open(name, "rb") as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b"PYZ\0"  # Sanity Check

            pyzPycMagic = f.read(4)  # Python magic value

            if self.pycMagic == b"\0" * 4:
                self.pycMagic = pyzPycMagic

            elif self.pycMagic != pyzPycMagic:
                self.pycMagic = pyzPycMagic
                print(
                    "[!] Warning: pyc magic of files inside PYZ archive are different from those in CArchive"
                )

            (tocPosition,) = struct.unpack("!i", f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = load_code(f, pycHeader2Magic(pyzPycMagic))
            except:
                print(
                    "[!] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.".format(
                        name
                    )
                )
                return

            print("[+] Found {0} files in PYZ archive".format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = fileName.decode("utf-8")
                except:
                    pass

                # Prevent writing outside dirName
                fileName = fileName.replace("..", "__").replace(".", os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, "__init__.pyc")

                else:
                    filePath = os.path.join(dirName, fileName + ".pyc")

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    try:
                        # Automatic decryption
                        # Make a copy
                        data_copy = data

                        # Try CTR mode, Pyinstaller >= 4.0 uses AES in CTR mode
                        data = self._tryDecrypt(data, "ctr")
                        data = zlib.decompress(data)
                    except:
                        # Try CFB mode, Pyinstaller < 4.0 uses AES in CFB mode
                        try:
                            data = data_copy
                            data = self._tryDecrypt(data, "cfb")
                            data = zlib.decompress(data)
                        except:
                            eprint(
                                "[!] Error: Failed to decrypt & decompress {0}. Extracting as is.".format(
                                    filePath
                                )
                            )
                            open(filePath + ".encrypted", "wb").write(data_copy)
                            continue
                
                self._writePyc(filePath, data)


def main():
    parser = argparse.ArgumentParser(description="PyInstaller Extractor NG")
    parser.add_argument(
        "-d",
        "--one-dir",
        help="One directory mode, extracts the pyz in the same directory as the executable",
        action="store_true",
    )
    args = parser.parse_args()

    exe_files = list_exe_files()
    selected_file = select_file(exe_files)

    arch = PyInstArchive(selected_file)
    if arch.open():
        if arch.checkFile():
            if arch.getCArchiveInfo():
                arch.parseTOC()
                arch.extractFiles(args.one_dir)
                arch.close()
                print(
                    "[+] Successfully extracted pyinstaller archive: {0}".format(
                        selected_file
                    )
                )
                print("\nYou can now use a python decompiler on the pyc files within the extracted directory\n")
                print("\n\nPress Enter to Exit...")
                input()
                os._exit(0)
                sys.exit(1)

        arch.close()
    print("\n\nPress Enter to Exit...")
    input()
    os._exit(0)
    sys.exit(1)


if __name__ == "__main__":
    
    def print_banner() -> str:
        sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=32, cols=130))
        banner = r"""
              .__                 __            __                        __                                         
______ ___.__.|__| ____   _______/  |____  ____/  |_____________    _____/  |_  ___________            ____    ____  
\____ <   |  ||  |/    \ /  ___/\   __\  \/  /\   __\_  __ \__  \ _/ ___\   __\/  _ \_  __ \  ______  /    \  / ___\ 
|  |_> >___  ||  |   |  \\___ \  |  |  >    <  |  |  |  | \// __ \\  \___|  | (  <_> )  | \/ /_____/ |   |  \/ /_/  >
|   __// ____||__|___|  /____  > |__| /__/\_ \ |__|  |__|  (____  /\___  >__|  \____/|__|            |___|  /\___  / 
|__|   \/             \/     \/             \/                  \/     \/   Modified By BwE               \//_____/  
    """
        os.system("")
        faded_banner = ""
        blue = 0
        for line in banner.splitlines():
            faded_banner += (f"\033[38;2;0;255;{blue}m{line}\033[0m\n")
            if blue != 255:
                blue += 60
                if blue > 255:
                    blue = 255
        return faded_banner


    def fade(text: str) -> str:
        os.system("")
        faded = ""
        green = 194
        for line in text:
            faded += (f"\033[38;2;0;{green};199m{line}\033[0m")
            if green != 0:
                green -= 6
                if green < 0:
                    green = 0
        return faded
    print(print_banner())
    main()
