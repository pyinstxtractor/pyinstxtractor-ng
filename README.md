# pyinstxtractor-ng

pyinstxtractor-ng is a tool to extract the contents of a Pyinstaller generated executable file. Both Linux ELFs and Windows PE executables are supported.

This project is a fork of [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor).

pyinstxtractor-ng uses the [xdis](https://github.com/rocky/python-xdis/) library to unmarshal Python bytecode and as a result there is NO requirement to use the same Python version which was used to build the executable.

pyinstxtractor-ng also supports automatic decryption of encrypted pyinstaller executables.

## Usage

Precompiled binaries for Linux and Windows are provided in [releases](https://github.com/pyinstxtractor/pyinstxtractor-ng/releases). 
These are generated using PyInstaller itself, so you don't even need a Python installation to run pyinstxtractor-ng

```
PyInstaller Extractor NG

positional arguments:
  filename       Path to the file to extract

optional arguments:
  -h, --help     show this help message and exit
  -d, --one-dir  One directory mode, extracts the pyz to the same directory
```

Pass the exe filename as an argument or drag & drop the pyinstaller exe file over pyinstxtractor.ng icon on Windows.
```
$ ./pyinstxtractor-ng <filename>
X:\> pyinstxtractor-ng <filename>
```

The `--one-dir` mode extracts the pyz in the same directory as the executable. This is useful if you want to run the extracted files straight-away.

```
X:\> pyinstxtractor-ng --one-dir main.exe
X:\> cd main.exe_extracted
X:\main.exe_extracted\> python main.py
```

## See Also

- [pyinstxtractor-web](https://pyinstxtractor-web.netlify.app/): pyinstxtractor running in the web browser, powered by Go & GopherJS.

## License

GNU General Public License v3.0