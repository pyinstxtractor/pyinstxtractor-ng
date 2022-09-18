# pyinstxtractor-ng

pyinstxtractor-ng is a tool to extract the contents of a Pyinstaller generated executable file. Both Linux ELFs and Windows PE executables are supported.

This project is a fork of [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor).

pyinstxtractor-ng uses the [xdis](https://github.com/rocky/python-xdis/) library to unmarshal Python bytecode and as a result there is NO requirement to use the same Python version which was used to build the executable.


## Usage

Precompiled binaries for Linux and Windows are provided in [releases](https://github.com/pyinstxtractor/pyinstxtractor-ng/releases). 
These are generated using PyInstaller itself, so you don't even need a Python installation to run pyinstxtractor-ng

```
$ ./pyinstxtractor-ng <filename>
X:\> pyinstxtractor-ng <filename>
```

## License

GNU General Public License v3.0