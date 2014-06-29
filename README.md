OpenPGPStream
=============

Simple implementation of the OpenPGP file format as a Java I/O stream for
symmetric encryption only. It can be used to get a standards compliant
encrypted output format for small Java applications.

## Usage

```
OpenPGPFactory.getInputStream(new FileInputStream("test.pgp"), "password");
```
