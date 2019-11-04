Overview
========
librho is utility library that provides:

- wrappers for C library functions for easier error handling
- implementations of common data structures
- encoders and decoders for common data formats
- a small event framework, along the lines of libevent
- a small unit test framework, along the lines of CUnit
- an interface for crypto and SSL that abstracts the underlying
  cryptography provider.

The library assumes a POSIX environment, with a few platform-specific features.
I try to ensure that librho works on Linux, macOS, FreeBSD, NetBSD, and
OpenBSD, but only regularly use the library on Linux.

Some source files are wholey or partly from other projects.  For instance,
`rho_atomic.h` is mostly based on musl libc's atomic functions, and
`rho_queue.h` is from OpenBSD.  In such situtions, the source file
contains the appropriate copyright notice.


<a name="building"/> Building and Installing
============================================
To build librho, enter:

```
git clone https:/github.com/smherwig/librho
cd librho/src
make
```

The build creates two libraries: `librho.a`, and a position-independent
version, `librho-pic.a`; the former is for statically linking into an
executable; the latter for statically linking into a shared object.


To install, enter:

```
make install
```

By default, the librho libraries and headers are installed to `/usr/local/`.
To install to a different, location, say, `/home/smherwig`, enter

```
make install INSTALL_TOP=/home/smherwig
```

When installed, the headers are placed under a `rho` directory (in the above
example, `/home/smherwig/include/rho/`); with the header file `rho/rho.h`
including all other rho headers.


The `src/Makefile` allows for adjusting various options, such as the platform
(e.g, Linux, FreeBSD) and cryptographic provider (openssl or bearssl).


<a name="testing"/> Testing
===========================
A fairly incomplete set of unit tests exists under `test`.  To build the unit
tests, enter:

```
cd librho/test
make
```

This creates a set of executables, with each executable testing a specific
module.  For instance, `rho_str_test` tests the functions in `src/rho_str.c`.
