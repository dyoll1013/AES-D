Overview
========

This is my personal, for-fun implementation of [AES](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf) in [D](http://dlang.org), one of my favorite programming languages. In addition to the naive implementation in pure, portable D code, I wrote a much faster version in assembly using the x86 [AES-NI](http://download-software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf) extensions.

In addition to the library which implements the AES algorithm, I wrote two utilities to demonstrate use of the library. `aestool.d` can be used to encrypt or decrypt files with a given key, optionally employing the [CBC mode of operation](http://en.wikipedia.org/wiki/Cipher_block_chaining#Cipher-block_chaining_.28CBC.29). `speedtest.d` generates a user-specified amount of data and then measures the speed at which encryption and decryption of that data can be done. It was primarily written to compare the speed of the naive and AES-NI versions.

Disclaimer
==========

This code is not certified to be secure. It was written by a college student in his free time. I believe that the implementation is correct, but it's probably vulnerable to [side-channel attacks](http://en.wikipedia.org/wiki/Side-channel_attacks). You should not use this code if you want to create a secure system.

Furthermore, although I've tested the basic algorithms on small amounts of data (see the unit tests), the functions in the `aes.util` module are not very well tested, and therefore `aestool.d` isn't either.

Building
========

Use `make aestool` or `make speedtest` to build either of the utilities. All binaries are placed in the `build` directory. To run the library's unit tests, run `make test`.

You will need [nasm](http://www.nasm.us/) for the assembly code and [DMD v2.064](http://dlang.org/download.html) or greater for the D code.

It should compile on 64-bit OS X and Linux machines. Slight modifications to the Makefile should help it run on Windows, but I haven't tested this at all. The D code should compile fine on 32-bit machines, but the assembly is written for 64-bit.