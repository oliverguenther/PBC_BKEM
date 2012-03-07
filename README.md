#Boneh-Gentry-Waters broadcast encryption scheme (PBC_bes)

PBC_bes implements the [Boneh-Gentry-Waters broadcast encryption system](http://crypto.stanford.edu/~dabo/abstracts/broadcast.html) (Based on the general construction of that scheme).

PBC_bes is based on the [Pairing-Based Cryptography Library](http://crypto.stanford.edu/pbc/) by Ben Lynn.

The scheme depends on a symmetric pairing, thus a [Type-A pairing](http://crypto.stanford.edu/pbc/manual/ch08s03.html) is required.

## Installation

PBC_bes depends on the PBC library, which itself depends on GMP. Please see their respective manuals for build instructions.

To build the test program, run:

	gcc pbc_bes.c testscheme.c -lgmp -lpbc

## TODO
- Key-Deriviation from Enc/Decryption key K
- I/O methods for structs

## Contact
Oliver Günther, mail@oliverguenther.de

##LICENSE

PBC_bes is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PBC_bes is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
