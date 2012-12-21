#Boneh-Gentry-Waters broadcast key encapsulation scheme (PPC_BKEM)

This Broadcast Key Encapsulation Mechanism (BKEM) implements the [Boneh-Gentry-Waters Broadcast Encryption scheme](http://crypto.stanford.edu/~dabo/abstracts/broadcast.html) (Sec. 3.2, General Construction).

PBC_BKEM is implemented using the [Pairing-Based Cryptography Library](http://crypto.stanford.edu/pbc/) by Ben Lynn.

The scheme depends on a symmetric pairing, thus a [Type-A pairing](http://crypto.stanford.edu/pbc/manual/ch08s03.html) is required.

## Installation

PBC_BKEM depends on the PBC library, which itself depends on GMP. Please see their respective manuals for build instructions.

To build the test program, simply run:

	gcc bkem.c testscheme.c -lgmp -lpbc

## Contact
Oliver Günther, mail@oliverguenther.de

##LICENSE

PBC_BKEM is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PBC_BKEM is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
