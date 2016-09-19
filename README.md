Secure Remote Password (SRP 6a) implementation for GO
=====================================================

[![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/pschlump/Go-FTL/master/LICENSE)

Secure Remote Password protocol (SRP 6a, SRP) is an augmented password-authenticated key agreement (PAKE) protocol, that works around existing patents.
The protocol provides a means of key exchange between a client and a server without ever sending the password across the wire.

SRP performs secure remote authentication of short human-usable passwords and resists both passive and active network attacks.
SRP is the most widely used and standardized protocol of its type.  It offers:

1. Freedom from restrictive licenses.  This implementation is MIT and BSD licensed.
2. Free of patent restrictions.
3. Provides strong authentication.
4. Standardized.
5. Widely used.

This implementation has examples of using it in Go (golang), JavaScript and will soon include an example in Swift on iOS.

According to wikipedia: 

"Like all PAKE protocols, an eavesdropper or man in the middle
cannot obtain enough information to be able to brute force guess a
password without further interactions with the parties for each
guess. This means that strong security can be obtained using weak
passwords. Furthermore, being an augmented PAKE protocol, the server
does not store password-equivalent data. This means that an attacker
who steals the server data cannot masquerade as the client unless
they first perform a brute force search for the password."

"In layman's terms, given two parties who both know a password, SRP
(or any other PAKE protocol) is a way for one party (the "client"
or "user") to demonstrate to another party (the "server") that they
know the password, without sending the password itself, nor any
other information from which the password can be broken, short of
a brute force search."

## References

1. [Stanford](http://srp.stanford.edu/)
2. [Wikipedia](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)

## License

./big is based on Go source code and is licensed accordingly.

All of the rest of the code is MIT licensed.  See LICENSE file.


