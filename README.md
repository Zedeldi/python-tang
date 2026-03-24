# python-tang

[![GitHub license](https://img.shields.io/github/license/Zedeldi/python-tang?style=flat-square)](https://github.com/Zedeldi/python-tang/blob/main/LICENSE) [![GitHub last commit](https://img.shields.io/github/last-commit/Zedeldi/python-tang?style=flat-square)](https://github.com/Zedeldi/python-tang/commits) [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

Python implementation of the Tang protocol.

## Description

> [Tang](https://github.com/latchset/tang) is a server for binding data to network presence.

`python-tang` implements the
[McCallum-Relyea key exchange](https://github.com/latchset/tang#binding), so
that the Tang server must be accessible to reconstitute the binding key.

Basic peers are implemented in `tang.peers`, providing a class for the role of
both client and server within the key exchange.

All cryptographic operations are implemented in `tang.keys.KeyHelper`, using
[`ECC.EccKey`](https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html)
from [PyCryptodome](https://www.pycryptodome.org/). `KeyHelper` also provides
methods to convert to/from a JWK using `python-jose` and an implementation of
`concatkdf` from [José](https://github.com/latchset/jose/blob/b58fdb1ac61cf1b7bd8034f07d76ad7f56c0e02a/lib/openssl/ecdhes.c#L50).

The Tang protocol is implemented by `tang.services.Tang`. Methods for key
advertisement and recovery are implemented by this class, to be used within the
FastAPI app. Keys are loaded from the specified path at instantiation as JWKs.
Filenames with a leading dot (`.`) are treated as rotated keys and will not be
advertised.

### Clevis

`python-tang` is compatible with [Clevis](https://github.com/latchset/clevis):

```console
$ clevis encrypt tang '{"url": "http://<tang server>"}' -y <<< "Hello, world" > ciphertext
$ clevis decrypt < ciphertext
Hello, world
```

## Usage

Start server: `fastapi run tang`

Run tests: `python -m pytest`

## Libraries

- [PyCryptodome](https://pypi.org/project/pycryptodome/) - Cryptographic primitives
- [python-jose](https://pypi.org/project/python-jose/) - JOSE implementation
- [FastAPI](https://pypi.org/project/fastapi/) - Web framework for HTTP API
- [pytest](https://pypi.org/project/pytest/) - Testing framework

## Credits

- [Tang](https://github.com/latchset/tang) - Tang binding daemon
- [Clevis](https://github.com/latchset/clevis) - Automated encryption framework
- [José](https://github.com/latchset/jose) - C implementation of JOSE standards.

## License

`python-tang` is licensed under the GPL v3 for everyone to use, modify and share freely.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

[![GPL v3 Logo](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0-standalone.html)

## Donate

If you found this project useful, please consider donating. Any amount is greatly appreciated! Thank you :smiley:

[![PayPal](https://www.paypalobjects.com/webstatic/mktg/Logo/pp-logo-150px.png)](https://paypal.me/ZackDidcott)
