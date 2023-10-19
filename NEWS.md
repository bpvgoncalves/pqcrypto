# pqcrypto (development version)

#### Fix
 - TSA secure time stamp defaults to use system time on http error or disconnection

#### Internals
 - Fix some problems preventing R CMD Check to work in some R/OS versions
 - Add additional tests to the suite

# pqcrypto 0.2.0

#### New Features
 - Specialized `print()` for some pqcrypto_* objects
 - Add `write_key()` and `open_key()` for key saving and retrieval
 - Digital Signatures:
   - Add new signing algorithm: Sphincs+
   - Add `write_signature()`and `read_signature()`for digital signatures saving and retrieval
   - Add signed metadata to digital signatures
   - Add secure time stamp from https://freetsa.org to digital signatures
 - Add envelope to send encrypted data and key
 - Add `write_envelope()`and `read_envelope()`for envelope saving and retrieval


#### Internals
 - Some changes to classes, new tests, lib compilation, ...
 - Change data types from integer to raw

# pqcrypto 0.1.0

 - Initial public version.
