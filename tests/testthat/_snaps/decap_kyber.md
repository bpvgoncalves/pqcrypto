# kyber-512 decapsulation works

    Code
      key <- keygen_kyber(512)
    Condition
      Warning:
      `keygen_kyber()` was deprecated in pqcrypto 0.3.0.
      i Please use `keygen_ml_kem()` instead.

---

    Code
      ss1 <- encap_kyber(key$public)
    Condition
      Warning:
      `encap_kyber()` was deprecated in pqcrypto 0.3.0.
      i Please use `encapsulate_ml_kem()` instead.

---

    Code
      ss2 <- decap_kyber(ss1$encapsulation, key$private)
    Condition
      Warning:
      `decap_kyber()` was deprecated in pqcrypto 0.3.0.
      i Please use `decapsulate_ml_kem()` instead.

# kyber-768 decapsulation works

    Code
      key <- keygen_kyber(768)
    Condition
      Warning:
      `keygen_kyber()` was deprecated in pqcrypto 0.3.0.
      i Please use `keygen_ml_kem()` instead.

---

    Code
      ss1 <- encap_kyber(key$public)
    Condition
      Warning:
      `encap_kyber()` was deprecated in pqcrypto 0.3.0.
      i Please use `encapsulate_ml_kem()` instead.

---

    Code
      ss2 <- decap_kyber(ss1$encapsulation, key$private)
    Condition
      Warning:
      `decap_kyber()` was deprecated in pqcrypto 0.3.0.
      i Please use `decapsulate_ml_kem()` instead.

# kyber-1024 decapsulation works

    Code
      key <- keygen_kyber(1024)
    Condition
      Warning:
      `keygen_kyber()` was deprecated in pqcrypto 0.3.0.
      i Please use `keygen_ml_kem()` instead.

---

    Code
      ss1 <- encap_kyber(key$public)
    Condition
      Warning:
      `encap_kyber()` was deprecated in pqcrypto 0.3.0.
      i Please use `encapsulate_ml_kem()` instead.

---

    Code
      ss2 <- decap_kyber(ss1$encapsulation, key$private)
    Condition
      Warning:
      `decap_kyber()` was deprecated in pqcrypto 0.3.0.
      i Please use `decapsulate_ml_kem()` instead.

