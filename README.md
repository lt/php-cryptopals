# [PHP Cryptopals](https://github.com/lt/php-cryptopals)

The [Matasano crypto challenges](http://cryptopals.com/) completed using PHP

The README files scattered throughout contain the original challenge text, in case the original site goes away.

Progress:

- [x] **Set 1: Basics**
  - [x] 1. Convert hex to base64
  - [x] 2. Fixed XOR
  - [x] 3. Single-byte XOR cipher
  - [x] 4. Detect single-character XOR
  - [x] 5. Implement repeating-key XOR
  - [x] 6. Break repeating-key XOR
  - [x] 7. AES in ECB mode
  - [x] 8. Detect AES in ECB mode
- [x] **Set 2: Block crypto**
  - [x] 9. Implement PKCS#7 padding
  - [x] 10. Implement CBC mode
  - [x] 11. An ECB/CBC detection oracle
  - [x] 12. Byte-at-a-time ECB decryption (Simple)
  - [x] 13. ECB cut-and-paste
  - [x] 14. Byte-at-a-time ECB decryption (Harder)
  - [x] 15. PKCS#7 padding validation
  - [x] 16. CBC bitflipping attacks
- [x] **Set 3: Block & stream crypto**
  - [x] 17. The CBC padding oracle
  - [x] 18. Implement CTR, the stream cipher mode
  - [x] 19. Break fixed-nonce CTR mode using substitions
  - [x] 20. Break fixed-nonce CTR statistically
  - [x] 21. Implement the MT19937 Mersenne Twister RNG
  - [x] 22. Crack an MT19937 seed
  - [x] 23. Clone an MT19937 RNG from its output
  - [x] 24. Create the MT19937 stream cipher and break it
- [x] **Set 4: Stream crypto and randomness**
  - [x] 25. Break "random access read/write" AES CTR
  - [x] 26. CTR bitflipping
  - [x] 27. Recover the key from CBC with IV=Key
  - [x] 28. Implement a SHA-1 keyed MAC
  - [x] 29. Break a SHA-1 keyed MAC using length extension
  - [x] 30. Break an MD4 keyed MAC using length extension
  - [x] 31. Implement and break HMAC-SHA1 with an artificial timing leak
  - [x] 32. Break HMAC-SHA1 with a slightly less artificial timing leak
- [ ] **Set 5: Diffie-Hellman and friends**
  - [x] 33. Implement Diffie-Hellman
  - [x] 34. Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
  - [x] 35. Implement DH with negotiated groups, and break with malicious "g" parameters
  - [x] 36. Implement Secure Remote Password (SRP)
  - [x] 37. Break SRP with a zero key
  - [x] 38. Offline dictionary attack on simplified SRP
  - [ ] 39. Implement RSA
  - [ ] 40. Implement an E=3 RSA Broadcast attack
- [ ] **Set 6: RSA and DSA**
  - [ ] 41. Implement unpadded message recovery oracle
  - [ ] 42. Bleichenbacher's e=3 RSA Attack
  - [ ] 43. DSA key recovery from nonce
  - [ ] 44. DSA nonce recovery from repeated nonce
  - [ ] 45. DSA parameter tampering
  - [ ] 46. RSA parity oracle
  - [ ] 47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
  - [ ] 48. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)
- [ ] **Set 7: Hashes**
  - [ ] 49. CBC-MAC Message Forgery
  - [ ] 50. Hashing with CBC-MAC
  - [ ] 51. Compression Ratio Side-Channel Attacks
  - [ ] 52. Iterated Hash Function Multicollisions
  - [ ] 53. Kelsey and Schneier's Expandable Messages
  - [ ] 54. Kelsey and Kohno's Nostradamus Attack
  - [ ] 55. MD4 Collisions
  - [ ] 56. RC4 Single-Byte Biases
