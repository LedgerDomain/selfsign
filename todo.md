# To-Do List for `selfsign`

-   Ideally get rid of NamedSignatureAlgorithm and maybe KeyType in favor of use of traits, so that the relevant Verifier, Signer, Signature traits can be implemented for arbitrary key types and signature algorithms, and client programs don't need to extend the `selfsign` crate in order to support additional key types and signature algorithms.  There would be a kind of registrar for key types and signature algorithms that is passed into self_sign and verify_self_signatures.
-   Add more asymmetric key types and corresponding SignatureAlgorithms
    -   Secp256r1 (aka P-256)
-   Choose a deterministic, no-alloc, streaming binary serialization format to recommend.  The idea here being that the serialization should simply traverse the data structure and stream its contents into the message digest Hasher object.
-   Implement a proc macro for deriving `SelfSignable` on structures.
-   Implement a proc macro for deriving `SelfSignAndHashable` on structures.
-   Add specific test vectors to ensure the specific encoding/decoding of the KERIVerifier and KERISignature types are correct.
