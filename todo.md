# To-Do List for `selfsign`

-   Add more asymmetric key types and corresponding SignatureAlgorithms
    -   Secp256k1
    -   Secp256r1 (aka P-256)
-   Choose a deterministic, no-alloc, streaming binary serialization format to recommend.  The idea here being that the serialization should simply traverse the data structure and stream its contents into the message digest Hasher object.
-   Implement a proc macro for deriving `SelfSignable` on structures.
