# selfsign

A Rust crate providing traits and data types to define self-signing data.  Inspired by the Self-Addressing Identifier concept in [KERI](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf).  This implementation is not necessarily compatible with KERI.  At the moment, it's a very initial implementation, and is a work in progress.

## Overview

In the context of cryptography, it's not possible to directly include a digital signature within the message being signed.  However, it is possible to define slightly altered signing and verification procedures for a given data structure which in a way does contain a signature over itself.

The idea is that the data structure has at least one "slot" for the verifying key and at least one "slot" for the signature.  Hereafter, these will be referred to as self-signature verifier slots and self-signature slots respectively.  Each self-signature slot is meant to represent the same value within the data structure.  Each self-signature verifier slot is meant to represent the same value within the data structure.  The purpose for having multiple of each kind of slot is to be able to have the signature or verifier data appear in multiple places within the data structure (e.g. in the definition of a DID document, in which the self-signature-containing DID itself must appear several places within the DID document).  The signature and verification procedures are as follows:

### Self-Signing

Let the signing key be `S` and the verifying key be `V`.  In asymmetric cryptography, these will be different (the private and public keys respectively), but they could be same as in the case of an HMAC.  Let the data to be self-signed be `D`.  The self-signature slots and self-signature verifier slots of `D` are well-defined and enumerable.

The steps to self-sign are:
1. Set all of `D`'s self-signature verifier slots to `V`.
2. Set all of `D`'s self-signature slots to the "placeholder" value for that signature type (this encodes the signature algorithm and an all-zeros dummy signature value).
3. Serialize `D` with an agreed-upon and deterministic serialization format, producing message `msg`.
4. Sign `msg` using `S`, producing signature `sig`.
5. Set all of `D`'s self-signature slots to `sig`.

At this point, `D` is self-signed, and can be self-verified successfully.

### Self-Verifying

When verifying self-signed data `D`, the signing key is not known and the verifying key isn't known ahead of time but rather is determined from `D`.

The steps to self-verify are:
1. Check that all of `D`'s self-signature slots are equal to each other.  Let this value be `sig`.
2. Check that all of `D`'s self-signature verifier slots are equal to each other.  Let this value be `V`.
3. Set all of `D`'s self-signature slots to the "placeholder" value for that signature type (this is the same as in step 2 of self-signing).
4. Serialize `D` with an agreed-upon and deterministic serialization format, producing message `msg`.
5. Use `V` to verify that `sig` is a valid signature over `msg`.

`D` is defined to be self-verified if and only if step 5 succeeded.

## Serialization Formats

Note that JSON isn't the only usable serialization format (and it's not even a good one, in particular because it doesn't have a canonical form and so may have interoperability issues between different implementations), but it does make for human-readable examples.  [CESR](https://www.ietf.org/archive/id/draft-ssmith-cesr-03.html) is the intended solution to this problem within the KERI ecosystem.  There are a wide range of possible solutions, each fitting different needs.  One that will be elaborated upon later within this git repository will be a process for computing the message digest on a binary serialization of the data in a streaming manner, thereby eliminating allocations and other representational issues that can plague human-readable serialization formats.

## Examples

The examples come from the tests.  To run them:

    cargo test --all-features -- --nocapture

The `--all-features` is necessary for now.

### Example 1 -- Simplest

Here is a simple example in which a data structure has a single self-signature slot and a single self-signature verifier slot.  Here is the primary data, with self-signature and self-signature verifier slots unpopulated:

```json
{"name":"hippodonkey","stuff_count":42,"data_byte_v":[1,2,3],"self_signature_verifier":null,"self_signature":null}
```

During the self-signing process, the `self_signature_verifier` field is populated with the verifying key (in this case, an Ed25519 public key, indicated via prefix `"D"` and the base64url-encoding of the 256 bits of the public key), and the `self_signature` field is populated with the appropriate placeholder (in this case, indicating that the signature algorithm is Ed25519_SHA2_512 via prefix `"0B"` and the base64url-encoding of 512 bits of 0):

```json
{"name":"hippodonkey","stuff_count":42,"data_byte_v":[1,2,3],"self_signature_verifier":"Dgcq4FvGStfSTNNXwYv2t-NiwGG1TtiRz9fgmE1FH26M","self_signature":"0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

After the self-signing process, the `self_signature` field has been populated:

```json
{"name":"hippodonkey","stuff_count":42,"data_byte_v":[1,2,3],"self_signature_verifier":"Dgcq4FvGStfSTNNXwYv2t-NiwGG1TtiRz9fgmE1FH26M","self_signature":"0BwR50D76a5DGVCFkh1LmhhiUipno3DPwkI89sB6hZdmfSNYNdSQz06n0LXmO4wTELnxrROyNnpxwU8poTUnpuAw"}
```

### Example 2 -- Multiple Self-Signature Slots

Here is an example involving a much-simplified version of the DID document data model, a data structure which will be called KeyMaterial here.  NOTE that this just an example, it is not intended to be a complete analog of DIDs/DID documents.  Note that the JSON has been prettified for readability, but what was signed is its compact form.

Root KeyMaterial -- initial definition of the identity, whose name is defined by the `uri` field.  Note here that the value of the `self_signature` field also shows up as a portion of the `uri` field.  This is where having multiple self-signature slots comes in handy.  There are a number of validity checks for this KeyMaterial data model, including, for the root KeyMaterial, that the `self_signature_verifier` field is present within the `capability_invocation_v` array.

```json
{
    "uri": "https://example.com/identity/0BUbRvOl-8QVb-_9OiJdZ_B9zXASfpUrypkLrjFbAVAHQNeVappFDINEtbcAZIK1yo3v0f34iLdTcEQc848oLcAQ",
    "version_id": 0,
    "valid_from": "2023-09-14T07:51:07.084308507Z",
    "authentication_v": [
        "DqK5AA_3VwLeSKqN_QpJXaZDZUbIeX8QN4W3TEZGpt8Q"
    ],
    "assertion_v": [
        "DPn1nUeg7Ykk3ylQ0WaRS7KxiwzfJQR0eXZ24BeOPLuM"
    ],
    "key_exchange_v": [
        "D_1sWlHwfr5ZulnF9oGKPLaZCEA28ZMNI566BrIlKDA0"
    ],
    "capability_invocation_v": [
        "D74m5EuWs6gXS7vBGYTKxHfn3gaQZsP3lV9GbsyodgaA"
    ],
    "capability_delegation_v": [
        "Dwhyexo5BKbQdZrLMqcg2FD9QM17zOQJJJaYBpZeu1ys"
    ],
    "self_signature_verifier": "D74m5EuWs6gXS7vBGYTKxHfn3gaQZsP3lV9GbsyodgaA",
    "self_signature": "0BUbRvOl-8QVb-_9OiJdZ_B9zXASfpUrypkLrjFbAVAHQNeVappFDINEtbcAZIK1yo3v0f34iLdTcEQc848oLcAQ"
}
```

First update to the KeyMaterial -- key rotation.  Note that the `uri` field has not changed.  The controller of the identity must sign the update using a key listed in `capability_invocation_v` when the update action was taken; the `self_signature_verifier` field listed here is present in the previous KeyMaterial's `capability_invocation_v` array, and is NOT present in this one's (because the `capability_invocation_v` key was rotated).

```json
{
    "uri": "https://example.com/identity/0BUbRvOl-8QVb-_9OiJdZ_B9zXASfpUrypkLrjFbAVAHQNeVappFDINEtbcAZIK1yo3v0f34iLdTcEQc848oLcAQ",
    "previous_key_material_self_signature": "0BUbRvOl-8QVb-_9OiJdZ_B9zXASfpUrypkLrjFbAVAHQNeVappFDINEtbcAZIK1yo3v0f34iLdTcEQc848oLcAQ",
    "version_id": 1,
    "valid_from": "2023-09-14T07:51:07.103411189Z",
    "authentication_v": [
        "DLPM9gqlbJPzs0kjAgYC3GbxGbmHPyBFkMJ5ZjSfU95w"
    ],
    "assertion_v": [
        "DsgGc1SXTBn9JTNs2lmSNEczsQ3jFOiBhnaEGuKcajPI"
    ],
    "key_exchange_v": [
        "D8si7YCUVUdV-2CuaCwJLqia1ckCVC6DPhSdOn2mQ51U"
    ],
    "capability_invocation_v": [
        "D3IZLJBDHWkjNOYsXlI0QXQldiK5OiohSGjbbwHVNqAo"
    ],
    "capability_delegation_v": [
        "Dp44hsc9w8xhmfOgbaXW-MP7TWENU9KjJ_TlcDlb6S0Q"
    ],
    "self_signature_verifier": "D74m5EuWs6gXS7vBGYTKxHfn3gaQZsP3lV9GbsyodgaA",
    "self_signature": "0BSxb-syWD56wtrvYA0ia8YgMBa23HCQoPcx_XLZ8n57MkxdUe-WaI5KNIChDI0UJx0o8e-wU6FewUEaSXvzf_CA"
}
```

Second update to the KeyMaterial -- adding some keys.

```json
{
    "uri": "https://example.com/identity/0BUbRvOl-8QVb-_9OiJdZ_B9zXASfpUrypkLrjFbAVAHQNeVappFDINEtbcAZIK1yo3v0f34iLdTcEQc848oLcAQ",
    "previous_key_material_self_signature": "0BSxb-syWD56wtrvYA0ia8YgMBa23HCQoPcx_XLZ8n57MkxdUe-WaI5KNIChDI0UJx0o8e-wU6FewUEaSXvzf_CA",
    "version_id": 2,
    "valid_from": "2023-09-14T07:51:07.130640532Z",
    "authentication_v": [
        "DLPM9gqlbJPzs0kjAgYC3GbxGbmHPyBFkMJ5ZjSfU95w",
        "D71LakXJUwafcGHxSqHsXJ_KdxAFbAFoThwTTHStTpig"
    ],
    "assertion_v": [
        "DsgGc1SXTBn9JTNs2lmSNEczsQ3jFOiBhnaEGuKcajPI",
        "DBycfMsPpm7tm7nRvCC-oqk-kO1iVvjPstXMA1uAwSDQ"
    ],
    "key_exchange_v": [
        "D8si7YCUVUdV-2CuaCwJLqia1ckCVC6DPhSdOn2mQ51U",
        "DFa5I_KaKxIWV4sc1O44GW63sKGNO9s7ZA2JxCDAVWEo"
    ],
    "capability_invocation_v": [
        "D3IZLJBDHWkjNOYsXlI0QXQldiK5OiohSGjbbwHVNqAo"
    ],
    "capability_delegation_v": [
        "Dp44hsc9w8xhmfOgbaXW-MP7TWENU9KjJ_TlcDlb6S0Q"
    ],
    "self_signature_verifier": "D3IZLJBDHWkjNOYsXlI0QXQldiK5OiohSGjbbwHVNqAo",
    "self_signature": "0BNue25ookArn-LNbrQMMKVwyL8oCsrH6jDfscNnLftbyhe7rQknjpEPjs7p3I670Ed9-1m0fiygGgEZPpxPSGCw"
}
```

## References

-   https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf
-   https://github.com/THCLab/cesrox
-   https://github.com/WebOfTrust/keriox
-   https://www.ietf.org/archive/id/draft-ssmith-cesr-03.html

## Copyright

Copyright 2023 LedgerDomain

## License

Apache 2.0
