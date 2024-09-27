# selfsign-bin

CLI tool for generating and verifying self-signed-and-hashed JSON.

## Installation

Run:

    cargo install --path <path-to-this-dir>

## Usage

### Help messages

Run:

    selfsign

Output:
    
    Operate on JSON as self-sign-and-hashable data -- signed data which is self-validating.  In particular, self-signable data is data which has at least one "self-signature slot" and "self-signature verifier slot" which is used during the computation and verification of the data's self-signature.  During the computation of the data's self-signatures, all the self-signature slots and self-hash slots, if present, are set to appropriate placeholder values which encode the public key, the digital signature algorithm, and the hash function that will be used in the self-signing and self-hashing procedure, the data is serialized into JCS (JSON Canonicalization Scheme), signed, that signature is used to populate all self-signature slots, the data is serialized into JCS again, hashed, then that hash is used to populate all self-hash slots, and finally the data is serialized into JCS.  The data is then serialized into JCS again, and at this point is self-signed-and-hashed, and is fully self-verifiable
    
    Usage: selfsign <COMMAND>
    
    Commands:
      gen-key  Generate a private key with which to self-sign JSON blobs
      compute  Read JSON from stdin, self-sign and self-hash the JSON, and output the resulting canonical JSON (JCS), overwriting any existing self-signature, self-signature verifier, and self-hash fields
      verify   Read JSON from stdin, verify its self-signature(s) and self-hash(es), and print the verified self-hash
      help     Print this message or the help of the given subcommand(s)
    
    Options:
      -h, --help     Print help
      -V, --version  Print version

Run:

    selfsign gen-key --help

Output:

    Generate a private key, writing it in PEM format to a specified filename, which can be used to self-sign JSON blobs.  Print the public key corresponding to the generated private key to stdout
    
    Usage: selfsign gen-key [OPTIONS] --key-type <KEY_TYPE> --private-key-path <PRIVATE_KEY_PATH>
    
    Options:
      -k, --key-type <KEY_TYPE>
              Specify the type of key to be generated.  Must be one of Ed25519, Secp256k1
      -p, --private-key-path <PRIVATE_KEY_PATH>
              Specify the path to write the generated private key to.  If the path exists already, it will not be overwritten, and this program will return an error
      -n, --no-newline
              If specified, don't print a trailing newline in the output [default: print newline]
      -h, --help
              Print help

Run:

    selfsign compute --help

Output:

    Read JSON from stdin, self-sign and self-hash the JSON, and output the resulting canonical JSON (JCS), overwriting any existing self-signature, self-signature verifier, and self-hash fields
    
    Usage: selfsign compute [OPTIONS] --private-key-path <PRIVATE_KEY_PATH>
    
    Options:
      -p, --private-key-path <PRIVATE_KEY_PATH>
              Specify the path of the private key to be used for the self-signing operation
      -s, --self-hash-field-names <FIELD_NAME>
              Optionally specify a comma-delimited list of top-level field names that are considered self-hash slots [default: selfHash]
      -u, --self-hash-url-field-names <FIELD_NAME>
              Optionally specify a comma-delimited list of top-level field names that are considered self-hash URL slots [default: ]
      -n, --no-newline
              If specified, don't print a trailing newline in the output [default: print newline]
      -h, --help
              Print help

Run:

    selfsign verify --help

Output:

    Read JSON from stdin, verify its self-signature(s) and self-hash(es), and print the verified self-hash
    
    Usage: selfsign verify [OPTIONS]
    
    Options:
      -s, --self-hash-field-names <FIELD_NAME>
              Optionally specify a comma-delimited list of top-level field names that are considered self-hash slots [default: selfHash]
      -u, --self-hash-url-field-names <FIELD_NAME>
              Optionally specify a comma-delimited list of top-level field names that are considered self-hash URL slots [default: ]
      -n, --no-newline
              If specified, don't print a trailing newline in the output [default: print newline]
      -h, --help
              Print help

## Example Usage

### `selfsign gen-key`

Run:

    selfsign gen-key -k ed25519 -p alice-priv.pem

Output (one possible output; depends on random number generator):

    DiKCjBWEB-qnKi82oWjTFQQ-lBSRzO8mDRzQPyVNRLPw

Run (again, using the same filename):

    selfsign gen-key -k ed25519 -p alice-priv.pem

Output:

    Path "priv.pem" specified by --private-key-path already exists -- refusing to overwrite.

Run:

    selfsign gen-key -k secp256k1 -p bob-priv.pem

Output (one possible output; depends on random number generator):

    1AABA-9kuYOd443TzDTi6mCVJhnYPLIndE3j9oAxJpbLUzgA

### `selfsign compute`

Run (ensuring that there is a private key generated to `alice-priv.pem`):

    echo '{"blah": 3}' | selfsign compute -p alice-priv.pem

Output:

    {"blah":3,"selfHash":"E9tvmHN_SV3mQF5LGrZpXQUCpuIkpifCG3D1yVJCekUg","selfSignature":"0B_Qszuzk2VIadjgvVT2gLYc0hzRBv7CIQpX30m6CwwKmLkLgUjaeUR3vOuaCSXy1-FOH8Q39583WoqDU8XySaDg","selfSignatureVerifier":"DiKCjBWEB-qnKi82oWjTFQQ-lBSRzO8mDRzQPyVNRLPw"}

Run (ensuring that there is a private key generated to `bob-priv.pem`):

    echo '{"blah": 3}' | selfsign compute -p bob-priv.pem

Output:

    {"blah":3,"selfHash":"EUeJ1EiOH1lZZZZ9Rs4GVM9O3obaO6woQqhFepqy83cg","selfSignature":"0CSXE42GoHtHaG50KfB0hyi42xGaHc10ab5-5_MAsFHLtWWu2EyUCUAUz7oh8ImtY4Xp0HrXZ7STPpT3TrShssxA","selfSignatureVerifier":"1AABA-9kuYOd443TzDTi6mCVJhnYPLIndE3j9oAxJpbLUzgA"}

### `selfsign verify`

Run:

    echo '{"blah":3,"selfHash":"E9tvmHN_SV3mQF5LGrZpXQUCpuIkpifCG3D1yVJCekUg","selfSignature":"0B_Qszuzk2VIadjgvVT2gLYc0hzRBv7CIQpX30m6CwwKmLkLgUjaeUR3vOuaCSXy1-FOH8Q39583WoqDU8XySaDg","selfSignatureVerifier":"DiKCjBWEB-qnKi82oWjTFQQ-lBSRzO8mDRzQPyVNRLPw"}' | selfsign verify

Output (this is the verified self-hash of the JSON blob):

    E9tvmHN_SV3mQF5LGrZpXQUCpuIkpifCG3D1yVJCekUg

Run:

    echo '{"blah":3,"selfHash":"EUeJ1EiOH1lZZZZ9Rs4GVM9O3obaO6woQqhFepqy83cg","selfSignature":"0CSXE42GoHtHaG50KfB0hyi42xGaHc10ab5-5_MAsFHLtWWu2EyUCUAUz7oh8ImtY4Xp0HrXZ7STPpT3TrShssxA","selfSignatureVerifier":"1AABA-9kuYOd443TzDTi6mCVJhnYPLIndE3j9oAxJpbLUzgA"}' | selfsign verify

Output (this is the verified self-hash of the JSON blob):

    EUeJ1EiOH1lZZZZ9Rs4GVM9O3obaO6woQqhFepqy83cg
