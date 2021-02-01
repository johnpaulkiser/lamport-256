[![codecov](https://codecov.io/gh/johnpaulkiser/lamport-256/branch/main/graph/badge.svg?token=ZWIK9EVZ3N)](https://codecov.io/gh/johnpaulkiser/lamport-256)
![tests](https://github.com/johnpaulkiser/lamport-256/workflows/tests/badge.svg)
![upload to pypi](https://github.com/johnpaulkiser/lamport-256/workflows/upload%20to%20pypi/badge.svg)

# lamport-256
Simple single use Lamport signature scheme in python

_Great for building toy blockchains and the like._

**DO NOT use in a security conscious production environment!** 


## Usage:
### Library

To install run 
```bash
> pip install lamport-256
```

Import
```python
import lamport_256
```

Generate a private/public key pair
```python
key_pair = lamport_256.generate_keys()
private_key = keypair.priv
public_key = keypair.pub
```

Sign a message
```python
signature = sign_message(private_key, 'Hello, World')
```

Verify a message
```python
if not verify_signature(public_key, 'Hello, World', signature):
    raise Exception('Invalid signature')
```

Dump key pair to files
```python
export_key_pair(key_pair, 'pub.key', 'priv.key') #filenames can be named anything you'd like

# Or individually:
export_key(key_pair.priv, 'priv.key')
```

Read key pair from file
```python
key_pair = parse_key_pair('location/of/pub.key', 'location/of/priv.key')

# Or individually:
pub = parse_key('pub.key')
```

_____
### CLI

Although you can simply run `python location/to/lamport_256.py generate_keys` its best to create an alias to run the python script
```bash
# In your .bashrc or equivalent
alias lamp='python location/of/lamport_256.py'
```

Now you can run the script more concisely
```bash
lamp generate_keys
```

To specify where to save keys to use the apropriate options
```bash
lamp generate_keys --priv location/to/save/key --pub location/to/save/key
```

Sign a message
```bash
lamp sign location/of/private/key 'Hello, world' > signature.txt
```

Verify a signature
```bash
lamp verify location/of/public/key 'message' location/of/signature 
```
