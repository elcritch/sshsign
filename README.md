# sshsign

A Nim library for signing and verifying messages using SSH keys via the `ssh-keygen` command-line tool. This library provides a simple, thread-safe interface to SSH's built-in signing capabilities.

## Features

- Sign messages and files using SSH private keys
- Verify signatures using SSH public keys
- Thread-safe process execution
- Support for custom namespaces
- Compatible with SSH's allowed_signers format

## Requirements

- Nim compiler
- OpenSSH with `ssh-keygen` support for signing (OpenSSH 8.0+)

## Installation

Add to your `.nimble` file:

```nim
requires "https://github.com/yourusername/sshsign"
```

Or install directly:

```bash
nimble install sshsign
```

## Quick Start

```nim
import sshsign

# Sign a message
let signature = signMessage(
  "Hello, World!",
  "~/.ssh/id_ed25519",
  "application"
).signature

# Verify the signature
let allowedSigners = "user@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx..."
let result = verifyMessage(
  "Hello, World!",
  signature,
  allowedSigners,
  "user@example.com",
  "application"
)

if result.valid:
  echo "Signature is valid!"
else:
  echo "Signature verification failed: ", result.message
```

## API Documentation

### Signing Messages

#### `signMessage`

Signs a message string using an SSH private key.

```nim
proc signMessage(message: string,
                 privateKeyPath: string,
                 namespace: string = "file",
                 keepFiles: bool = false): SignResult
```

**Parameters:**
- `message`: The message to sign
- `privateKeyPath`: Path to SSH private key (supports `~` expansion)
- `namespace`: Namespace for the signature (default: "file")
- `keepFiles`: Keep temporary files (default: false)

**Returns:** `SignResult` with signature and optional file path

**Example:**
```nim
let result = signMessage("Hello!", "~/.ssh/id_ed25519", "myapp")
echo result.signature
```

#### `signFile`

Signs a file using an SSH private key.

```nim
proc signFile(filePath: string,
              privateKeyPath: string,
              namespace: string = "file"): string
```

**Example:**
```nim
let signature = signFile("document.txt", "~/.ssh/id_ed25519", "file")
writeFile("document.txt.sig", signature)
```

### Verifying Signatures

#### `verifyMessage`

Verifies a message signature.

```nim
proc verifyMessage(message: string,
                   signature: string,
                   allowedSigners: string,
                   identity: string,
                   namespace: string = "file"): VerifyResult
```

**Parameters:**
- `message`: Original message that was signed
- `signature`: SSH signature to verify
- `allowedSigners`: Content of allowed_signers file
- `identity`: Identity to verify (e.g., "user@example.com")
- `namespace`: Namespace used for signing

**Returns:** `VerifyResult` with `valid` boolean and message

**Example:**
```nim
let allowedSigners = """
user@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx...
"""

let result = verifyMessage(
  "Hello!",
  signature,
  allowedSigners,
  "user@example.com",
  "myapp"
)

if result.valid:
  echo "Valid signature"
```

#### `verifyFile`

Verifies a file signature.

```nim
proc verifyFile(filePath: string,
                signaturePath: string,
                allowedSigners: string,
                identity: string,
                namespace: string = "file"): VerifyResult
```

**Example:**
```nim
let allowedSigners = readFile("allowed_signers")
let result = verifyFile(
  "document.txt",
  "document.txt.sig",
  allowedSigners,
  "user@example.com"
)
```

## Complete Example

```nim
import sshsign, os

# Setup
let privateKey = "~/.ssh/id_ed25519"
let publicKey = readFile(expandTilde("~/.ssh/id_ed25519.pub"))
let identity = "developer@example.com"

# Create allowed_signers format: "identity key-type key-data"
let allowedSigners = identity & " " & publicKey

# Sign a message
echo "Signing message..."
let signResult = signMessage(
  "This is a secure message",
  privateKey,
  "myapp"
)

# Verify the signature
echo "Verifying signature..."
let verifyResult = verifyMessage(
  "This is a secure message",
  signResult.signature,
  allowedSigners,
  identity,
  "myapp"
)

if verifyResult.valid:
  echo "✓ Signature verified successfully!"
  echo "Message: ", verifyResult.message
else:
  echo "✗ Signature verification failed!"
  echo "Error: ", verifyResult.message
```

## Error Handling

The library raises `SshSignError` for SSH-related errors:

```nim
try:
  let signature = signMessage("Hello", "/invalid/key", "app")
except SshSignError as e:
  echo "Signing failed: ", e.msg
except OSError as e:
  echo "File error: ", e.msg
```

## Namespaces

Namespaces prevent signature reuse across different contexts. Always use specific namespaces for your application:

```nim
# Good: Specific namespaces
signMessage(msg, key, "myapp.login")
signMessage(msg, key, "myapp.api")

# Bad: Generic namespace
signMessage(msg, key, "file")
```

## Thread Safety

This library is thread-safe and can be used in multi-threaded applications. All process executions use the thread-safe `execProcessCapture` function.

## License

MIT

## Contributing

Contributions welcome! Please open an issue or pull request.
