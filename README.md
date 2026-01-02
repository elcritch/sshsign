# sshsign

A Nim library for signing and verifying messages using SSH keys via the `ssh-keygen` command-line tool. This library provides a simple, thread-safe interface to SSH's built-in signing capabilities.

## Features

- Sign messages and files using SSH private keys
- Verify signatures using SSH public keys
- **GitHub Integration**: Verify signatures using GitHub user's public SSH keys
- **JSON Serialization**: Simple JSON encoding/decoding for results
- Thread-safe process execution
- Support for custom namespaces
- Compatible with SSH's allowed_signers format

## Requirements

- Nim compiler
- OpenSSH with `ssh-keygen` support for signing (OpenSSH 8.0+)
- SSL support (compile with `-d:ssl`) for GitHub integration features

## Installation

Add to your `.nimble` file:

```nim
requires "https://github.com/elcritch/sshsign"
```

Or install directly:

```bash
nimble install sshsign
```

## Quick Start

```nim
import sshsign

# Sign a message
let signResult = signMessage(
  "Hello, World!",
  "~/.ssh/id_ed25519",
  "application"
)

# Verify the signature
let allowedSigners = "user@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx..."
let verifyResult = verifyMessage(
  "Hello, World!",
  signResult.signature,
  allowedSigners,
  "user@example.com",
  "application"
)

if verifyResult.valid:
  echo "Signature is valid!"
else:
  echo "Signature verification failed: ", verifyResult.message

# Serialize to JSON
echo verifyResult.toJsonString()
# Output: {"valid":true,"message":"Good signature..."}
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

### GitHub Integration

#### `fetchGithubKeys`

Fetches SSH public keys for a GitHub user from `github.com/{username}.keys`.

```nim
proc fetchGithubKeys(username: string): string
```

**Parameters:**
- `username`: GitHub username

**Returns:** Public keys in SSH format (one per line)

**Example:**
```nim
let keys = fetchGithubKeys("elcritch")
echo keys
```

**Note:** Requires compilation with `-d:ssl` flag for HTTPS support.

#### `verifyMessageWithGithubUser`

Verifies a message signature using a GitHub user's public keys.

```nim
proc verifyMessageWithGithubUser(message: string,
                                  signature: string,
                                  githubUsername: string,
                                  namespace: string = "file"): VerifyResult
```

**Parameters:**
- `message`: Original message that was signed
- `signature`: SSH signature to verify
- `githubUsername`: GitHub username whose keys to use
- `namespace`: Namespace used for signing (default: "file")

**Returns:** `VerifyResult` with validation status

**Example:**
```nim
# Sign a message with your SSH key
let signature = signMessage("Hello!", "~/.ssh/id_ed25519", "myapp").signature

# Verify using a GitHub user's public keys
let result = verifyMessageWithGithubUser(
  "Hello!",
  signature,
  "elcritch",
  "myapp"
)

if result.valid:
  echo "Signature verified against GitHub user's keys!"
```

#### `verifyFileWithGithubUser`

Verifies a file signature using a GitHub user's public keys.

```nim
proc verifyFileWithGithubUser(filePath: string,
                               signaturePath: string,
                               githubUsername: string,
                               namespace: string = "file"): VerifyResult
```

**Example:**
```nim
let result = verifyFileWithGithubUser(
  "document.txt",
  "document.txt.sig",
  "elcritch",
  "file"
)
```

### JSON Serialization

The library provides simple JSON serialization for `SignResult` and `VerifyResult` types.

#### `toJson`

Converts results to JSON nodes.

```nim
# Serialize SignResult
let signResult = signMessage("Hello", "~/.ssh/id_ed25519", "app")
let jsonNode = signResult.toJson()
echo jsonNode.pretty()

# Serialize VerifyResult
let verifyResult = verifyMessage(msg, sig, allowed, identity, ns)
let jsonNode = verifyResult.toJson()
```

#### `fromJson`

Deserializes results from JSON.

```nim
# Deserialize SignResult
let json = parseJson("""{"signature": "...", "signatureFile": ""}""")
let signResult = SignResult.fromJson(json)

# Deserialize VerifyResult
let json = parseJson("""{"valid": true, "message": "Good signature"}""")
let verifyResult = VerifyResult.fromJson(json)
```

#### `toJsonString`

Converts results directly to JSON strings.

```nim
# Convert to JSON string
let signResult = signMessage("Hello", "~/.ssh/id_ed25519", "app")
let jsonStr = signResult.toJsonString()

# Save to file
writeFile("signature.json", jsonStr)

# Load and parse
let loaded = parseJson(readFile("signature.json"))
let restored = SignResult.fromJson(loaded)
```

**JSON Format Examples:**

SignResult:
```json
{
  "signature": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----",
  "signatureFile": ""
}
```

VerifyResult:
```json
{
  "valid": true,
  "message": "Good signature for test@example.com with ED25519 key SHA256:..."
}
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
