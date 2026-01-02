## SSH Message Signing Library
##
## This library provides functionality to sign and verify messages using SSH keys
## via the ssh-keygen command-line tool.
##
## Example:
##
## .. code-block:: nim
##   import sshsign
##
##   # Sign a message
##   let signature = signMessage("Hello, World!", "~/.ssh/id_ed25519", "application")
##
##   # Verify a signature
##   let allowedSigners = "user@example.com ssh-ed25519 AAAAC3..."
##   let isValid = verifyMessage("Hello, World!", signature, allowedSigners,
##                               "user@example.com", "application")

import std/[osproc, os, tempfiles, strutils]

type
  SshSignError* = object of CatchableError
    ## Exception raised when SSH signing operations fail

  SignResult* = object
    ## Result of a signing operation
    signature*: string      ## The signature in SSH signature format
    signatureFile*: string  ## Path to the signature file (if kept)

  VerifyResult* = object
    ## Result of a verification operation
    valid*: bool           ## Whether the signature is valid
    message*: string       ## Message from ssh-keygen about the verification

proc signMessage*(message: string,
                  privateKeyPath: string,
                  namespace: string = "file",
                  keepFiles: bool = false): SignResult =
  ## Signs a message using an SSH private key via ssh-keygen.
  ##
  ## Parameters:
  ##   - message: The message to sign
  ##   - privateKeyPath: Path to the SSH private key file
  ##   - namespace: The namespace for the signature (default: "file")
  ##   - keepFiles: If true, keeps temporary files and returns their paths
  ##
  ## Returns:
  ##   A SignResult containing the signature and optionally file paths
  ##
  ## Raises:
  ##   - SshSignError: If signing fails
  ##   - OSError: If file operations fail

  # Expand tilde in key path
  let keyPath = expandTilde(privateKeyPath)

  if not fileExists(keyPath):
    raise newException(SshSignError, "Private key file not found: " & keyPath)

  # Create temporary file for the message
  let (msgFile, msgPath) = createTempFile("sshsign_msg_", ".txt")
  try:
    msgFile.write(message)
    msgFile.close()

    let sigPath = msgPath & ".sig"

    # Run ssh-keygen to sign the message
    let cmd = "ssh-keygen -Y sign -f " & quoteShell(keyPath) &
              " -n " & quoteShell(namespace) & " " & quoteShell(msgPath)

    let (output, exitCode) = execCmdEx(cmd)

    if exitCode != 0:
      raise newException(SshSignError,
        "ssh-keygen sign failed (exit code " & $exitCode & "): " & output)

    if not fileExists(sigPath):
      raise newException(SshSignError,
        "Signature file was not created: " & sigPath)

    # Read the signature
    result.signature = readFile(sigPath)

    if keepFiles:
      result.signatureFile = sigPath
    else:
      removeFile(sigPath)

  finally:
    if not keepFiles:
      try:
        removeFile(msgPath)
      except OSError:
        discard

proc signFile*(filePath: string,
               privateKeyPath: string,
               namespace: string = "file"): string =
  ## Signs a file using an SSH private key via ssh-keygen.
  ##
  ## Parameters:
  ##   - filePath: Path to the file to sign
  ##   - privateKeyPath: Path to the SSH private key file
  ##   - namespace: The namespace for the signature (default: "file")
  ##
  ## Returns:
  ##   The signature in SSH signature format
  ##
  ## Raises:
  ##   - SshSignError: If signing fails
  ##   - OSError: If file operations fail

  let keyPath = expandTilde(privateKeyPath)

  if not fileExists(keyPath):
    raise newException(SshSignError, "Private key file not found: " & keyPath)

  if not fileExists(filePath):
    raise newException(SshSignError, "File to sign not found: " & filePath)

  let sigPath = filePath & ".sig"

  # Run ssh-keygen to sign the file
  let cmd = "ssh-keygen -Y sign -f " & quoteShell(keyPath) &
            " -n " & quoteShell(namespace) & " " & quoteShell(filePath)

  let (output, exitCode) = execCmdEx(cmd)

  if exitCode != 0:
    raise newException(SshSignError,
      "ssh-keygen sign failed (exit code " & $exitCode & "): " & output)

  if not fileExists(sigPath):
    raise newException(SshSignError,
      "Signature file was not created: " & sigPath)

  # Read and return the signature
  result = readFile(sigPath)

  # Clean up the signature file
  try:
    removeFile(sigPath)
  except OSError:
    discard

proc verifyMessage*(message: string,
                    signature: string,
                    allowedSigners: string,
                    identity: string,
                    namespace: string = "file"): VerifyResult =
  ## Verifies a signed message using SSH signature verification.
  ##
  ## Parameters:
  ##   - message: The original message that was signed
  ##   - signature: The SSH signature to verify
  ##   - allowedSigners: Content of allowed_signers file (format: "identity key-type key-data")
  ##   - identity: The identity to verify against (e.g., "user@example.com")
  ##   - namespace: The namespace used for signing (default: "file")
  ##
  ## Returns:
  ##   A VerifyResult indicating whether the signature is valid

  # Create temporary files for message, signature, and allowed_signers
  let (msgFile, msgPath) = createTempFile("sshsign_msg_", ".txt")
  let (sigFile, sigPath) = createTempFile("sshsign_sig_", ".sig")
  let (allowedFile, allowedPath) = createTempFile("sshsign_allowed_", ".txt")

  try:
    msgFile.write(message)
    msgFile.close()

    sigFile.write(signature)
    sigFile.close()

    allowedFile.write(allowedSigners)
    allowedFile.close()

    # Run ssh-keygen to verify
    let cmd = "ssh-keygen -Y verify -f " & quoteShell(allowedPath) &
              " -I " & quoteShell(identity) &
              " -n " & quoteShell(namespace) &
              " -s " & quoteShell(sigPath) &
              " < " & quoteShell(msgPath)

    let (output, exitCode) = execCmdEx(cmd)

    result.valid = (exitCode == 0)
    result.message = output.strip()

  finally:
    try:
      removeFile(msgPath)
      removeFile(sigPath)
      removeFile(allowedPath)
    except OSError:
      discard

proc verifyFile*(filePath: string,
                 signaturePath: string,
                 allowedSigners: string,
                 identity: string,
                 namespace: string = "file"): VerifyResult =
  ## Verifies a signed file using SSH signature verification.
  ##
  ## Parameters:
  ##   - filePath: Path to the file that was signed
  ##   - signaturePath: Path to the signature file
  ##   - allowedSigners: Content of allowed_signers file
  ##   - identity: The identity to verify against
  ##   - namespace: The namespace used for signing (default: "file")
  ##
  ## Returns:
  ##   A VerifyResult indicating whether the signature is valid

  if not fileExists(filePath):
    raise newException(SshSignError, "File not found: " & filePath)

  if not fileExists(signaturePath):
    raise newException(SshSignError, "Signature file not found: " & signaturePath)

  let (allowedFile, allowedPath) = createTempFile("sshsign_allowed_", ".txt")

  try:
    allowedFile.write(allowedSigners)
    allowedFile.close()

    # Run ssh-keygen to verify
    let cmd = "ssh-keygen -Y verify -f " & quoteShell(allowedPath) &
              " -I " & quoteShell(identity) &
              " -n " & quoteShell(namespace) &
              " -s " & quoteShell(signaturePath) &
              " < " & quoteShell(filePath)

    let (output, exitCode) = execCmdEx(cmd)

    result.valid = (exitCode == 0)
    result.message = output.strip()

  finally:
    try:
      removeFile(allowedPath)
    except OSError:
      discard
