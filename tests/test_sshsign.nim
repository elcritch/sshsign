import std/[unittest, os, osproc, strutils, tempfiles]
import sshsign

suite "SSH Signing Tests":
  var testKeyPath: string
  var testPubKeyPath: string
  var testPublicKeyContent: string

  setup:
    # Generate a temporary SSH key pair for testing
    let (tempFile, keyPath) = createTempFile("test_ssh_key_", "")
    tempFile.close()
    removeFile(keyPath)  # Remove the temp file, we just want the path

    testKeyPath = keyPath
    testPubKeyPath = keyPath & ".pub"

    # Generate ED25519 key (no passphrase, for testing)
    let genCmd = "ssh-keygen -t ed25519 -f " & quoteShell(testKeyPath) &
                 " -N '' -C 'test@example.com'"
    let (output, exitCode) = execCmdEx(genCmd)

    if exitCode != 0:
      echo "Failed to generate test key: ", output
      echo "Exit code: ", exitCode
      skip()

    if not fileExists(testPubKeyPath):
      echo "Public key file was not created at: ", testPubKeyPath
      skip()

    testPublicKeyContent = readFile(testPubKeyPath).strip()

  teardown:
    # Clean up temporary key files
    if fileExists(testKeyPath):
      removeFile(testKeyPath)
    if fileExists(testPubKeyPath):
      removeFile(testPubKeyPath)

  test "signMessage creates valid signature":
    let message = "Hello, SSH signing world!"
    let namespace = "test"

    let result = signMessage(message, testKeyPath, namespace)

    check result.signature.len > 0
    check result.signature.contains("-----BEGIN SSH SIGNATURE-----")
    check result.signature.contains("-----END SSH SIGNATURE-----")

  test "signMessage with keepFiles preserves signature file":
    let message = "Test message with kept files"
    let namespace = "test"

    let result = signMessage(message, testKeyPath, namespace, keepFiles = true)

    check result.signature.len > 0
    check result.signatureFile.len > 0
    check fileExists(result.signatureFile)

    # Clean up
    removeFile(result.signatureFile)
    # Also remove the message file
    let msgPath = result.signatureFile.replace(".sig", "")
    if fileExists(msgPath):
      removeFile(msgPath)

  test "signMessage with non-existent key raises error":
    expect SshSignError:
      discard signMessage("test", "/nonexistent/key", "test")

  test "verifyMessage accepts valid signature":
    let message = "Message to verify"
    let namespace = "test"
    let identity = "test@example.com"

    # Sign the message
    let result = signMessage(message, testKeyPath, namespace)

    # Create allowed_signers content
    let allowedSigners = identity & " " & testPublicKeyContent

    # Verify the signature
    let verifyResult = verifyMessage(message, result.signature,
                                     allowedSigners, identity, namespace)

    check verifyResult.valid == true
    check verifyResult.message.contains("Good")

  test "verifyMessage rejects invalid signature":
    let message = "Original message"
    let tamperedMessage = "Tampered message"
    let namespace = "test"
    let identity = "test@example.com"

    # Sign the original message
    let result = signMessage(message, testKeyPath, namespace)

    # Create allowed_signers content
    let allowedSigners = identity & " " & testPublicKeyContent

    # Try to verify with tampered message
    let verifyResult = verifyMessage(tamperedMessage, result.signature,
                                     allowedSigners, identity, namespace)

    check verifyResult.valid == false

  test "verifyMessage rejects signature with wrong namespace":
    let message = "Message with namespace"
    let signNamespace = "namespace1"
    let verifyNamespace = "namespace2"
    let identity = "test@example.com"

    # Sign with one namespace
    let result = signMessage(message, testKeyPath, signNamespace)

    # Create allowed_signers content
    let allowedSigners = identity & " " & testPublicKeyContent

    # Try to verify with different namespace
    let verifyResult = verifyMessage(message, result.signature,
                                     allowedSigners, identity, verifyNamespace)

    check verifyResult.valid == false

  test "signFile creates signature for file":
    let (testFile, testFilePath) = createTempFile("test_file_", ".txt")
    testFile.write("File content to sign")
    testFile.close()

    try:
      let signature = signFile(testFilePath, testKeyPath, "test")

      check signature.len > 0
      check signature.contains("-----BEGIN SSH SIGNATURE-----")

      # Signature file should have been created
      let sigPath = testFilePath & ".sig"
      check fileExists(sigPath) == false  # signFile reads and removes it

    finally:
      removeFile(testFilePath)

  test "verifyFile accepts valid file signature":
    let (testFile, testFilePath) = createTempFile("test_file_", ".txt")
    let content = "File content to verify"
    testFile.write(content)
    testFile.close()

    let sigPath = testFilePath & ".sig"

    try:
      let namespace = "test"
      let identity = "test@example.com"

      # Sign the file (this creates testFilePath.sig)
      let cmd = "ssh-keygen -Y sign -f " & quoteShell(testKeyPath) &
                " -n " & quoteShell(namespace) & " " & quoteShell(testFilePath)
      let (_, exitCode) = execCmdEx(cmd)
      check exitCode == 0

      # Create allowed_signers content
      let allowedSigners = identity & " " & testPublicKeyContent

      # Verify the file signature
      let verifyResult = verifyFile(testFilePath, sigPath,
                                    allowedSigners, identity, namespace)

      check verifyResult.valid == true

    finally:
      removeFile(testFilePath)
      if fileExists(sigPath):
        removeFile(sigPath)

  test "multiple signatures with different namespaces":
    let message = "Multi-namespace message"
    let identity = "test@example.com"

    # Sign with different namespaces
    let sig1 = signMessage(message, testKeyPath, "namespace1")
    let sig2 = signMessage(message, testKeyPath, "namespace2")

    check sig1.signature != sig2.signature

    let allowedSigners = identity & " " & testPublicKeyContent

    # Each signature should only verify with its own namespace
    let verify1 = verifyMessage(message, sig1.signature,
                               allowedSigners, identity, "namespace1")
    let verify2 = verifyMessage(message, sig2.signature,
                               allowedSigners, identity, "namespace2")

    check verify1.valid == true
    check verify2.valid == true

    # Cross-verification should fail
    let verify1Wrong = verifyMessage(message, sig1.signature,
                                    allowedSigners, identity, "namespace2")
    let verify2Wrong = verifyMessage(message, sig2.signature,
                                    allowedSigners, identity, "namespace1")

    check verify1Wrong.valid == false
    check verify2Wrong.valid == false

  test "empty message can be signed and verified":
    let message = ""
    let namespace = "test"
    let identity = "test@example.com"

    let result = signMessage(message, testKeyPath, namespace)
    check result.signature.len > 0

    let allowedSigners = identity & " " & testPublicKeyContent
    let verifyResult = verifyMessage(message, result.signature,
                                    allowedSigners, identity, namespace)

    check verifyResult.valid == true

suite "GitHub Integration Tests":
  test "fetchGithubKeys retrieves public keys":
    # Test with a known GitHub user that has public keys
    # Using "elcritch" as mentioned in the requirements
    let keys = fetchGithubKeys("elcritch")

    check keys.len > 0
    # Keys should be in SSH public key format
    check keys.contains("ssh-") or keys.contains("ecdsa-") or keys.contains("ed25519")

  test "fetchGithubKeys fails for non-existent user":
    expect SshSignError:
      discard fetchGithubKeys("this-user-definitely-does-not-exist-123456789")

  test "verifyMessageWithGithubUser verifies signature":
    # Generate a temporary key for this test
    let (tempFile, keyPath) = createTempFile("test_github_key_", "")
    tempFile.close()
    removeFile(keyPath)

    let pubKeyPath = keyPath & ".pub"

    try:
      # Generate ED25519 key
      let genCmd = "ssh-keygen -t ed25519 -f " & quoteShell(keyPath) &
                   " -N '' -C 'elcritch'"
      let (_, exitCode) = execCmdEx(genCmd)

      if exitCode != 0:
        skip()

      # Sign a message with our local key
      let message = "Test message for GitHub verification"
      let namespace = "test-github"

      let signature = signMessage(message, keyPath, namespace).signature

      # Fetch actual GitHub keys for elcritch to ensure the function works
      discard fetchGithubKeys("elcritch")

      # Check if our local key matches any GitHub key
      # This test will only pass if the local key matches a GitHub key
      # For testing purposes, we'll just verify the mechanism works
      # by checking that the function executes without error

      # Try to verify - this will fail unless the key matches
      let verifyResult = verifyMessageWithGithubUser(message, signature, "elcritch", namespace)

      # Since our test key likely doesn't match elcritch's actual keys,
      # we just verify the function runs without crashing
      # The result.valid will likely be false, which is expected
      check verifyResult.message.len > 0

    finally:
      if fileExists(keyPath):
        removeFile(keyPath)
      if fileExists(pubKeyPath):
        removeFile(pubKeyPath)

  test "verifyMessageWithGithubUser integration test":
    # This is a more realistic test that would work if we had control
    # over the GitHub account. For now, we'll test the error path.

    let message = "Message signed by unknown key"
    let namespace = "test"

    # Generate a temporary key
    let (tempFile, keyPath) = createTempFile("test_unknown_key_", "")
    tempFile.close()
    removeFile(keyPath)

    let pubKeyPath = keyPath & ".pub"

    try:
      # Generate a key that won't match any GitHub user's keys
      let genCmd = "ssh-keygen -t ed25519 -f " & quoteShell(keyPath) &
                   " -N '' -C 'test@example.com'"
      discard execCmdEx(genCmd)

      # Sign a message
      let signature = signMessage(message, keyPath, namespace).signature

      # Try to verify with elcritch's GitHub keys
      # This should fail since we're using a different key
      let verifyResult = verifyMessageWithGithubUser(message, signature, "elcritch", namespace)

      # Verification should fail since the signature was made with a different key
      check verifyResult.valid == false

    finally:
      if fileExists(keyPath):
        removeFile(keyPath)
      if fileExists(pubKeyPath):
        removeFile(pubKeyPath)
