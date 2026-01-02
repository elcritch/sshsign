version = "0.1.0"
author = "Jaremy Creechley"
description = "ssh signing library"
license = "MIT"
srcDir = "."

requires "nim >= 2.0.2"

feature "cbor":
  requires "cborious"

task test, "Run the test suite":
  exec "nim c -r tests/test_sshsign.nim"

