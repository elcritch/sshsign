
task test, "Run the test suite":
  exec "nim c -d:ssl -r tests/test_sshsign.nim"

