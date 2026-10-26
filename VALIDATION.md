# Validation

Built on Linux with GCC 14.2, Qt 6.8.2 and CMake 3.31.6. No compiler warnings with `-Wall -Wextra -Wpedantic`.

`--self-test` checks profile validation, port ranges, option injection rejection, profile serialization, plaintext secret exclusion, reverse mapping, IPv6, known_hosts paths with spaces, SSH options, askpass IPC and invalid token rejection. On Linux it also checks reconnect and shutdown against a deterministic SSH process stand-in. On Windows it additionally checks a DPAPI round trip.

A local test passing does not verify a real SSH server. Windows OpenSSH, DPAPI, server policy and firewall settings need Windows/server testing. The Windows Actions workflow runs the build and self-test.
