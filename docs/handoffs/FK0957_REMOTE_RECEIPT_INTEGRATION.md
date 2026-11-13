# FK0957 remote cleanup receipt integration status

The latest Left cleanup contract reviewed here is commit
`2474ebba421f14ce7e1d63cb32816310aefc9adb` (parent
`8da668970f58c2ad458c171e046b7cfa3618cd3b`). Its protocol validator and
adversarial tests are integrated as the starting contract for remote receipts.
The contract binds operation/authorization/manifest/target identity, a
challenge nonce, receipt identity, and the complete PID/start-time/executable/
argv/cwd tuple. Only exact non-running terminal states permit restoration.

The implementation is not complete yet: the production endpoint still does
not write the receipt lifecycle or implement the read-only status command.
Until that remote writer/query exists and the RGB orchestrator invokes it after
SSH loss, cleanup after a lost connection remains `REMOTE_STATE_UNKNOWN` and
restoration must be withheld. In particular, SSH exit code 255 never proves
remote exit, even when stdout contains a refusal record.

The integrated contract test module passed 14 offline tests. No SSH, service,
bridge, USB, JTAG, or hardware action was performed.
