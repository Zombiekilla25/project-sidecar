# FK0957 native runtime requalification

Scope is offline native library provenance and software tests only. No FTDI
context, USB enumeration, bridge operation, or hardware access was performed.

The previous libc pin referred to `/usr/lib/x86_64-linux-gnu/libc.so.6`,
SHA256 `3a15d66867d83762c7f2f1e37359cb8f6c5743edb369c65285cb0b1c4f7498bf`,
build ID `a4a7992a8e66555c8141ab2a08a8465ff6e0ea65`. The actual object is at
the same path, SHA256
`755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a`, build
ID `8cebda42d140fc2b09639f8b13a5d5f2e617ef09`.

This is a legitimate Ubuntu package update, not a wrong-path load: apt history
records unattended-upgrade from `2.39-0ubuntu8.9` to `2.39-0ubuntu8.12`; both
Noble updates and security InRelease signatures verify under the Ubuntu archive
keyring; the local Packages index matches its signed Release hash; `dpkg -V`
passes; and package ownership/version match. The exact `.deb` is no longer
cached, so its archive bytes could not be independently rehashed. The signed
Packages index records archive SHA256
`d821b41fc59cb4978ecd53bc83e5c964ac15d305c8d2ac4c8a35aebe55010fb9`.

Right's independent requalification commit is
`6e67c4496a0e9d4c82f6a5601e50fcd1c7787d67`. I reproduced its 173 FK0957
suite run from a disposable copy of production baseline
`3226bfc1474d6afa873fce7327ded6dac548baae`, changing only the libc pin in the
copy. Approved library FDs, hashes, loaded mappings, build IDs and required
libftdi/libusb symbols matched. Loader override variables were refused. No
libftdi context or USB functions were called. The integrated WIP pin update
changes only libc SHA/build ID; the libcap, libudev, libusb, and libftdi pins
remain unchanged.

The dynamic loader itself was separately inventoried at
`/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`, SHA256
`5fc0940888e9d2e1a00e66d6b1a559c36364ee867683652e1074fa576952cc3f`, build
ID `231ab65dd867a89dce29cb958fd5ca50abb1aa34`. The static launcher source now
checks hashes and ELF build IDs for the approved Python executable, dynamic
loader, libc, libftdi, and libusb before `execve` starts Python. It opens each
fixed absolute path with `O_NOFOLLOW`, requires a root-owned singly-linked
regular file with safe mode, and rechecks file identity after hashing. Wrong
hash and wrong build-ID launchers refuse before Python in offline regressions.
The launcher and bootstrap have not been installed at an administrator-owned
path, so the source-level prestart check is not yet enforced by a deployed
production entrypoint.

Machine-readable provenance and test results are in
[`fk0957-native-runtime-pin-qualification.json`](../../results/fk0957-native-runtime-pin-qualification.json).
