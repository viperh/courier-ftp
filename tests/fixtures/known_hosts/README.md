# known_hosts fixtures (T21) — TEST-ONLY public keys

Copied from sverb (`crates/sverb-core/src/known_hosts/testdata`, generated with OpenSSH
10.5p1's `ssh-keygen`, never from a real `~/.ssh/known_hosts`):

- `ed25519.pub`, `ecdsa.pub`, `rsa.pub`: `ssh-keygen -t <type> -N ''` public keys;
- `hashed_example_com.txt`: `example.com <ed25519 key>` hashed with `ssh-keygen -H`;
- `known_hosts.txt`: the parser fixture (markers, hashed line, certificate, `sk-*` keys,
  one malformed line).

Written for courier-ftp:

- `matching.txt`: host patterns (plain, hashed, `[host]:port`, wildcard, `!negation`);
  the test lists what `ssh-keygen -F <host> -f matching.txt` finds for each host;
- `fingerprints.txt`: `ssh-keygen -l -f <key>.pub` (SHA-256 lines, recorded by sverb) and
  `ssh-keygen -l -E md5 -f <key>.pub` (MD5 lines: computed with Python `hashlib` over the
  decoded blob, the same definition; no `ssh-keygen` was available when they were added).

Also the seed corpus of the `known_hosts_parse` fuzz target (`fuzz/seed-corpus.sh`).
