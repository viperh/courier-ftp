# TLS fixture CA — TEST-ONLY

> **WARNING: TEST-ONLY key material, committed on purpose.** `ca.key` is public; this
> CA protects nothing. Never add `ca.pem` to any trust store outside the courier-ftp
> e2e tests. Secret scanners skip this directory.

`ca.pem` / `ca.key`: a self-signed RSA-2048 CA (`CN=courier-ftp-e2e TEST-ONLY CA`,
20 years). The ftpd image signs its server certificates with it at every daemon start
(`FTPD_CERT=ca-signed|expired|wrong-host`; `self-signed` uses its own key).
`tests/fixtures/ftpd/tls/` holds an identical copy (the image's build context is
`tests/fixtures/ftpd/`); `tests/fixtures.rs` checks that both copies match.

Regenerate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 7300 \
    -subj "/CN=courier-ftp-e2e TEST-ONLY CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
cp ca.pem ca.key ../ftpd/tls/
```
