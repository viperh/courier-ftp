# Proxy e2e fixture (T76)

squid (HTTP CONNECT, :3128) and dante (SOCKS 4/5, :1080) in one image; the profile is
picked with `PROXY_PROFILE` (`profiles/<name>.conf`, see `courier_ftp_e2e::ProxyProfile`):
`http`, `http-auth` (basic auth), `socks4`, `socks5`, `socks5-auth` (username method).
The credentials `proxyuser` / `proxypass` are TEST-ONLY. CONNECT is allowed to ports 21,
22, 990 and 30000–30019. `--list` / `--check` as in the other fixture images.
