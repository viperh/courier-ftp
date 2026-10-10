# HTTP CONNECT (squid) and SOCKS 4/5 (dante) proxy image for the courier-ftp e2e suite
# (T76). The proxy is chosen at container start with `PROXY_PROFILE=<name>`
# (profiles/<name>.conf): http, http-auth (squid :3128), socks4, socks5, socks5-auth
# (dante :1080). Credentials of the *-auth profiles: proxyuser / proxypass (TEST-ONLY).
# `--list` prints the profiles, `--check` validates one (`squid -k parse` / `danted -V`).
FROM public.ecr.aws/docker/library/debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      squid dante-server openssl \
 && rm -rf /var/lib/apt/lists/*

COPY profiles/ /etc/courier-proxy/profiles/
COPY entrypoint.sh /usr/local/bin/courier-proxy-entrypoint

# proxyuser/proxypass: a squid basic-auth entry and a system user for dante's
# `username` method.
RUN set -eu; \
    chmod 0755 /usr/local/bin/courier-proxy-entrypoint; \
    printf 'proxyuser:%s\n' "$(openssl passwd -apr1 proxypass)" > /etc/squid/courier-passwd; \
    chmod 0644 /etc/squid/courier-passwd; \
    useradd --no-create-home --shell /usr/sbin/nologin proxyuser; \
    echo 'proxyuser:proxypass' | chpasswd

ENTRYPOINT ["/usr/local/bin/courier-proxy-entrypoint"]
