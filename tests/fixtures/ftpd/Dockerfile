# FTP/FTPS server image for the courier-ftp e2e suite (T76): vsftpd, proftpd (+mod_tls)
# and pure-ftpd in one image. The server and its configuration are chosen at container
# start with `FTPD_PROFILE=<name>` (profiles/<name>.conf); the certificate variant with
# `FTPD_CERT=ca-signed|self-signed|expired|wrong-host`; the PASV address with
# `FTPD_PASV_ADDRESS` (default: the container IP). `--list` prints the profiles,
# `--check` validates one without serving.
#
# Control port 21 (implicit TLS: 990), passive ports 30000-30019. Users `test`/`test`
# and `canary`/`CANARY-PW-e2e-7f3a`, chrooted to their homes (~/upload writable,
# ~/fixtures = FIXTURE_TREE); anonymous root /srv/anon (read-only, readme.txt).
#
# Build: docker build -t courier-ftp-e2e-ftpd:local tests/fixtures/ftpd
# tls/ is the TEST-ONLY CA (a copy of tests/fixtures/tls/). Never trust it anywhere.
FROM public.ecr.aws/docker/library/debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      vsftpd proftpd-core proftpd-mod-crypto pure-ftpd openssl python3 procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/courier-ftpd/tls /var/run/vsftpd/empty

COPY base/ /etc/courier-ftpd/base/
COPY profiles/ /etc/courier-ftpd/profiles/
COPY tls/ca.pem tls/ca.key /etc/courier-ftpd/ca/
COPY bin/ /usr/local/bin/
COPY entrypoint.sh /usr/local/bin/courier-ftpd-entrypoint

# Homes are root-owned (chroot-safe for every server); only ~/upload is writable.
RUN set -eu; \
    chmod 0755 /usr/local/bin/*; \
    chmod 0600 /etc/courier-ftpd/ca/ca.key; \
    for spec in test:test canary:CANARY-PW-e2e-7f3a; do \
      user="${spec%%:*}"; pass="${spec#*:}"; \
      useradd --create-home --shell /bin/bash "$user"; \
      echo "$user:$pass" | chpasswd; \
      chown root:root "/home/$user"; chmod 0755 "/home/$user"; \
      install -d -m 0755 -o "$user" -g "$user" "/home/$user/upload"; \
      make-fixture-tree "/home/$user/fixtures"; \
      chown -R -h "$user:$user" "/home/$user/fixtures"; \
    done; \
    install -d -m 0555 /srv/anon; \
    printf 'courier-ftp e2e anonymous area (read-only)\n' > /srv/anon/readme.txt; \
    chmod 0444 /srv/anon/readme.txt; \
    sed -i 's/^\(root\|test\|canary\)$/# &/' /etc/ftpusers 2>/dev/null || true

ENTRYPOINT ["/usr/local/bin/courier-ftpd-entrypoint"]
