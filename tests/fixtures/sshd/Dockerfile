# OpenSSH (SFTP) server image for the courier-ftp e2e suite (T76).
#
# One image, many scenarios: the sshd profile is chosen at container start with
# `SSHD_PROFILE=<name>` (profiles/<name>.conf). `--list` prints the profiles, `--check`
# validates one without serving. Host keys are generated per container at first start.
#
# Build: docker build -t courier-ftp-e2e-sshd:local tests/fixtures/sshd
# The harness (crates/courier-ftp-e2e) builds it on demand, tagged with a hash of this
# directory, unless COURIER_E2E_SSHD_IMAGE names a prebuilt image (CI).
#
# Everything under keys/ is TEST-ONLY key material. Never trust it anywhere.

# The keyboard-interactive OTP module (pam/pam_courier_otp.c).
FROM public.ecr.aws/docker/library/debian:bookworm-slim AS pam
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev libpam0g-dev \
 && rm -rf /var/lib/apt/lists/*
COPY pam/pam_courier_otp.c /src/pam_courier_otp.c
RUN gcc -fPIC -shared -O2 -Wall -o /src/pam_courier_otp.so /src/pam_courier_otp.c -lpam

FROM public.ecr.aws/docker/library/debian:bookworm-slim

# Debian generates host keys during install; they are deleted (every container would
# share them) and generated per container by the entrypoint.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server openssh-client sshpass libpam-modules python3 procps \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_* \
 && mkdir -p /run/sshd /etc/ssh/courier

COPY --from=pam /src/pam_courier_otp.so /tmp/pam_courier_otp.so
COPY keys/authorized_keys /etc/ssh/courier/authorized_keys
COPY sshd_config /etc/ssh/sshd_config
COPY profiles/ /etc/ssh/courier/profiles/
COPY pam/sshd /etc/pam.d/sshd
COPY bin/ /usr/local/bin/
COPY entrypoint.sh /usr/local/bin/courier-sshd-entrypoint

# Users `test`/`test` and `canary`/`CANARY-PW-e2e-7f3a`, each with ~/upload (writable)
# and ~/fixtures (the FIXTURE_TREE), also inside the two chroots:
# /srv/chroot/home/<user> (chroot-sftp) and /srv/win/C:/Users/<user> (windows-like).
RUN set -eu; \
    chmod 0755 /usr/local/bin/*; \
    chmod 0644 /etc/ssh/sshd_config /etc/pam.d/sshd; \
    pamdir="$(dirname "$(find /usr/lib /lib -name pam_unix.so -path '*security*' | head -n1)")"; \
    install -m 0644 /tmp/pam_courier_otp.so "$pamdir/pam_courier_otp.so"; rm /tmp/pam_courier_otp.so; \
    for spec in test:test canary:CANARY-PW-e2e-7f3a; do \
      user="${spec%%:*}"; pass="${spec#*:}"; \
      useradd --create-home --shell /bin/bash "$user"; \
      echo "$user:$pass" | chpasswd; \
      install -d -m 0700 -o "$user" -g "$user" "/home/$user/.ssh"; \
      install -m 0600 -o "$user" -g "$user" /etc/ssh/courier/authorized_keys "/home/$user/.ssh/authorized_keys"; \
      for home in "/home/$user" "/srv/chroot/home/$user" "/srv/win/C:/Users/$user"; do \
        mkdir -p "$(dirname "$home")"; \
        install -d -m 0755 -o "$user" -g "$user" "$home" "$home/upload"; \
        make-fixture-tree "$home/fixtures"; \
        chown -R -h "$user:$user" "$home/fixtures"; \
      done; \
    done; \
    chown root:root /srv/chroot /srv/win; chmod 0755 /srv/chroot /srv/win

# No EXPOSE: containers are reached by their bridge IP (no published ports).
ENTRYPOINT ["/usr/local/bin/courier-sshd-entrypoint"]
