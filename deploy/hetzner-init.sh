#!/usr/bin/env bash
#
# deploy/hetzner-init.sh — cloud-init bootstrap for the Hetzner CX22 host.
#
# This script is NOT executed automatically by anything in this repo. It's
# the file an operator pastes (or links via cloud-config user_data) into
# Hetzner Cloud's "User data" field when provisioning the VM.
#
# Idempotent. Safe to re-run.
#
# Pre-conditions:
#   - Hetzner CX22 in fsn1 with public IPv4 + IPv6
#   - 50 GB Hetzner Cloud Volume attached at /dev/disk/by-id/scsi-0HC_Volume_<id>
#   - DNS A + AAAA for relay.ochk.io pointing at the VM's public IP
#
# Post-conditions:
#   - docker + docker compose installed
#   - this repo cloned to /opt/oc-relay-infra
#   - compose stack up (strfry + caddy)
#   - Caddy has acquired a Let's Encrypt cert for relay.ochk.io
#   - UFW configured: allow 22, 80, 443; deny everything else
#   - Strfry data volume mounted at /var/lib/strfry-data, bind-mounted into
#     the container
#
# Operational notes:
#   - To rotate strfry to a new image: `cd /opt/oc-relay-infra && git pull && docker compose pull && docker compose up -d`
#   - To run the cold-start backfill: `docker compose exec strfry /data/strfry/sync/backfill.sh`
#   - To take a snapshot: `docker compose exec strfry strfry export > /var/backups/strfry-$(date +%F).jsonl`

set -euxo pipefail

# 1. base packages
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y install ca-certificates curl gnupg ufw fail2ban htop git

# 2. docker
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release; echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

# 3. firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# 4. fail2ban — sshd jail by default; relay traffic is unauthenticated by design,
# no jail there.
systemctl enable --now fail2ban

# 5. data volume
DATA_DEV=$(ls /dev/disk/by-id/scsi-0HC_Volume_* | head -1)
if [ -z "${DATA_DEV}" ]; then
    echo "no Hetzner Volume attached; aborting" >&2
    exit 1
fi
if ! blkid "${DATA_DEV}" >/dev/null 2>&1; then
    mkfs.ext4 -L strfry-data "${DATA_DEV}"
fi
mkdir -p /var/lib/strfry-data
echo "${DATA_DEV} /var/lib/strfry-data ext4 defaults,nofail 0 2" >> /etc/fstab
mount -a

# 6. clone repo
if [ ! -d /opt/oc-relay-infra ]; then
    git clone https://github.com/orangecheck/oc-relay-infra.git /opt/oc-relay-infra
else
    git -C /opt/oc-relay-infra pull --ff-only
fi

# 7. tell compose to bind-mount the data volume
sed -i 's|strfry-data:/data/strfry/db|/var/lib/strfry-data:/data/strfry/db|' \
    /opt/oc-relay-infra/compose.yaml

# 8. up
cd /opt/oc-relay-infra
docker compose pull
docker compose up -d

# 9. cron — quarterly negentropy backfill, weekly export
cat > /etc/cron.d/oc-relay-infra <<'CRON'
# negentropy sync from public relays (quarterly)
17 3 1 */3 * root cd /opt/oc-relay-infra && docker compose exec -T strfry /data/strfry/sync/backfill.sh >> /var/log/oc-relay-backfill.log 2>&1

# weekly export to /var/backups (rotated by logrotate)
23 4 * * 0 root cd /opt/oc-relay-infra && docker compose exec -T strfry strfry export > /var/backups/strfry-$(date +%F).jsonl
CRON

# 10. hint to operator
echo
echo "===================================================================="
echo "relay.ochk.io is up at https://relay.ochk.io and wss://relay.ochk.io"
echo "Run cold-start backfill manually:"
echo "  cd /opt/oc-relay-infra && docker compose exec strfry /data/strfry/sync/backfill.sh"
echo "===================================================================="
