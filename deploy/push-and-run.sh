#!/usr/bin/env bash
# Run from D:\REPO\sbomix after SSH access to 76.13.101.31 is established.
# Usage: bash deploy/push-and-run.sh
set -euo pipefail

VPS="root@76.13.101.31"
SSH_KEY="$HOME/.ssh/id_ed25519"
JUMP="-J root@76.13.101.39"
SSH="ssh -i $SSH_KEY $JUMP -o StrictHostKeyChecking=no"
SCP="scp -i $SSH_KEY -o ProxyJump=root@76.13.101.39 -o StrictHostKeyChecking=no"

echo "==> Uploading files to VPS..."
$SCP deploy/sbomix-nginx.conf  $VPS:/tmp/sbomix-nginx.conf
$SCP deploy/vps-setup.sh       $VPS:/tmp/vps-setup.sh
$SCP deploy/vps.env            $VPS:/tmp/sbomix.env

echo "==> Running setup script on VPS..."
$SSH $VPS "bash /tmp/vps-setup.sh"

echo ""
echo "==> Check status:"
echo "  $SSH $VPS 'docker compose -f /opt/sbomix/docker-compose.yml ps'"
echo "  curl https://api.sbomix.com/health"
