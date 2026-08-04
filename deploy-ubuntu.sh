#!/bin/bash

# TurboWall + Marmot + Nebula Deployment Script for Ubuntu 24.04 LTS
# Run this script as root: sudo ./deploy-ubuntu.sh

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

NEBULA_VERSION="v1.9.0"
MARMOT_VERSION="v0.8.12"
GO_VERSION="1.22.3"
NODE_IP="192.168.100.1/24" # Default Nebula Overlay IP
NODE_NAME="turbowall-node-1"

echo "========================================"
echo "Installing System Dependencies..."
echo "========================================"
apt-get update
apt-get install -y wget curl tar jq git build-essential ufw

echo "========================================"
echo "Installing Go (required for xcaddy)..."
echo "========================================"
if ! command -v go &> /dev/null; then
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz
    echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
fi
export PATH=$PATH:/usr/local/go/bin

echo "========================================"
echo "Installing Nebula (Overlay Network)..."
echo "========================================"
mkdir -p /etc/nebula
if [ ! -f /usr/local/bin/nebula ]; then
    wget -q https://github.com/slackhq/nebula/releases/download/${NEBULA_VERSION}/nebula-linux-amd64.tar.gz
    tar -xzf nebula-linux-amd64.tar.gz -C /usr/local/bin/ nebula nebula-cert
    rm nebula-linux-amd64.tar.gz
fi

# Generate a dummy CA if one doesn't exist (For demonstration purposes)
# In production, you should securely distribute certificates from a central CA.
if [ ! -f /etc/nebula/ca.crt ]; then
    echo "Generating Nebula CA and Node Certificates..."
    cd /etc/nebula
    nebula-cert ca -name "TurboWall Overlay"
    nebula-cert sign -name "${NODE_NAME}" -ip "${NODE_IP}"
fi

cat << 'EOF' > /etc/nebula/config.yml
pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key: /etc/nebula/host.key

static_host_map:
  # Add Lighthouse IP mappings here
  # "192.168.100.1": ["public.lighthouse.ip:4242"]

lighthouse:
  am_lighthouse: false
  # interval: 60
  # hosts:
  #   - "192.168.100.1"

listen:
  host: 0.0.0.0
  port: 4242

punchy:
  punch: true

tun:
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: icmp
      host: any
    # Marmot NATS communication
    - port: 4222
      proto: tcp
      host: any
EOF

# Create Nebula Systemd Service
cat << 'EOF' > /etc/systemd/system/nebula.service
[Unit]
Description=Nebula Overlay Network
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nebula -config /etc/nebula/config.yml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nebula
systemctl start nebula

echo "========================================"
echo "Installing Marmot (Distributed SQLite)..."
echo "========================================"
if [ ! -f /usr/local/bin/marmot ]; then
    wget -q https://github.com/maxpert/marmot/releases/download/${MARMOT_VERSION}/marmot-linux-amd64.tar.gz
    tar -xzf marmot-linux-amd64.tar.gz -C /usr/local/bin/ marmot
    rm marmot-linux-amd64.tar.gz
fi

mkdir -p /var/lib/turbowall

# Create Marmot Systemd Service
# NATS listens on the Nebula IP to ensure replication only happens securely over the overlay
cat << EOF > /etc/systemd/system/marmot.service
[Unit]
Description=Marmot SQLite Replicator
After=nebula.service

[Service]
Type=simple
Environment="NATS_ADDR=0.0.0.0:4222"
# Bind NATS clustering strictly to the Nebula interface (assuming overlay IP)
ExecStart=/usr/local/bin/marmot -db-path /var/lib/turbowall/turbowall.db -node-id ${NODE_NAME} -cluster-addr nats://0.0.0.0:4222
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl enable marmot
systemctl start marmot

echo "========================================"
echo "Building TurboWall (Caddy + Go)..."
echo "========================================"
export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

cd /opt
if [ ! -d "turbowall" ]; then
    git clone https://github.com/turbo-wall-app/turbowall.git
fi
cd turbowall

~/go/bin/xcaddy build --with turbowall-go=$(pwd)/src/standalone
mv caddy /usr/local/bin/turbowall-server

cat << 'EOF' > /etc/turbowall.caddyfile
:80 {
    custom_waf {
        db_path /var/lib/turbowall/turbowall.db
    }
    respond "TurboWall WAF is active!" 200
}
EOF

# Create TurboWall Systemd Service
cat << 'EOF' > /etc/systemd/system/turbowall.service
[Unit]
Description=TurboWall Standalone WAF
After=network.target marmot.service

[Service]
Type=simple
ExecStart=/usr/local/bin/turbowall-server run --config /etc/turbowall.caddyfile --adapter caddyfile
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl enable turbowall
systemctl start turbowall

echo "========================================"
echo "Deployment Complete!"
echo "========================================"
echo "Nebula overlay is running on nebula1 interface."
echo "Marmot is replicating /var/lib/turbowall/turbowall.db over Nebula (Port 4222)."
echo "TurboWall is running on port 80."
