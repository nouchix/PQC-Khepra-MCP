#!/bin/bash
# ==============================================================================
# KHEPRA-BASTION: The Invisibility Cloak
# ==============================================================================
# This script configures iptables to DROP all incoming traffic EXCEPT from
# the designated Proton VPN Gateway.
#
# USAGE: sudo ./bastion_wall.sh
# WARNING: Run this ONLY if you have access via the Bastion (or Console access).
#          Otherwise, you will lock yourself out.
# ==============================================================================

BASTION_IP="74.118.125.101"
KHEPRA_PORTS="22,443,45444" 

# 1. Verification
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root." 
   exit 1
fi

echo "[KHEPRA] Erecting the Bastion Wall..."
echo "[INFO] Whitelisted Gateway: $BASTION_IP"

# 2. Reset the Firewall (Flush)
# Note: We set default policies to ACCEPT first to avoid lockout during flush
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
echo " [OK] Existing rules flushed."

# 3. Apply the "Zero-Trust" Rules

# 3.1 Allow Loopback (Localhost)
iptables -A INPUT -i lo -j ACCEPT

# 3.2 Allow Established/Related Connections
# (Allows return traffic for outbound requests made by the server)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 3.3 === THE GOLDEN RULE ===
# Allow Ingress ONLY from the Bastion Gateway
iptables -A INPUT -s "$BASTION_IP" -p tcp -m multiport --dports "$KHEPRA_PORTS" -j ACCEPT
echo " [OK] Bastion Whitelist Applied ($BASTION_IP -> Ports $KHEPRA_PORTS)"

# 4. Drop Everything Else (The Black Hole)
iptables -P INPUT DROP
iptables -P FORWARD DROP
# We usually leave OUTPUT ACCEPT unless strictly restrictive
iptables -P OUTPUT ACCEPT

echo " [OK] Default Policy set to DROP (Invisibility Mode Active)."

# 5. Persistence (Debian/Ubuntu/CentOS agnostic attempt)
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
    echo " [OK] Rules saved via netfilter-persistent."
elif command -v service &> /dev/null; then
    service iptables save 2>/dev/null || echo " [WARN] Could not auto-save rules. Install iptables-persistent."
else
    echo " [WARN] Please manually save your iptables rules."
fi

echo "[SUCCESS] Khepra Server is now invisible to the world."
