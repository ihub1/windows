#!/bin/bash
#
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2020 Nyr. Released under the MIT License.


# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OS
# <span class="math-inline">os\_version variables aren't always in use, but are kept here for convenience
<2\>if grep \-qs "ubuntu" /etc/os\-release; then
os\="ubuntu"
os\_version\=</span>(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=<span class="math-inline">\(grep \-oE '\[0\-9\]\+' /etc/debian\_version \| head \-1\)
elif \[\[ \-e /etc/almalinux\-release \|\| \-e /etc/rocky\-release \|\| \-e /etc/centos\-release \]\]; then
os\="centos"
os\_version\=</span>(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
	echo "Ubuntu 22.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" ]]; then
	if grep -q '/sid' /etc/debian_version; then
		echo "Debian Testing and Debian Unstable are unsupported by this installer."
		exit
	fi
	if [[ "$os_version" -lt 11 ]]; then
		echo "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
		exit
	fi
fi

if [[ "$os" == "centos" && "<span class="math-inline">os\_version" \-lt</5\> 9 \]\]; then
os\_name\=</span>(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
	echo "$os_name 9 or higher is required to use this installer.
This version of $os_name is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

# Detect if BoringTun (userspace WireGuard) needs to be used
if ! systemd-detect-virt -cq; then
	# Not running inside a container
	use_boringtun="0"
elif grep -q '^wireguard ' /proc/modules; then
	# Running inside a container, but the wireguard kernel module is available
	use_boringtun="0"
else
	# Running inside a container and the wireguard kernel module is not available
	use_boringtun="1"
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ "<span class="math-inline">use\_boringtun" \-eq 1 \]\]; then
if \[ "</span>(uname -m)" != "x86_64" ]; then
		echo "In containerized systems without the wireguard kernel module, this installer
supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
		exit
	fi
	# TUN device is required to use BoringTun
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
		exit
	fi
fi

new_client_dns () {
	echo "Select a DNS server for the client:"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "<span class="math-inline">dns" \=\~ ^\[1\-6\]</span> ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
		# DNS
	case "<span class="math-inline">dns" in
1\|""\)
\# Locate the proper resolv\.conf
\# Needed for systems running systemd\-resolved
if grep</0\> '^nameserver' "/etc/resolv\.conf" \| grep \-qv '127\.0\.0\.53' ; then
resolv\_conf\="/etc/resolv\.conf"
else
resolv\_conf\="/run/systemd/resolve/resolv\.conf"
fi
\# Extract nameservers and provide them in the required format
dns\=</span>(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
		;;
		2)
			dns="8.8.8.8, 8.8.4.4"
		;;
		3)
			dns="1.1.1.1, 1.0.0.1"
		;;
		4)
			dns="208.67.222.222, 208.67.220.220"
		;;
		5)
			dns="9.9.9.9, 149.112.112.112"
		;;
		6)
			dns="94.140.14.14, 94.140.15.15"
		;;
	esac
}

new_client_setup () {
	# Given a list of the assigned internal IPv4 addresses, obtain the lowest still
	# available octet. Important to start looking at 2, because 1 is our gateway.
	octet=2
	while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^<span class="math-inline">octet</span>"; do
		(( octet++ ))
	done
	# Don't break the WireGuard configuration in case the address space is full
	if [[ "<span class="math-inline">octet" \-eq 255 \]\]; then</2\>
echo "253 clients are already configured\. The WireGuard internal subnet is full\!"
exit
<2\>fi
key\=</span>(wg genkey)
	psk=$(wg genpsk)
	# Configure client in the server
	cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = 10.7.0.<span class="math-inline">octet/32</span>(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER <span class="math-inline">client
EOF
\# Create client configuration
cat << EOF</2\> \> \~/"</span>client".conf
[Interface]
Address = 10.7.0.<span class="math-inline">octet/24</span>(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = <span class="math-inline">\(grep '^\# ENDPOINT' /etc/wireguard/wg0\.conf \| cut \-d " " \-f 3\)\:</span>(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
}

# --- Helper Functions for Management ---

add_client() {
  echo
  echo "Provide a name for the client:"
  read -p "Name: " unsanitized_client
  # Allow a limited length and set of characters to avoid conflicts
  client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
  while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER <span class="math-inline">client</span>" /etc/wireguard/wg0.conf; do
    echo "<span class="math-inline">client\: invalid name\."
read \-p "Name\: " unsanitized\_client
client\=</span>(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
  done
  echo
  new_client_dns
  new_client_setup
  # Append new client configuration to the WireGuard interface
  wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER <span class="math-inline">client/p" /etc/wireguard/wg0\.conf\)
echo
qrencode \-t</2\> ANSI256UTF8 < \~/"</span>client.conf"
  echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
  echo
  echo "$client added. Configuration available in:" ~/"<span class="math-inline">client\.conf"</0\>
\}
remove\_client\(\) \{
<2\>number\_of\_clients\=</span>(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
  if [[ "$number_of_clients" = 0 ]]; then
    echo
    echo "There are no existing clients!"
    return 1
  fi
  echo
  echo "Select the client to remove:"
  grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
  read -p "Client: " client_number
  until [[ "<span class="math-inline">client\_number" \=\~ ^\[0\-9\]\+</span> && "$client_number" -le "$number_of_clients" ]]; do
    echo "<span class="math-inline">client\_number\: invalid selection\."
read \-p "Client\: " client\_number
done
client\=</span>(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
  echo
  read -p "Confirm $client removal? [y/N]: " remove
  until [[ "<span class="math-inline">remove" \=\~ ^\[yYnN\]\*</span> ]]; do
    echo "$remove: invalid selection."
    read -p "Confirm $client removal? [y/N]: " remove
  done
  if [[ "<span class="math-inline">remove" \=\~ ^\[yY\]</span> ]]; then
    # The following is the right way to avoid disrupting other active connections:
    # Remove from the live interface
    wg set wg0 peer "$(sed -n "/^# BEGIN_PEER <span class="math-inline">client</span>/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
    # Remove from the configuration file
    sed -i "/^# BEGIN_PEER <span class="math-inline">client</span>/,/^# END_PEER <span class="math-inline">client</span>/d" /etc/wireguard/wg0.conf
    echo
    echo "$client removed!"
  else
    echo
    echo "$client removal aborted!"
  fi
}

list_clients() {
  echo "List of configured clients:"
  grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
}

show_status() {
  echo "WireGuard Status:"
  wg show wg0
}

update_config() {
  # ... (Implementation to update server configuration) ...
  echo "update_config function not yet implemented."
}

# --- End of Helper Functions ---


if [[ ! -e /etc/wireguard/wg0.conf ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Welcome to this WireGuard road warrior installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ <span class="math-inline">\(ip \-4 addr \| grep inet \| grep \-vEc '127\(\\\.\[0\-9\]\{1,3\}\)\{3\}'\) \-eq 1 \]\]; then
ip\=</span>(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "<span class="math-inline">ip\_number" \=\~ ^\[0\-9\]\+</span> && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "<span class="math-inline">ip\_number" \]\] && ip\_number\="1"
ip\=</span>(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "<span class="math-inline">ip" \| grep \-qE '^\(10\\\.\|172\\\.1\[6789\]\\\.\|172\\\.2\[0\-9\]\\\.\|172\\\.3\[01\]\\\.\|192\\\.168\)'; then
echo
echo "This server is behind NAT\. What is the public IPv4 address or hostname?"
\# Get public IP and sanitize with grep
get\_public\_ip\=</span>(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}<span class="math-inline">' <<< "</span>(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ <span class="math-inline">\(ip \-6 addr \| grep \-c 'inet6 \[23\]'\) \-eq 1 \]\]; then
ip6\=</span>(ip -
