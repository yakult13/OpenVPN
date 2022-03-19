#!/bin/bash
# VPS Installer
# Script by Juan
# 
# Illegal selling and redistribution of this script is strictly prohibited
# Please respect author's Property
# Binigay sainyo ng libre, ipamahagi nyo rin ng libre.
#
#

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi
MyScriptName='FreenetCafe'
SSH_Port1='22'
SSH_Port2='225'
SSH_Banner='https://github.com/yakult13/parte/raw/main/cafe'
Dropbear_Port1='550'
Dropbear_Port2='555'
Stunnel_Port1='443'
Stunnel_Port2='444'
Proxy_Port1='8080'
Proxy_Port2='8000'
OpenVPN_Port1='110'
OpenVPN_Port2='112'
OpenVPN_Port3='1194'
OpenVPN_Port4='25888'
Privoxy_Port1='8686'
Privoxy_Port2='8787'
OvpnDownload_Port='1998'
MyVPS_Time='Asia/Manila'

function  Instupdate() {
export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 apt install fail2ban -y
 apt-get remove --purge ufw firewalld -y
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt -y
 apt-get install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid screenfetch -y
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl -y
 apt-get install shared-mime-info jq -y
 gem install lolcat
 apt-get autoremove -y
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" >/etc/apt/sources.list.d/openvpn.list && apt-key del E158C569 && wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
 wget -qO security-openvpn-net.asc "https://keys.openpgp.org/vks/v1/by-fingerprint/F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7" && gpg --import security-openvpn-net.asc
 apt-get update -y
 apt-get install openvpn -y
}

function InstWebmin(){
 WebminFile='http://prdownloads.sourceforge.net/webadmin/webmin_1.910_all.deb'
 wget -qO webmin.deb "$WebminFile"
 dpkg --install webmin.deb
 rm -rf webmin.deb
 sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf
 systemctl restart webmin
}

function InstSSH(){
 rm -f /etc/ssh/sshd_config*
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
 sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner

 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
 systemctl restart ssh

 rm -rf /etc/default/dropbear*
 
 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

 # Now changing our desired dropbear ports
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 
 # Restarting dropbear service
 systemctl restart dropbear
}

function InsStunnel(){
 StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

 # Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS="/etc/banner"
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*
 
 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=PH/ST=NCR/L=Manila/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
##  > /dev/null 2>&1

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:dropbear_port_c

[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:openssh_port_c
MyStunnelC

 # setting stunnel ports
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf

 # Restarting stunnel service
 systemctl restart $StunnelDir

}

function InsOpenVPN(){
 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'VPN1' > /etc/openvpn/server_tcp.conf
port MyOvpnPort1
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh none
server 172.18.0.0 255.255.0.0
ifconfig-pool-persist /etc/openvpn/ipp.txt
duplicate-cn
keepalive 10 120
tls-crypt ta.key
compress lz4
max-clients 4000
user nobody
group nogroup
persist-key
persist-tun
status /etc/openvpn/openvpn-status.log
log /etc/openvpn/openvpn.log
verb 3
mute 20
explicit-exit-notify 0
cipher AES-128-CBC
auth SHA256
push "redirect-gateway def1"
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
VPN1

cat <<'VPN2' > /etc/openvpn/server_tcp1.conf
port MyOvpnPort2
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh none
server 172.19.0.0 255.255.0.0
ifconfig-pool-persist /etc/openvpn/ipp.txt
duplicate-cn
keepalive 10 120
tls-crypt ta.key
compress lz4
max-clients 4000
user nobody
group nogroup
persist-key
persist-tun
status /etc/openvpn/openvpn-status.log
log /etc/openvpn/openvpn.log
verb 3
mute 20
explicit-exit-notify 0
cipher AES-128-CBC
auth SHA256
push "redirect-gateway def1"
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
VPN2

 cat <<'VPN3' > /etc/openvpn/server_udp.conf
port MyOvpnPort3
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh none
server 172.20.0.0 255.255.0.0
ifconfig-pool-persist /etc/openvpn/ipp.txt
duplicate-cn
keepalive 10 120
tls-crypt ta.key
compress lz4
max-clients 4000
user nobody
group nogroup
persist-key
persist-tun
status /etc/openvpn/openvpn-status.log
log /etc/openvpn/openvpn.log
verb 3
mute 20
explicit-exit-notify 0
cipher AES-128-CBC
auth SHA256
push "redirect-gateway def1"
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
VPN3

 cat <<'VPN4' > /etc/openvpn/server_udp1.conf
port MyOvpnPort4
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh none
server 172.21.0.0 255.255.0.0
ifconfig-pool-persist /etc/openvpn/ipp.txt
duplicate-cn
keepalive 10 120
tls-crypt ta.key
compress lz4
max-clients 4000
user nobody
group nogroup
persist-key
persist-tun
status /etc/openvpn/openvpn-status.log
log /etc/openvpn/openvpn.log
verb 3
mute 20
explicit-exit-notify 0
cipher AES-128-CBC
auth SHA256
push "redirect-gateway def1"
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
VPN4

 cat <<'CERT'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIB/TCCAYKgAwIBAgIUNH30fnRLkt03pCWLm/rxoHDzXLswCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMjIwMzE4MTkzNDE1WhcNMzIwMzE1
MTkzNDE1WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABDU/aCg94N0chFQ/GBszev44qlY98wFndPDTj+g4QWp0cglarndHJJXY
6pOIRZkPUoMECruYToSH/8LwtHgoeNxCiqLL3mODZP3s395BL93VAc1LfY2K3gmD
D8VtwzcZq6OBkDCBjTAdBgNVHQ4EFgQU8E9Vc7Q8ZTuNCK4aOpCQyL6cc9kwUQYD
VR0jBEowSIAU8E9Vc7Q8ZTuNCK4aOpCQyL6cc9mhGqQYMBYxFDASBgNVBAMMC0Vh
c3ktUlNBIENBghQ0ffR+dEuS3TekJYub+vGgcPNcuzAMBgNVHRMEBTADAQH/MAsG
A1UdDwQEAwIBBjAKBggqhkjOPQQDAgNpADBmAjEA9tY8w6/O2zF6vkmbJO3tKxsU
UHyRziaq92qRP3KhCUUaRqph5sOQRnai0nEI2/BMAjEAunAoJb2BcdJRdNbRMi9t
sCcYgoUcwGfW6V8z3nR9jnOavFyGi1owc1Zj+wZjf+r1
-----END CERTIFICATE-----
CERT

 cat <<'SCERT'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            a1:5b:c1:fe:e7:89:aa:61:bc:97:49:fb:29:8f:fc:cc
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Easy-RSA CA
        Validity
            Not Before: Mar 18 19:36:45 2022 GMT
            Not After : Mar 15 19:36:45 2032 GMT
        Subject: CN=server
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:bf:5d:da:05:bb:bf:4f:a6:40:ed:6c:6b:18:1b:
                    7b:ac:85:35:a0:cc:79:88:ea:92:7b:91:8c:52:a2:
                    47:1a:73:af:cd:ee:be:83:c2:7b:9e:21:ba:09:4d:
                    39:32:11:d8:29:67:cb:36:7d:97:91:03:a6:f5:17:
                    d7:e7:fa:70:93:86:08:04:80:d2:38:71:04:93:b5:
                    84:0d:43:fb:1d:a6:bd:c2:73:78:6b:84:88:de:ab:
                    94:4f:76:04:5b:1e:72
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                70:F7:BF:AB:C1:88:3E:7F:6B:95:F6:71:F7:BF:8D:11:DC:6E:98:91
            X509v3 Authority Key Identifier: 
                keyid:F0:4F:55:73:B4:3C:65:3B:8D:08:AE:1A:3A:90:90:C8:BE:9C:73:D9
                DirName:/CN=Easy-RSA CA
                serial:34:7D:F4:7E:74:4B:92:DD:37:A4:25:8B:9B:FA:F1:A0:70:F3:5C:BB

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: ecdsa-with-SHA256
         30:66:02:31:00:99:bb:23:68:15:c5:e5:1f:82:ff:0d:01:90:
         4c:e3:f2:4a:05:58:82:16:bf:db:75:f9:a9:d1:b8:f2:e9:77:
         a0:e4:1b:30:23:b0:6f:61:b3:a0:0c:a6:e3:bc:90:87:27:02:
         31:00:bc:1f:34:6c:91:52:6b:be:1c:78:c4:45:18:4d:1e:02:
         c8:2b:75:0d:e9:4f:e6:86:65:ab:7f:fd:9a:db:f6:63:34:42:
         64:d7:b0:68:cd:2a:5e:1e:f8:71:26:5b:b5:2b
-----BEGIN CERTIFICATE-----
MIICGjCCAZ+gAwIBAgIRAKFbwf7niaphvJdJ+ymP/MwwCgYIKoZIzj0EAwIwFjEU
MBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMjIwMzE4MTkzNjQ1WhcNMzIwMzE1MTkz
NjQ1WjARMQ8wDQYDVQQDDAZzZXJ2ZXIwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS/
XdoFu79PpkDtbGsYG3ushTWgzHmI6pJ7kYxSokcac6/N7r6DwnueIboJTTkyEdgp
Z8s2fZeRA6b1F9fn+nCThggEgNI4cQSTtYQNQ/sdpr3Cc3hrhIjeq5RPdgRbHnKj
gbUwgbIwCQYDVR0TBAIwADAdBgNVHQ4EFgQUcPe/q8GIPn9rlfZx97+NEdxumJEw
UQYDVR0jBEowSIAU8E9Vc7Q8ZTuNCK4aOpCQyL6cc9mhGqQYMBYxFDASBgNVBAMM
C0Vhc3ktUlNBIENBghQ0ffR+dEuS3TekJYub+vGgcPNcuzATBgNVHSUEDDAKBggr
BgEFBQcDATALBgNVHQ8EBAMCBaAwEQYDVR0RBAowCIIGc2VydmVyMAoGCCqGSM49
BAMCA2kAMGYCMQCZuyNoFcXlH4L/DQGQTOPySgVYgha/23X5qdG48ul3oOQbMCOw
b2GzoAym47yQhycCMQC8HzRskVJrvhx4xEUYTR4CyCt1DelP5oZlq3/9mtv2YzRC
ZNewaM0qXh74cSZbtSs=
-----END CERTIFICATE-----
SCERT

 cat <<'SKEY' > /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB9GFQq8I1R0E5HqmyN
K5dn/EvbG8DeHddWLB8CYCsALo+UaYbxebUvVumkxwGmSaqhZANiAAS/XdoFu79P
pkDtbGsYG3ushTWgzHmI6pJ7kYxSokcac6/N7r6DwnueIboJTTkyEdgpZ8s2fZeR
A6b1F9fn+nCThggEgNI4cQSTtYQNQ/sdpr3Cc3hrhIjeq5RPdgRbHnI=
-----END PRIVATE KEY-----
SKEY

cat <<'TAK' > /etc/openvpn/ta.key
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
172be86093890bb827d0c03b7cd60835
8e76c0da47337c15ab22287500915fe1
728b86664823ceccd2595e2781d5acef
428146ec3f13ee005608cc8bc98d64e9
7fd51b396b22e34906c38bc956af2174
18987125fad057280de4a0c16d18cda1
66b635babd7d23c950046ae68e86f4bd
dab3e08b2f76d517e21d09c661b8c4eb
3c60edb292bfc66f3974b112741ff5f5
8aabc3982ee2a3ae5d6b9dfedf24312d
e2477f08feac84bf7fbe89b233e6d6a8
db9fb65f5d8dab3de61497837ded52da
cb47b2bfc9644512e85f60e9b20e289e
97fed7e79881cc3befe40d835a94c713
6c4c5d0c667c75b38235c6310ec8b9ab
3edb2283397e85e14a1b9f935d4667ba
-----END OpenVPN Static key V1-----
TAK

cat <<'clientkey' > /etc/openvpn/ckey.key
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAJr0n/pKoD7rubXqFI
PUe4tKmOCFXmq4YRFKpcGddtcczvlfBmtNHCcCo3OjTgWOahZANiAATVlCL4CFD6
u5vvFo+1Y0nL/d2bKKWwCAxunWlP4SBIfKvYar7w8hO2wn4xVgAkN8WYfTIJJOn4
cWpEI2d5L9sahAmyX3UBoCbBa2vNtIGcHPyD9rPFHKRJ7ZSDf6DhCqs=
-----END PRIVATE KEY-----
clientkey

cat <<'clientcert' > /etc/openvpn/ccert.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            41:fd:1c:7c:6b:27:02:73:6d:3b:17:39:c6:90:6c:39
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Easy-RSA CA
        Validity
            Not Before: Mar 18 19:39:04 2022 GMT
            Not After : Mar 15 19:39:04 2032 GMT
        Subject: CN=client1
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:d5:94:22:f8:08:50:fa:bb:9b:ef:16:8f:b5:63:
                    49:cb:fd:dd:9b:28:a5:b0:08:0c:6e:9d:69:4f:e1:
                    20:48:7c:ab:d8:6a:be:f0:f2:13:b6:c2:7e:31:56:
                    00:24:37:c5:98:7d:32:09:24:e9:f8:71:6a:44:23:
                    67:79:2f:db:1a:84:09:b2:5f:75:01:a0:26:c1:6b:
                    6b:cd:b4:81:9c:1c:fc:83:f6:b3:c5:1c:a4:49:ed:
                    94:83:7f:a0:e1:0a:ab
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                FE:2B:1A:EA:60:05:DC:1E:23:12:CC:83:B8:2A:CB:FA:B3:A5:10:29
            X509v3 Authority Key Identifier: 
                keyid:F0:4F:55:73:B4:3C:65:3B:8D:08:AE:1A:3A:90:90:C8:BE:9C:73:D9
                DirName:/CN=Easy-RSA CA
                serial:34:7D:F4:7E:74:4B:92:DD:37:A4:25:8B:9B:FA:F1:A0:70:F3:5C:BB

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: ecdsa-with-SHA256
         30:66:02:31:00:c2:e0:44:02:52:90:5e:65:3f:2c:c0:d9:d1:
         85:d0:f4:53:d9:d2:62:c7:21:8d:41:50:c8:5d:47:d0:b6:41:
         1f:f9:a1:8c:a2:88:98:da:28:38:a8:a1:d9:e0:aa:20:a2:02:
         31:00:c2:38:9a:0e:74:2d:60:e9:e7:20:34:ec:ab:28:45:33:
         9b:0a:75:70:a1:89:f5:38:e2:87:fa:88:8d:00:5b:5d:cc:7b:
         14:80:19:16:eb:58:84:8c:4a:d5:3f:4d:e6:7f
-----BEGIN CERTIFICATE-----
MIICBzCCAYygAwIBAgIQQf0cfGsnAnNtOxc5xpBsOTAKBggqhkjOPQQDAjAWMRQw
EgYDVQQDDAtFYXN5LVJTQSBDQTAeFw0yMjAzMTgxOTM5MDRaFw0zMjAzMTUxOTM5
MDRaMBIxEDAOBgNVBAMMB2NsaWVudDEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATV
lCL4CFD6u5vvFo+1Y0nL/d2bKKWwCAxunWlP4SBIfKvYar7w8hO2wn4xVgAkN8WY
fTIJJOn4cWpEI2d5L9sahAmyX3UBoCbBa2vNtIGcHPyD9rPFHKRJ7ZSDf6DhCquj
gaIwgZ8wCQYDVR0TBAIwADAdBgNVHQ4EFgQU/isa6mAF3B4jEsyDuCrL+rOlECkw
UQYDVR0jBEowSIAU8E9Vc7Q8ZTuNCK4aOpCQyL6cc9mhGqQYMBYxFDASBgNVBAMM
C0Vhc3ktUlNBIENBghQ0ffR+dEuS3TekJYub+vGgcPNcuzATBgNVHSUEDDAKBggr
BgEFBQcDAjALBgNVHQ8EBAMCB4AwCgYIKoZIzj0EAwIDaQAwZgIxAMLgRAJSkF5l
PyzA2dGF0PRT2dJixyGNQVDIXUfQtkEf+aGMooiY2ig4qKHZ4KogogIxAMI4mg50
LWDp5yA07KsoRTObCnVwoYn1OOKH+oiNAFtdzHsUgBkW61iEjErVP03mfw==
-----END CERTIFICATE-----
clientcert

 # setting openvpn server port
 sed -i "s|MyOvpnPort1|$OpenVPN_Port1|g" /etc/openvpn/server_tcp.conf
 sed -i "s|MyOvpnPort2|$OpenVPN_Port2|g" /etc/openvpn/server_tcp1.conf
 sed -i "s|MyOvpnPort3|$OpenVPN_Port3|g" /etc/openvpn/server_udp.conf
 sed -i "s|MyOvpnPort4|$OpenVPN_Port4|g" /etc/openvpn/server_udp1.conf
 
 # Getting some OpenVPN plugins for unix authentication
 #wget -qO /etc/openvpn/b.zip 'https://github.com/imaPSYCHO/Parts/raw/main/openvpn_plugin64'
 #unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
 #rm -f /etc/openvpn/b.zip
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf && sysctl --system &> /dev/null && echo 1 > /proc/sys/net/ipv4/ip_forward

 # Installing Firewalld
 apt install firewalld -y
 systemctl start firewalld
 systemctl enable firewalld
 firewall-cmd --quiet --set-default-zone=public
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/tcp
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/udp
 firewall-cmd --quiet --reload
 firewall-cmd --quiet --add-masquerade
 firewall-cmd --quiet --permanent --add-masquerade
 firewall-cmd --quiet --permanent --add-service=ssh
 firewall-cmd --quiet --permanent --add-service=openvpn
 firewall-cmd --quiet --permanent --add-service=http
 firewall-cmd --quiet --permanent --add-service=https
 firewall-cmd --quiet --permanent --add-service=privoxy
 firewall-cmd --quiet --permanent --add-service=squid
 firewall-cmd --quiet --reload
 
 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward

 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl start openvpn@server_tcp1
 systemctl start openvpn@server_udp
 systemctl start openvpn@server_udp1
 systemctl enable openvpn@server_tcp
 systemctl enable openvpn@server_tcp1
 systemctl enable openvpn@server_udp
 systemctl enable openvpn@server_udp1
 systemctl restart openvpn@server_tcp
 systemctl restart openvpn@server_tcp1
 systemctl restart openvpn@server_udp
 systemctl restart openvpn@server_udp1
}

function InsProxy(){
 # Removing Duplicate privoxy config
 rm -rf /etc/privoxy/config*
 
 # Creating Privoxy server config using cat eof tricks
 cat <<'myPrivoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
listen-address 0.0.0.0:Privoxy_Port2
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
myPrivoxy

 # Setting machine's IP Address inside of our privoxy config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/privoxy/config
 
 # Setting privoxy ports
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port2|$Privoxy_Port2|g" /etc/privoxy/config

 # I'm setting Some Squid workarounds to prevent Privoxy's overflowing file descriptors that causing 50X error when clients trying to connect to your proxy server(thanks for this trick @homer_simpsons)
 apt remove --purge squid -y
 rm -rf /etc/squid/sq*
 apt install squid -y
 
# Squid Ports (must be 1024 or higher)

 cat <<mySquid > /etc/squid/squid.conf
acl VPN dst $(wget -4qO- http://ipinfo.io/ip)/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:$Proxy_Port1
http_port 0.0.0.0:$Proxy_Port2
coredump_dir /var/spool/squid
dns_nameservers 1.1.1.1 1.0.0.1
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname localhost
mySquid

 sed -i "s|SquidCacheHelper|$Proxy_Port1|g" /etc/squid/squid.conf
 sed -i "s|SquidCacheHelper|$Proxy_Port2|g" /etc/squid/squid.conf

sudo apt install ziproxy
 cat <<myziproxy > /etc/ziproxy/ziproxy.conf
 Port = 2898
 UseContentLength = false
 ImageQuality = {30,25,25,20}
myziproxy

 # Starting Proxy server
 echo -e "Restarting proxy server.."
 systemctl restart privoxy
 systemctl restart squid
 systemctl restart ziproxy
}

function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/bonveio-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/bonveio-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn

 # Now creating all of our OpenVPN Configs 
cat <<EOF152 > /var/www/openvpn/GStories.ovpn
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port1
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
auth-user-pass
mute-replay-warnings
remote-cert-tls server
cipher AES-128-CBC
auth sha256
verb 3
mute 20
key-direction 1
compress lz4
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.0
http-proxy-option CUSTOM-HEADER Host vt.tiktok.com
http-proxy-option CUSTOM-HEADER X-Forward-Host vt.tiktok.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For vt.tiktok.com
http-proxy-option CUSTOM-HEADER Referrer vt.tiktok.com

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/ccert.crt)
</cert>
<key>
$(cat /etc/openvpn/ckey.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF152

cat <<EOF16 > /var/www/openvpn/WildRift.ovpn
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port2
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
auth-user-pass
mute-replay-warnings
remote-cert-tls server
cipher AES-128-CBC
auth sha256
verb 3
mute 20
key-direction 1
compress lz4
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port2
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.0
http-proxy-option CUSTOM-HEADER "Host: mobile.garena.my"
http-proxy-option CUSTOM-HEADER "X-Online-Host: mobile.garena.my"
http-proxy-option CUSTOM-HEADER "X-Forward-Host: mobile.garena.my"
http-proxy-option CUSTOM-HEADER "Connection: Keep-Alive"

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/ccert.crt)
</cert>
<key>
$(cat /etc/openvpn/ckey.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF16

cat <<EOF18 > /var/www/openvpn/GGames.ovpn
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
auth-user-pass
mute-replay-warnings
remote-cert-tls server
cipher AES-128-CBC
auth sha256
verb 3
mute 20
key-direction 1
compress lz4
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port1
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.0
http-proxy-option CUSTOM-HEADER "Host: c3cdn.ml.youngjoygame.com"
http-proxy-option CUSTOM-HEADER "X-Online-Host: c3cdn.ml.youngjoygame.com"
http-proxy-option CUSTOM-HEADER "X-Forward-Host: c3cdn.ml.youngjoygame.com"
http-proxy-option CUSTOM-HEADER "Connection: Keep-Alive"

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/ccert.crt)
</cert>
<key>
$(cat /etc/openvpn/ckey.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF18

cat <<EOF601 > /var/www/openvpn/GVideo.ovpn
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
auth-user-pass
mute-replay-warnings
remote-cert-tls server
cipher AES-128-CBC
auth sha256
verb 3
mute 20
key-direction 1
compress lz4
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port1
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.0
http-proxy-option CUSTOM-HEADER "Host: staging.iwant.ph"
http-proxy-option CUSTOM-HEADER "X-Online-Host: staging.iwant.ph"
http-proxy-option CUSTOM-HEADER "X-Forward-Host: staging.iwant.ph"
http-proxy-option CUSTOM-HEADER "Connection: Keep-Alive"

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/ccert.crt)
</cert>
<key>
$(cat /etc/openvpn/ckey.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF601

cat <<EOF600 > /var/www/openvpn/GTM.ovpn
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
auth-user-pass
mute-replay-warnings
remote-cert-tls server
cipher AES-128-CBC
auth sha256
verb 3
mute 20
key-direction 1
compress lz4
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port1
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.0
http-proxy-option CUSTOM-HEADER "Host: redirect.googlevideo.com"
http-proxy-option CUSTOM-HEADER "X-Online-Host: redirect.googlevideo.com"
http-proxy-option CUSTOM-HEADER "X-Forward-Host: redirect.googlevideo.com"
http-proxy-option CUSTOM-HEADER "Connection: Keep-Alive"

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/ccert.crt)
</cert>
<key>
$(cat /etc/openvpn/ckey.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF600

cat <<EOF160 > /var/www/openvpn/UDP_1194.ovpn
client
dev tun
proto udp
remote $IPADDR $OpenVPN_Port3
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
auth-user-pass
mute-replay-warnings
remote-cert-tls server
cipher AES-128-CBC
auth sha256
verb 3
mute 20
key-direction 1
compress lz4

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/ccert.crt)
</cert>
<key>
$(cat /etc/openvpn/ckey.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF160

cat <<EOF17 > /var/www/openvpn/UDP_25888.ovpn
client
dev tun
proto udp
remote $IPADDR $OpenVPN_Port4
remote-cert-tls server
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
auth-user-pass
mute-replay-warnings
remote-cert-tls server
cipher AES-128-CBC
auth sha256
verb 3
mute 20
key-direction 1
compress lz4

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/ccert.crt)
</cert>
<key>
$(cat /etc/openvpn/ckey.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/ta.key)
</tls-crypt>
EOF17


cat <<NOTE > /var/www/openvpn/ENJOY.txt
        **ENJOY AND HAVE FUN**
   <3 THANK YOU FOR THE SUPPORT <3
     ## HOPE YOU WILL BE ABLE ##
> TO SEE THE TRICK IN OUR NEW CONFIG <
NOTE

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">
<!-- GVPNHUB CONF SITE -->
<head>
<meta charset="utf-8" />
<title>FREENET OVPN</title>
<meta name="description" content="This site is made only for GVPNHUB CONF's and are NOT FOR SALE" />
<meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" />
<meta name="theme-color" content="#000000" />
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css">
<link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
</head>
<body style="background-image: linear-gradient(to right, #6f9ee8, #427bd4, #195bc2)">
<div class="container justify-content-center>
    <div class="col-md">
        <div class="view" style="margin-top:3em;margin-bottom:3em;">
                <center>
                    <img class="w3-circle" src="https://github.com/yakult13/parte/raw/main/cafe%20(1).png" width="250px" height="250px" class="card-img-top">
                </center>
        </div>
    <div class="card">
        <div class="card-body">
            <h5 class="card-title"><center><b><3 THANK YOU FREENET USERS <3</b></center></h5>
            <br>
            <ul class="list-group">
                <li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;">
                    <p>Note
                        <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span>
                        <br>
                        <small>ZIP FILE</small>
                    </p>
                    <a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/OVPN.zip" style="float:right;"><i class="fa fa-download"></i> Download</a>
                </li>
                <li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;">
                    <p> GTM
                        <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span>
                        <br>
                        <small>WNP/SNS/FUNALIW</small>
                    </p>
                    <a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GTM.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a>
                </li>
                <li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;">
                   <p>UDP
                        <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span>
                        <br>
                        
                   </p>
                    <a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/UDP_1194.ovpn" style="float:right;"><i class="fa fa-download"></i> 1194</a>
                
                    <a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/UDP_25888.ovpn" style="float:right;"><i class="fa fa-download"></i> 25888</a>
                </li>
                <li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;">
                    <p>Smart
                        <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span>
                        <br>
                        <small>Giga Promos</small>
                    </p>
                    <a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GGames.ovpn" style="float:right;"><i class="fa fa-download"></i> Games/Ml</a>
                    <a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/WildRift.ovpn" style="float:right;"><i class="fa fa-download"></i> Games/WR</a>                        
                 
                    <a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GStories.ovpn" style="float:right;"><i class="fa fa-download"></i> Stories</a>                        
                 
                    <a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GVideo.ovpn" style="float:right;"><i class="fa fa-download"></i> Video</a>
                </li>
                
            </ul>
        </div>
        </div>   
    </div>
    <br>
    </div>
</body>
</html>
mySiteOvpn
 
 # Setting template's correct name,IP address and nginx Port
 sed -i "s|MyScriptName|$MyScriptName|g" /var/www/openvpn/index.html
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html

 # Restarting nginx service
 systemctl restart nginx
 
 # Creating all .ovpn config archives
 cd /var/www/openvpn 
 zip -qq -r OVPN.zip *.ovpn *.txt
 cd
}

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 timedatectl set-timezone Asia/Manila
     #write out current crontab
     crontab -l > mycron
     #echo new cron into cron file
     echo -e "0 3 * * * /sbin/reboot >/dev/null 2>&1" >> mycron
     echo -e "*/1 * * * * sudo service ziproxy restart" >> mycron
     echo -e "0 */1 * * * /sbin/sysctl -p >/dev/null 2>&1" >> mycron
     echo -e "0 */1 * * * sysctl -p" >> mycron
     #install new cron file
     crontab mycron
     service cron restart
     echo '0 3 * * * /sbin/reboot >/dev/null 2>&1' >> /etc/cron.d/mycron
     echo '*/1 * * * * sudo service ziproxy restart' >> /etc/cron.d/mycron
     echo '0 */1 * * * /sbin/sysctl -p >/dev/null 2>&1' >> /etc/cron.d/mycron
     echo '0 */1 * * * sysctl -p' >> mycron

 # Creating directory for startup script
 rm -rf /etc/juans
 mkdir -p /etc/juans
 chmod -R 777 /etc/juans
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/juans/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
EOFSH
 chmod +x /etc/juans/startup.sh
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/juans/startup.sh

 # 
 rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
 echo "[Unit]
Description=Juans Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/juans/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/juans.service
 chmod +x /etc/systemd/system/juans.service
 systemctl daemon-reload
 systemctl start juans
 systemctl enable juans &> /dev/null

 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron
 
}

function ConfMenu(){
echo -e " Creating Menu scripts.."

cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,delete_all,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://github.com/yue0706/parte/raw/main/fixed1.zip'
unzip -qq fixed1.zip
rm -f fixed1.zip
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
sed -i 's|http_port|listen-address|g' ./*
cd ~

echo 'clear' > /etc/profile.d/juans.sh
echo 'echo '' > /var/log/syslog' >> /etc/profile.d/juans.sh
echo 'screenfetch -p -A Debian' >> /etc/profile.d/juans.sh
chmod +x /etc/profile.d/juans.sh

 # Turning Off Multi-login Auto Kill
 rm -f /etc/cron.d/set_multilogin_autokill_lib
 
 # removing and installing sysctl.conf for bbr installation
 rm -f /etc/sysctl.conf
 wget -q https://github.com/yue0706/parte/raw/main/sysctl.conf
 chmod -R 777 sysctl.conf
 mv sysctl.conf /etc/
 
}

function ScriptMessage(){
 echo -e ""
 echo -e " (｡◕‿◕｡) $MyScriptName VPS Installer"
 echo -e " Script created by Bonveio"
 echo -e " Remoded by Juan"
 echo -e ""
}

 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31m×\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 
  echo -e "Updating Libraries...."
 Instupdate
 
 # Configure OpenSSH and Dropbear
 echo -e "Configuring ssh..."
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring stunnel..."
 InsStunnel
 
 # Configure Webmin
 echo -e "Configuring webmin..."
 InstWebmin
 
 # Configure Privoxy and Squid
 echo -e "Configuring proxy..."
 InsProxy
 
 # Configure OpenVPN
 echo -e "Configuring OpenVPN..."
 InsOpenVPN
 
 # Configuring Nginx OVPN config download site
 OvpnConfigs

 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 
 # restarting sysctl.conf to update
 sysctl -p

 wget -qO /etc/ssh/ssht https://github.com/yakult13/ws/raw/main/services.py
chmod +x services.py
cat << END > /lib/systemd/system/ssht.service
[Unit]
Description=Websocket
Documentation=https://google.com
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/bin/python -O /etc/ssh/ssht
ProtectSystem=true
ProtectHome=true
RemainAfterExit=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
END
systemctl daemon-reload
systemctl enable ssht
systemctl restart ssht

 clear
 cd ~

 # Running sysinfo 
 bash /etc/profile.d/juans.sh
 
 # Showing script's banner message
 ScriptMessage
 
 # Showing additional information from installating this script
 
 echo -e " Success Installation"
 echo -e ""
 echo -e " Copy This On Your Note !"
 echo -e ""
 echo -e " Service Ports: "
 echo -e " SSH: $SSH_Port1, $SSH_Port2"
 echo -e " SSL: $Stunnel_Port1, $Stunnel_Port2"
 echo -e " Dropbear: $Dropbear_Port1, $Dropbear_Port2"
 echo -e " Privoxy: $Privoxy_Port1, $Privoxy_Port2"
 echo -e " Squid: $Proxy_Port1, $Proxy_Port2"
 echo -e " Auto-Recon: $Port"
 echo -e " TCP: $OpenVPN_Port1, $OpenVPN_Port2"
 echo -e " UDP: $OpenVPN_Port3, $OpenVPN_Port4"
 echo -e " NGiNX: $OvpnDownload_Port"
 echo -e " Webmin: 10000"
 echo -e " Server Reset: 3AM PH Time"
 echo -e ""
 echo -e " OpenVPN Configs Download site"
 echo -e " http://$IPADDR:$OvpnDownload_Port"
 echo -e ""
 echo -e " All OpenVPN Configs Archive"
 echo -e " http://$IPADDR:$OvpnDownload_Port/OVPN.zip"
 echo -e ""
 echo -e " [Note] DO NOT RESELL THIS SCRIPT"

 # Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog

exit 1
