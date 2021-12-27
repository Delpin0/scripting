#!/bin/bash
#Get the name for the connection and use the ip file to keep track of used IPs


echo "Enter name of the user/device you want to add: "
read $VPN_USER
SERVER_PUBKEY=`cat /etc/wireguard/public.key`
IP_RANGE=10.100.0
EXTERNAL_IP=`dig @resolver4.opendns.com myip.opendns.com +short`


#Create the public/private keypair
mkdir -p /etc/wireguard/clients; wg genkey | sudo tee /etc/wireguard/clients/$VPN_USER.key | wg pubkey | sudo tee /etc/wireguard/clients/$VPN_USER.key.pub
#Get the next sequential IP for the config
# Verify the IP tracker exists
if [ ! -f /opt/scripts/ip ]
then
    echo "1" > /opt/scripts/ip
fi

IP=`cat /opt/scripts/ip`
IP=$(($IP + 1))
echo $IP > /opt/scripts/ip

#Create the config file
PRIVKEY=`cat /etc/wireguard/clients/$VPN_USER.key`
PUBKEY=`cat /etc/wireguard/clients/$VPN_USER.key.pub`
echo "Public Key: $PUBKEY"
echo "Private Key: $PRIVKEY"
echo "[Interface]" > /etc/wireguard/clients/$VPN_USER.conf
echo "PrivateKey = $PRIVKEY" >> /etc/wireguard/clients/$VPN_USER.conf
echo "Address = $IP_RANGE.$IP/24" >> /etc/wireguard/clients/$VPN_USER.conf
echo "DNS = 1.1.1.1, 1.0.0.1" >> /etc/wireguard/clients/$VPN_USER.conf
echo "" >> /etc/wireguard/clients/$VPN_USER.conf
echo "[Peer]" >> /etc/wireguard/clients/$VPN_USER.conf
echo "PublicKey = $SERVER_PUBKEY" >> /etc/wireguard/clients/$VPN_USER.conf
echo "AllowedIPs = 0.0.0.0/0" >> /etc/wireguard/clients/$VPN_USER.conf
echo "Endpoint = $EXTERNAL_IP:51820" >> /etc/wireguard/clients/$VPN_USER.conf

#Add the created configuration to allowed hosts
wg set wg0 peer $PUBKEY allowed-ips $IP_RANGE.0/24


echo "Scan the following with your mobile device if so needed."
qrencode -t ansiutf8 < /etc/wireguard/clients/$VPN_USER.conf
