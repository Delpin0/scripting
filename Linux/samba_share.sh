#!/bin/bash
read -r -p "Enter user name: " USER
apt install samba -y
smbpasswd -a $USER
mkdir /home/$USER/sambashare

if [ ! -f /etc/samba/smb.conf.orig ]; then
    cp /etc/samba/smb.conf /etc/samba/smb.conf.orig
fi
echo -e "\n" 
echo "[$USER sambashare]" >> /etc/samba/smb.conf
echo "path = /home/$USER/sambashare" >> /etc/samba/smb.conf
echo "guest ok = no" >> /etc/samba/smb.conf
echo "valid users = $USER" >> /etc/samba/smb.conf
echo "read only = no" >> /etc/samba/smb.conf
service smbd restart
