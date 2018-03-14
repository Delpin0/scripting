#!/bin/bash
read -r -p "Enter desired share name: " SHARE
read -r -p "Enter desired subnet IP range (end with slash notation) e.g. 10.3.1.0/24: " RANGE

apt install nfs-kernel-server -y
mkdir -p /export/$SHARE
mkdir /$SHARE
chmod 777 /$SHARE
mount --bind /$SHARE /export/$SHARE
#Add this to /etc/fstab
echo "/$SHARE    /export/$SHARE   none    bind  0  0" >> /etc/fstab
#add this to /etc/exports
echo "/$SHARE       $RANGE(rw,async,no_subtree_check,no_root_squash)" >> /etc/exports
service nfs-kernel-server restart
showmount -e localhost
