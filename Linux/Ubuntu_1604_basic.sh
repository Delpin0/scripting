#!/bin/bash
#Ubuntu 16.04

#Base updates
apt-get update -o Acquire::ForceIPv4=true
apt-get upgrade -y -o Acquire::ForceIPv4=true
apt-get install vim wget -y -o Acquire::ForceIPv4=true
apt-get autoremove -o Acquire::ForceIPv4=true
apt-get autoclean -o Acquire::ForceIPv4=true

#Disable IPV6
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >>/etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.conf
sysctl -p

#  Install Fail2ban
apt-get install sudo fail2ban -y -o Acquire::ForceIPv4=true
service fail2ban start

#  Remove common unnecessary applications
apt-get remove bind9 apache2 rpcbind postfix -y -o Acquire::ForceIPv4=true

#  Install tshark
#apt-get install tshark -y -o Acquire::ForceIPv4=true

#Install Strongswan from source
apt-get update
apt-get install gcc libgmp3-dev build-essential inotify-tools make gcc-multilib -y -o Acquire::ForceIPv4=true
cd ~
wget https://download.strongswan.org/strongswan-5.6.1.tar.bz2
tar xjvf strongswan-5.6.1.tar.bz2
cd strongswan-5.6.1
./configure --prefix=/usr --sysconfdir=/etc
make
make install
cd ..
rm -rf strongswan-5.6.1
rm strongswan-5.6.1.tar.bz2


#Install OSSEC from source as a standalone monitor only
cd ~
wget https://github.com/ossec/ossec-hids/archive/2.9.2.tar.gz
tar zxf 2.9.2.tar.gz
cd ossec-hids-2.9.2/
cp etc/preloaded-vars.conf.example etc/preloaded-vars.conf
sed -i 's/#USER_LANGUAGE="en"/USER_LANGUAGE="en"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_NO_STOP="y"/USER_NO_STOP="y"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_INSTALL_TYPE="local"/USER_INSTALL_TYPE="local"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_DIR="\/var\/ossec"/USER_DIR="\/var\/ossec"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_DELETE_DIR="y"/USER_DELETE_DIR="y"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_ENABLE_ACTIVE_RESPONSE="y"/USER_ENABLE_ACTIVE_RESPONSE="y"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_ENABLE_SYSCHECK="y"/USER_ENABLE_SYSCHECK="y"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_ENABLE_ROOTCHECK="y"/USER_ENABLE_ROOTCHECK="y"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_ENABLE_EMAIL="y"/USER_ENABLE_EMAIL="n"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_ENABLE_SYSLOG="y"/USER_ENABLE_SYSLOG="y"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_ENABLE_FIREWALL_RESPONSE="y"/USER_ENABLE_FIREWALL_RESPONSE="n"/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
sed -i 's/#USER_WHITE_LIST="192.168.2.1 192.168.1.0\/24"/USER_WHITE_LIST=""/' ~/ossec-hids-2.9.2/etc/preloaded-vars.conf
./install.sh
/var/ossec/bin/ossec-control start
cd ..
rm -rf ossec-hids-2.9.2
rm 2.9.2.tar.gz


#Remove code compilers and dependencies, the run a final update.
apt-get remove -y build-essential inotify-tools gcc libgmp3-dev make gcc-multilib -o Acquire::ForceIPv4=true
apt-get update -o Acquire::ForceIPv4=true
apt-get upgrade -y -o Acquire::ForceIPv4=true
apt-get autoremove -y


#Update nanorc
sed -i 's/# set autoindent/set autoindent/' /etc/nanorc
sed -i 's/# set constantshow/set constantshow/' /etc/nanorc
sed -i 's/set nowrap/#set nowrap/' /etc/nanorc
sed -i 's/# set smarthome/set smarthome/' /etc/nanorc
sed -i 's/# set smooth/set smooth/' /etc/nanorc
sed -i 's/# set softwrap/set softwrap/' /etc/nanorc
sed -i 's/# set tabsize 8/set tabsize 4/' /etc/nanorc
sed -i 's/# set tabstospaces/set tabstospaces/' /etc/nanorc

#Rename the system host
read -r -p "Enter system hostname:" NEW_HOSTNAME
echo $NEW_HOSTNAME > /proc/sys/kernel/hostname
sed -i 's/127.0.1.1.*/127.0.1.1\t'"$NEW_HOSTNAME"'/g' /etc/hosts
echo $NEW_HOSTNAME > /etc/hostname
service hostname start

#Persist IPtables
apt-get install iptables-persistent -y -o Acquire::ForceIPv4=true
