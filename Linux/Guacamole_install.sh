#!/bin/bash
#Install and configure Guacamole
#The LDAP connector is commented out, uncomment it if you'll be using that

#Update Everything
apt update && apt -y dist-upgrade

#Install Stuff
apt -y install gcc libcairo2-dev libpng12-dev libossp-uuid-dev libfreerdp-dev libpango1.0-dev libssh2-1-dev \
libtelnet-dev libvncserver-dev libpulse-dev libssl-dev libvorbis-dev libwebp-dev \
mysql-server mysql-client mysql-common mysql-utilities tomcat7 wget vim libavcodec-dev libavutil-dev libswscale-dev \
libfreerdp-dev libssh2-1-dev libssl-dev

#Create installer folder
mkdir ~/GuacInstall
cd ~/GuacInstall

# Install libjpeg-turbo-dev
wget -O libjpeg-turbo-official_1.5.2_amd64.deb https://PATH/TO/FILE/libjpeg-turbo-official_1.5.2_amd64.deb
dpkg -i libjpeg-turbo-official_1.5.2_amd64.deb
rm libjpeg-turbo-official_1.5.2_amd64.deb

# Add GUACAMOLE_HOME to Tomcat7 ENV
echo -e "\n# GUACAMOLE ENV VARIABLE" >> /etc/default/tomcat7
echo "GUACAMOLE_HOME=/etc/guacamole" >> /etc/default/tomcat7

#Download Guacamole Files PATH/TO/FILE/
wget -O guacamole-0.9.13.war "https://PATH/TO/FILE/guacamole-0.9.13-incubating.war"
wget -O guacamole-server-0.9.13.tar.gz "https://PATH/TO/FILE/guacamole-server-0.9.13-incubating.tar.gz"
wget -O guacamole-auth-jdbc-0.9.13.tar.gz "https://PATH/TO/FILE/guacamole-auth-jdbc-0.9.13-incubating.tar.gz"
#wget -O guacamole-auth-ldap-0.9.13.tar.gz "https://PATH/TO/FILE/guacamole-auth-ldap-0.9.13-incubating.tar.gz"
wget -O mysql-connector-java-5.1.44.tar.gz "https://PATH/TO/FILE/mysql-connector-java-5.1.44.tar.gz"


#Extract Guac
tar -xzf guacamole-server-0.9.13.tar.gz
tar -xzf guacamole-auth-jdbc-0.9.13.tar.gz
#tar -xvf guacamole-auth-ldap-0.9.13.tar.gz
tar -xzf mysql-connector-java-5.1.44.tar.gz


# MAKE DIRECTORIES
mkdir -p /etc/guacamole/lib
mkdir -p /etc/guacamole/extensions

# Install GUACD
cd guacamole-server-0.9.13-incubating
./configure --with-init-dir=/etc/init.d
make
make install
ldconfig
systemctl enable guacd
service guacd start
cd ..

# Move files to correct locations
mv guacamole-0.9.13.war /etc/guacamole/guacamole.war
ln -s /etc/guacamole/guacamole.war /var/lib/tomcat7/webapps/
cp mysql-connector-java-5.1.44/mysql-connector-java-5.1.44-bin.jar /etc/guacamole/lib/
cp guacamole-auth-jdbc-0.9.13-incubating/mysql/guacamole-auth-jdbc-mysql-0.9.13-incubating.jar /etc/guacamole/extensions/
#cp guacamole-auth-ldap-0.9.13-incubating/guacamole-auth-ldap-0.9.13-incubating.jar /etc/guacamole/extensions/

# Configure guacamole.properties
echo -e "\n#MYSQL configuration" >> /etc/guacamole/guacamole.properties
echo "mysql-hostname: localhost" >> /etc/guacamole/guacamole.properties
echo "mysql-port: 3306" >> /etc/guacamole/guacamole.properties
echo "mysql-database: guacamole_db" >> /etc/guacamole/guacamole.properties
echo "mysql-username: guacamole_user" >> /etc/guacamole/guacamole.properties


#LDAP configuration
#echo "#Configure ldap for server XXXXX" >> /etc/guacamole/guacamole.properties
#echo "# ldap properties" >> /etc/guacamole/guacamole.properties
#echo "ldap-hostname: $HOSTNAME" >> /etc/guacamole/guacamole.properties
#echo "ldap-port: 389" >> /etc/guacamole/guacamole.properties
#echo "#ldap-encryption-method: ssl" >> /etc/guacamole/guacamole.properties
#echo "ldap-user-base-dn: CN=Users,DC=CONTOSO,DC=COM" >> /etc/guacamole/guacamole.properties
#echo "#ldap-username-attribute: CN" >> /etc/guacamole/guacamole.properties
#echo "#ldap-config-base-dn: DC=CONTOSO,DC=COM" >> /etc/guacamole/guacamole.properties
#echo "ldap-search-bind-dn: CN=$GUACAMOLE_USER,CN=Users,DC=CONTOSO,DC=COM" >> /etc/guacamole/guacamole.properties
#echo "ldap-search-bind-password: $GUACAMOLE_PASSWORD" >> /etc/guacamole/guacamole.properties
#echo "ldap-username-attribute: sAMAccountName" >> /etc/guacamole/guacamole.properties


# This is where you will want to change the GUACAMOLE_PASSWORD 
echo "mysql-password: GUACAMOLE_PASSWORD" >> /etc/guacamole/guacamole.properties
rm -rf /usr/share/tomcat7/.guacamole
ln -s /etc/guacamole /usr/share/tomcat7/.guacamole


#Add IP information to hostname  Be sure to change both the server IP and the hostname
#SERVER_IP=`hostname -I`
#echo "$SERVER_IP      $HOSTNAME.CONTOSO.COM" >> /etc/hosts

#Create the database and user.  Be sure to use the GUACAMOLE_PASSWORD you created above.
mysql -u root -p -v -e "CREATE DATABASE guacamole_db; CREATE USER 'GUACAMOLE_USER'@'localhost' IDENTIFIED BY 'GUACAMOLE_PASSWORD'; GRANT SELECT,INSERT,UPDATE,DELETE ON guacamole_db.* TO 'guacamole_user'@'localhost'; FLUSH PRIVILEGES;"

cd ~/GuacInstall/guacamole-auth-jdbc-0.9.13-incubating/mysql/
cat schema/*.sql | mysql -u root -p guacamole_db

#Create user mappings file 
touch /etc/guacamole/user-mapping.xml
chown tomcat7:tomcat7 /etc/guacamole/user-mapping.xml

# Restart Tomcat Service
service tomcat7 restart

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

#Final cleanup
rm -rf ~/GuacInstall
