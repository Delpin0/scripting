#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#Post-configuration check script:
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


#Check for accounts with password min age not set  71927
awk -F: '$4 < 1 {print $1}' /etc/shadow
#Remedy line:
chage -m 1 [user]

#Check for accounts with no max password age   71931
awk -F: '$5 > 60 {print $1}' /etc/shadow
#Remedy line
chage -M 60 [user]

#Check for sudo users with nopasswd and if found remove the NOPASSWD flag 71947
grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

#Verify no user had !authenticate in their sudoers   71949
grep -i authenticate /etc/sudoers /etc/sudoers.d/*

#Verify all groups are specified in /etc/group  72003
#Also verify no listed accounts without home directories are interactive users    72011
pwck -r

#Verify no one but root has a UID of 0   72005
awk -F: '$3 == 0 {print $1}' /etc/passwd

#Verify no files are unowned by a user 72007
find / -nouser

#Verify no files are unowned by a group 72009
find / -nogroup

#Set all home directories to 750 permissions  72017  This was done initially but should also be done afer any new users may have been added
chmod  0750 /home/*

#Verify files in the home directories are owned by that user or group a user belongs to  72023 72025
for dir in /home/*/; do
    ls -lLR /home/$dir
done

#Verify all directories that are world writeable are owned by root, bin, sys, or an application group    72047
find / -xdev -perm -002 -type d -exec ls -lLd {} \;

#Verify no umasks are set less restrictive than 077   72049
grep -i umask /home/*/.*

#Debsums will allow the equivalent to rpm -Va (RPM Verify All)
debsums -a | grep -v "OK" - Selects all packages installed that do not match their default MD5 checksums


