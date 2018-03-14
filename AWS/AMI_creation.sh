#/bin/bash
Server=i-0000000xxxxxxx #Instance ID
#Repeat for each server

d=`date +%m-%d-%Y`
TIMER=20
#TIMER is the number of seconds between snapshots.  I found that the standard AWS instances would fail when they went too quickly for some reason, but with an inserted delay
#they worked properly.  Decrease if you want to play with it.

#This creates a snapshot of the instance specified and applies a tag to it with the date of backup.   Be sure jq is installed with apt install jq
#You'll need to create the following section for each server you want to back up.  If the AWS instance is in another AWS account, e.g. GovCloud and standard
#Use the --profile flag with aws ec2



instance=`aws ec2 create-image --instance-id $Server --no-reboot  --name "$Server System $d " --description "$Server $d" | jq -r '.ImageId'`
aws ec2 create-tags --resources $instance --tags Key=Backup,Value=$d
echo "$Server image created"
sleep $TIMER

#Again, repeat this above section for each server.  I may be able to alter this in the future to allow reading from a list elsewhere and running a while loop
#but at this time, didn't have the time.
