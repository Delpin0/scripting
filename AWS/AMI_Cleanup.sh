#/bin/bash
#Set date to 7 days ago
d=`date +%m-%d-%Y --date "7 day ago"`

#This block finds all AMIs tagged with the date a week ago, then strips out the text beyond the AMI ID.
#As before, if you have two accounts, use the --profile flag to specify between them.
aws ec2 describe-images --filters Name=tag-key,Values=Backup Name=tag-value,Values="$d" --query 'Images[*].{ID:ImageId}' > image.txt	
grep -e "ami" image.txt > image2.txt
sed 's/        "ID": "//g' image2.txt > image.txt
sed 's/"//g' image.txt > serverstodelete.txt
rm image.txt image2.txt


#Delete the servers listed from the previous command string
while read servername; do
  aws ec2 deregister-image --image-id $servername
#  echo "Deleted AMI $servername"
done <serverstodelete.txt
rm serverstodelete.txt
