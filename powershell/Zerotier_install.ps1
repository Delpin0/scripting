#Script install for zerotier

$NETWORKID = xxxxx
$AUTHKEY = XXXXXX
$SERVER_IP = x.x.x.x

$plinkPath = "C:\Program Files\Putty\plink.exe"
If (Test-Path $plinkPath) {
    Set-Alias plink $plinkPath
}
Else {
    $Putty = "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.70-installer.msi"
    Invoke-WebRequest -Uri $Putty -OutFile putty.msi
	Start-Process msiexec.exe -Wait -ArgumentList '/i putty.msi /qn'
	Remove-Item putty.msi
    Set-Alias plink $plinkPath
}
Set-Alias pscp "C:\Program Files\Putty\pscp.exe"

$zerotierPath = "C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe"
If (Test-Path $zerotierPath) {
    Set-Alias zerotier $zerotierPath
}
Else {
    $ZerotierDL = "https://download.zerotier.com/dist/ZeroTier%20One.msi"
	Invoke-WebRequest -Uri $ZerotierDL -OutFile zerotier.msi
	Start-Process msiexec.exe -Wait -ArgumentList '/i zerotier.msi /qn'
	Remove-Item zerotier.msi
    Set-Alias zerotier $zerotierPath
}

#Get the output data from the executable
$Output = zerotier -q info
#Convert the data to a string for modificaion
$Output2 = echo $Output | Select-Object -first 1
#Select the 10 characters after the tenth character
$UserID = $Output2.substring(9,10)
echo "Your user ID is $UserID"


#Attempt to join the network
zerotier -q join $NETWORKID

#Due to the wonderful way plink handles quotation marks, I have to upload the command as a shell script, run it, then delete it.
$command = "curl -X POST --header ""X-ZT1-Auth: AUTHKEY"" -d '{""authorized"":""true""}' http://localhost:9993/controller/network/$NETWORKID/member/$UserID" > authorize.sh
echo y | plink -ssh $SERVER_IP -l ubuntu -i "C:\PATH\TO\zerotier.ppk" exit
pscp -i "C:\PATH\TO\zerotier.ppk" authorize.sh ubuntu@10.4.2.137:/home/ubuntu/authorize.sh   
plink -ssh $SERVER_IP -l ubuntu -i "C:\PATH\TO\zerotier.ppk" "dos2unix authorize.sh"
plink -ssh $SERVER_IP -l ubuntu -i "C:\PATH\TO\zerotier.ppk" "bash authorize.sh"
plink -ssh $SERVER_IP -l ubuntu -i "C:\PATH\TO\zerotier.ppk" $command
