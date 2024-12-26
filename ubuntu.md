# creating a bootable pendrive from ubuntu
1. insert pendrive and find it in termial
   - ```
     lsblk
     ```
2. sudo dd bs=4M if=/home/sumit/Documents/ubuntu-24.04.1-desktop-amd64.iso of=/dev/sdb status=progress conv=fdatasync
	- sdb : pendrive name
