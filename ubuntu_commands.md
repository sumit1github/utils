# Download a file from server to local
```
scp root@<ip-address>:/var/lib/postgresql/basantishopee_7_mar_2026.bak /Users/sumit/Desktop/MyGitRepo/Basanti_Shopee/app
```
# upload from local to server
```
scp /path/to/local/file username@server_ip:/path/to/destination/

if neeed to use using ssh key

scp -i ~/.ssh/mykey.pem myfile.zip ubuntu@192.168.1.100:/home/ubuntu/uploads/
```
