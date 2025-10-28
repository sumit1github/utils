# how work with multiple git a/c in one system

### step1 - generate new keys
If we have an existing SSH key, we can ignore it or generate a fresh one. Otherwise, we can delete the old SSH keys and start with fresh, personal and professional keys.

```
ssh-keygen -t ed25519 -C "workemail@gmail.com"
thefile name enter => id_workemail

ssh-keygen -t ed25519 -C "personalemail@gmail.com"
thefile name enter => id_personalemail
```
now 2 ssh keys has been created

### step2 : need to register the keys in ssh agent

```
cd ~/.ssh
eval "$(ssh-agent -s)"
=> agent pid 3350

ssh-add id_workemail
ssh-add id_personalemail
==> Identity created
```

### step3 : add ssh keys in github
```
cd ~/.ssh
cat id_workemail.pub
cat id_personalemail.pub
```
copy and paste it in github

### step4 : update the config file
-
  ```
  cd ~/.ssh
  ```

-  `touch config` is no config file is present
-  open config file
-  ```
   nano config

   # --- paste at the end ---
   Host hge-nsg
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_whge
    AddKeysToAgent yes
   
   ```
- `Host hge-nsg` -> identifier name, can be any
- `HostName github.com ` -> github.com is the actual domain/sub-domain
- `User git ` -> always will be the git
- `IdentityFile ~/.ssh/id_whge` -> point to the private key
- `AddKeysToAgent yes` -> tells SSH to automatically add the private key

### ste5 : need to test it
`Host hge-nsg` going to use this identifier to test

```
ssh -T hge-nsg
==> Hi abharadwaj-hge! You've successfully authenticated, but GitHub does not provide shell access.
```


