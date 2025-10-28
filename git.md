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
