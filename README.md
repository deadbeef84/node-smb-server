# user
node --openssl-legacy-provider --watch .
smbclient --port 8445 --option='debugencryption=yes' -d 10 -U foo%bar '\\localhost\nxt' -c dir

# root
sudo $(which node) --openssl-legacy-provider --watch .
smbclient --option='debugencryption=yes' -d 10 -U foo%bar '\\localhost\nxt' -c dir

# samba in docker...
docker run --name smb -p 445:445 -v /tmp:/webdav --rm nxtedition/samba:4.16.10-nxt.0