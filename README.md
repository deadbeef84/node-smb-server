smbclient --option='debugencryption=yes' -d 10 -U foo%bar '\\localhost\nxt' -c dir
sudo $(which node) --watch .
docker run --name smb -p 445:445 -v /tmp:/webdav --rm nxtedition/samba:4.16.10-nxt.0