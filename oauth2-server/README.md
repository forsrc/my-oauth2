```
token=$(curl --request POST -u forsrc:forsrc "http://localhost:20000/oauth/token?grant_type=password&username=forsrc&password=forsrc" --silent | awk -F"\"" '{print $4}')
curl --request GET "http://localhost:20000/user/me?access_token=$token" --silent
```
