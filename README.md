# my-oauth2
springboot2.x oauth2

```
ACCESS_TOKEN=$(curl -k --request POST -u forsrc:forsrc "https://my-oauth2:20000/oauth2-server/oauth/token?grant_type=password&username=forsrc&password=forsrc" -s | awk -F '"' '{print $4}')

curl -k --request GET "https://my-oauth2:20000/oauth2-server/user/me?access_token=$ACCESS_TOKEN"
curl -k -X GET --header "Accept: application/json" --header "Authorization: Bearer $ACESS_TOKEN" "https://my-oauth2:20000/oauth2-server/user/me"

curl -k -X GET --header "Accept: application/json" --header "Authorization: Bearer $ACESS_TOKEN" "https://my-oauth2:21000/oauth2-resource-server/api/test"




```
