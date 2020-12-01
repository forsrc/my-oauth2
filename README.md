# my-oauth2
springboot2.x oauth2

```
ACCESS_TOKEN=$(curl -k --request POST -u forsrc:forsrc "https://my-oauth2:8080/oauth2-server/oauth/token?grant_type=password&username=forsrc&password=forsrc" -s | awk -F '"' '{print $4}')

curl -k --request GET "https://my-oauth2:8080/oauth2-server/user/me?access_token=$ACCESS_TOKEN"
curl -k -X GET --header "Accept: application/json" --header "Authorization: Bearer $ACCESS_TOKEN" "https://my-oauth2:8080/oauth2-server/user/me"

curl -k -X GET --header "Accept: application/json" --header "Authorization: Bearer $ACCESS_TOKEN" "https://my-oauth2:8080/oauth2-resource-server/api/test"

```

```
# ACCESS_TOKEN=$(curl -k -X POST -u "forsrc:forsrc" -d "grant_type=client_credentials" "https://my-oauth2:8080/oauth2-server/oauth/token" -s | awk -F '"' '{print $4}')

ACCESS_TOKEN=$(curl -k -X POST -u "forsrc:forsrc" "https://my-oauth2:8080/oauth2-server/oauth/token?grant_type=client_credentials" -s | awk -F '"' '{print $4}')

ACCESS_TOKEN=$(curl -k -X POST -d "grant_type=client_credentials&client_id=forsrc&client_secret=forsrc" "https://my-oauth2:8080/oauth2-server/oauth/token" -s | awk -F '"' '{print $4}')

curl -k --request GET "https://my-oauth2:8080/oauth2-server/user/me?access_token=$ACCESS_TOKEN"
```

```
TOKEN=$(curl -k --request POST -u forsrc:forsrc "https://my-oauth2:8080/oauth2-server/oauth/token?grant_type=password&username=forsrc&password=forsrc" -s)
ACCESS_TOKEN=$(echo  $TOKEN | awk -F '"' '{print $4}')
REFRESH_TOKEN=$(echo $TOKEN | awk -F '"' '{print $12}')

curl -k -X POST -d "grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}&client_id=forsrc&client_secret=forsrc" "https://my-oauth2:8080/oauth2-server/oauth/token"

```
