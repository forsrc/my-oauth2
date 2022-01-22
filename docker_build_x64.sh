docker build -t forsrc/my-oauth2:oauth2-admin-server    oauth2-admin-server/
docker build -t forsrc/my-oauth2:oauth2-client          oauth2-client2/
docker build -t forsrc/my-oauth2:oauth2-eureka-server   oauth2-eureka-server/
docker build -t forsrc/my-oauth2:oauth2-gateway         oauth2-gateway/
docker build -t forsrc/my-oauth2:oauth2-resource-server oauth2-resource-server/
docker build -t forsrc/my-oauth2:oauth2-server          oauth2-server/

docker push forsrc/my-oauth2:oauth2-admin-server
docker push forsrc/my-oauth2:oauth2-client
docker push forsrc/my-oauth2:oauth2-eureka-server
docker push forsrc/my-oauth2:oauth2-gateway
docker push forsrc/my-oauth2:oauth2-resource-server
docker push forsrc/my-oauth2:oauth2-server