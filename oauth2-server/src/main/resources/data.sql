-- oauth_client_details
-- INSERT INTO oauth_client_details (client_id, client_secret, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, additional_information, autoapprove) VALUES  ('forsrc', 'forsrc', 'forsrc', 'forsrc,read,write', 'authorization_code,client_credentials,refresh_token,password,implicit', null, null, 36000, 36000, null, true);
INSERT INTO oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types,
                                  web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity,
                                  additional_information, autoapprove)
VALUES ('forsrc', 'forsrc,oauth_server,api,resource,ui', '$2a$10$Smc1lKpNSr/MeX1ZTt0GVu0b6LzlbOBp8Lzy9JfriAb1Xp8rVBMsm',
        'forsrc,oauth_server,api,resource,tcc,user,ui,read,write',
        'authorization_code,client_credentials,refresh_token,password,implicit',
        'http://oauth2-client:22000/oauth2-client/login/oauth2/code/my-oauth2,http://oauth2-client:22000/oauth2-client/login,https://oauth2-client/oauth2-client/login/oauth2/code/my-oauth2, https://oauth2-client/oauth2-client/login,https://oauth2-client:8080/oauth2-client/login/oauth2/code/my-oauth2,https://oauth2-client:8080/oauth2-client/login,http://oauth2-gateway/oauth2-client/login,http://oauth2-gateway/oauth2-client/login/oauth2/code/my-oauth2,https://oauth2-gateway/oauth2-client/login/oauth2/code/my-oauth2',
        null, 36000, 36000, null, 'true');
INSERT INTO oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types,
                                  web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity,
                                  additional_information, autoapprove)
VALUES ('oauth_server', 'forsrc,oauth_server,api,resource,ui',
        '$2a$10$Smc1lKpNSr/MeX1ZTt0GVu0b6LzlbOBp8Lzy9JfriAb1Xp8rVBMsm',
        'forsrc,oauth_server,api,resource,tcc,user,ui,read,write',
        'authorization_code,client_credentials,refresh_token,password,implicit',
        'http://oauth2-client:22000/oauth2-client/login/oauth2/code/my-oauth2,http://oauth2-client:22000/oauth2-client/login,https://oauth2-client/oauth2-client/login/oauth2/code/my-oauth2, https://oauth2-client/oauth2-client/login,https://oauth2-client:8080/oauth2-client/login/oauth2/code/my-oauth2,https://oauth2-client:8080/oauth2-client/login,http://oauth2-gateway/oauth2-client/login,http://oauth2-gateway/oauth2-client/login/oauth2/code/my-oauth2,https://oauth2-gateway/oauth2-client/login/oauth2/code/my-oauth2',
        null, 36000, 36000, null, 'true');
INSERT INTO oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types,
                                  web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity,
                                  additional_information, autoapprove)
VALUES ('ui', 'forsrc,oauth_server,api,resource,ui', '$2a$10$Smc1lKpNSr/MeX1ZTt0GVu0b6LzlbOBp8Lzy9JfriAb1Xp8rVBMsm',
        'forsrc,oauth_server,api,resource,tcc,user,ui,read,write',
        'authorization_code,client_credentials,refresh_token,password,implicit',
        'http://oauth2-client:22000/oauth2-client/login/oauth2/code/my-oauth2,http://oauth2-client:22000/oauth2-client/login,https://oauth2-client/oauth2-client/login/oauth2/code/my-oauth2, https://oauth2-client/oauth2-client/login,https://oauth2-client:8080/oauth2-client/login/oauth2/code/my-oauth2,https://oauth2-client:8080/oauth2-client/login,http://oauth2-gateway/oauth2-client/login,http://oauth2-gateway/oauth2-client/login/oauth2/code/my-oauth2,https://oauth2-gateway/oauth2-client/login/oauth2/code/my-oauth2',
        null, 36000, 36000, null, 'true');
INSERT INTO oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types,
                                  web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity,
                                  additional_information, autoapprove)
VALUES ('resource', 'forsrc,oauth_server,api,resource,ui',
        '$2a$10$Smc1lKpNSr/MeX1ZTt0GVu0b6LzlbOBp8Lzy9JfriAb1Xp8rVBMsm',
        'forsrc,oauth_server,api,resource,tcc,user,ui,read,write',
        'authorization_code,client_credentials,refresh_token,password,implicit', null, null, 36000, 36000, null,
        'true');
INSERT INTO oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types,
                                  web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity,
                                  additional_information, autoapprove)
VALUES ('api', 'forsrc,oauth_server,api,resource,ui', '$2a$10$Smc1lKpNSr/MeX1ZTt0GVu0b6LzlbOBp8Lzy9JfriAb1Xp8rVBMsm',
        'forsrc,oauth_server,api,resource,tcc,user,ui,read,write',
        'authorization_code,client_credentials,refresh_token,password,implicit', null, null, 36000, 36000, null,
        'true');


-- users
INSERT INTO users (username, password, enabled)
SELECT *
FROM (SELECT 'forsrc' username, '$2a$10$Wzme7qZtAsJZspQpNx3ee.qTu/IqRHiTb0jORWUOXCxptAkG3kf8e' password, 1 enabled) AS T
WHERE NOT EXISTS(SELECT username FROM users WHERE username = 'forsrc');
INSERT INTO users (username, password, enabled)
SELECT *
FROM (SELECT 'user' username, '$2a$10$SNKOBpTBuCbWukZ3Rc5DpuIHRP585Ss02fULAIX/m1NmFpWeJ8ic2' password, 1 enabled) AS T
WHERE NOT EXISTS(SELECT username FROM users WHERE username = 'user');
INSERT INTO users (username, password, enabled)
SELECT *
FROM (SELECT 'tcc' username, '$2a$10$lFUTwK/W3S3U8NI3cnqJPeVD3cZj6udLbW2W5GMvybtJw70N4WqFC' password, 1 enabled) AS T
WHERE NOT EXISTS(SELECT username FROM users WHERE username = 'tcc');
INSERT INTO users (username, password, enabled)
SELECT *
FROM (SELECT 'test' username, '$2a$10$uCchlP6N1q7ZOEMMifeZyOEOgqpddiVEIiIrM4k/76ftgLxtBaSXq' password, 1 enabled) AS T
WHERE NOT EXISTS(SELECT username FROM users WHERE username = 'test');

-- authorities
INSERT INTO authorities (username, authority)
SELECT *
FROM (SELECT 'forsrc' username, 'ROLE_ADMIN' authorities) AS T
WHERE NOT EXISTS(SELECT username FROM authorities WHERE username = 'forsrc' and authority = 'ROLE_ADMIN');
INSERT INTO authorities (username, authority)
SELECT *
FROM (SELECT 'forsrc' username, 'ROLE_USER' authorities) AS T
WHERE NOT EXISTS(SELECT username FROM authorities WHERE username = 'forsrc' and authority = 'ROLE_USER');
INSERT INTO authorities (username, authority)
SELECT *
FROM (SELECT 'user' username, 'ROLE_USER' authorities) AS T
WHERE NOT EXISTS(SELECT username FROM authorities WHERE username = 'user');
INSERT INTO authorities (username, authority)
SELECT *
FROM (SELECT 'tcc' username, 'ROLE_TCC' authorities) AS T
WHERE NOT EXISTS(SELECT username FROM authorities WHERE username = 'tcc');
INSERT INTO authorities (username, authority)
SELECT *
FROM (SELECT 'test' username, 'ROLE_TEST' authorities) AS T
WHERE NOT EXISTS(SELECT username FROM authorities WHERE username = 'test');
 
