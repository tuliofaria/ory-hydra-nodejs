# OAuth2 Flow Demo

- `auth-app`: user identification and consent coordination. Also, provide private data from an user.
- `client-app`: OAuth2 client app. This is the app that is going to consume data from auth-app.
- `client-app-passportjs`: OAuth2 client app using PassportJS.

For this test, only Ory Hydra runs inside docker. All the other services can be run on the host.

# Running:

Start Ory Hydra:

```shell
docker compose up
```

## Creating a new OAuth2 client on Ory Hydra:

```shell
docker compose exec hydra hydra create client \
    --endpoint http://127.0.0.1:4445 \
    --name "Partner apps name" \
    --id someidforthisclient \
    --secret my-secret \
    --grant-type authorization_code,refresh_token \
    --response-type code,id_token \
    --scope openid,offline,profile,email \
    --redirect-uri http://localhost:5555/callback \
    --token-endpoint-auth-method client_secret_post \
    --logo-uri <https://url-to-partner-logo.png>
```

Or with a JSON:

```shell
curl -X POST 'http://127.0.0.1:4445/admin/clients' -H 'Content-Type: application/json' -d @client-pkce.json
```

```json
{
  "client_id": "idoftheclient2",
  "client_secret": "my-secret",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code", "id_token"],
  "scope": "openid offline profile email",
  "token_endpoint_auth_method": "client_secret_post",
  "access_token_strategy": "opaque",
  "redirect_uris": ["http://localhost:5555/callback"],
  "authorization_code_grant_access_token_lifespan": "165000h0m0s"
}
```

Start `auth-app` and `client-app`:

```shell
cd auth-app
npm install
npm run start

# open another terminal
cd client-app
npm install
npm run start
```

Open:

http://localhost:5555

Follow the flow :)

Login can also be initiate with some URL like this (this is the same URL from login button):

http://localhost:4444/oauth2/auth?client_id=client-id&redirect_uri=http://localhost:5555/callback&response_type=code&scope=openid,offline,profile,email&state=somestate
