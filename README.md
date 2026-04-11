# google-drive-s3
I.R.I.S. (Integrated Reliable Interop Storage)

Use Cloudflare Workers to turn your Google Drive into S3 object storage at no extra cost.

## About
This is a Workers script that converts the Google Drive API into an S3-compatible API. Turn your Google Drive into object storage at no extra cost!

### Does it work with the free Workers plan?
Signature verification uses the native Web Crypto API, and exceeding the 10ms CPU time limit is not normal usage. It also leverages JavaScript streams to handle large files.
However, this means that features such as hash verification are not implemented. This is because the memory limitations of Workers make it impossible to expand the entire uploaded file into memory.

### Does this violate the Google Terms of Service?
We believe that it does not violate the Terms of Service as long as you do not upload illegal content such as CSAM.
For the sake of your Google account, we strongly recommend using this in an environment where only you can upload.


## How to Deploy

### 1. Prepare a Google Drive API Refresh Token
You will need to use rclone to obtain your Google API credentials and a Google Drive API refresh token.
Follow the rclone documentation to configure the client.  
https://rclone.org/drive/#making-your-own-client-id

> [!NOTE]
> When your Google API client is in "Testing" mode, the refresh token will expire after a certain period of time, so if you need to use it for a long period of time, be sure to switch the mode before authenticating with rclone.
> 
> You can complete the OAuth flow by skipping the very scary confirmation screen without submitting your app for validation.

Once complete, obtain the path to your rclone configuration file using `rclone config file`, read the configuration file, and note the following values:

```
[my-remote]
type = drive
# Use as GOOGLE_CLIENT_ID
client_id = myid.apps.googleusercontent.com
# Use as GOOGLE_CLIENT_SECRET
client_secret = SUPER_SECRET_TOKEN
scope = drive
token = {
  "access_token":"SECRET_ACCESS_TOKEN",
  "token_type":"Bearer",
  # ↓ Use this value as GOOGLE_REFRESH_TOKEN.
  "refresh_token":"SECRET_REFRESH_TOKEN",
  "expiry":"2026-01-08T12:37:09.064662+09:00",
  "expires_in":3599
}

```

### 2. Configure Cloudflare
From the Cloudflare dashboard, create two KV databases.  
Create a fork of this repository, edit `wrangler.json`, and modify the binding to the ID of your KV database.

Once complete, deploy Workers by running the following command:
```bash
wrangler deploy
```

### 3. Configure Secrets
Follow the documentation to configure the following secrets:  
https://developers.cloudflare.com/workers/configuration/secrets/#via-the-dashboard

| Key | Description |
| :--- | :--- |
| `ACCESS_KEY` | Any access key used by the S3 client. |
| `SECRET_KEY` | A secure secret key used by the S3 client. |
| `REGION` | The region used by the S3 client. |
| `GOOGLE_CLIENT_ID`,  `GOOGLE_CLIENT_SECRET`,   `GOOGLE_REFRESH_TOKEN` | Google API credentials obtained from rclone. |
| `ALLOWED_BUCKETS` | Set the buckets allowed, separated by `,`. A directory with the bucket name will be created directly under Google Drive. |
| `PUBLIC_READ_BUCKETS` | *(Optional)* Buckets that allow unauthenticated GET/HEAD access without signature, separated by `,`. Write operations (PUT/POST/DELETE) still require authentication. Must be a subset of `ALLOWED_BUCKETS`. |


### 4. CORS Configuration
If you need to configure CORS, set up your own domain for Workers and use Cloudflare's Response Header Transform Rules to add the necessary headers.  
https://developers.cloudflare.com/rules/transform/response-header-modification/
