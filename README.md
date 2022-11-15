# go_jwt_auth
This module is Mantained by Extark and is open source, you can use it for your personal modules.

## Methods
```func CreateAuthorization(data any, tokenExpireTimeHours int, encryptionKey string) (access string, refresh string, err error)```

Returns two JWT tokens and an error (if there is one), one for the access token and the second for the refresh token
