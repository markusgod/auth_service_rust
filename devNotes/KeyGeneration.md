# ES384
```
openssl ecparam -genkey -noout -name secp384r1 | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
openssl ec -pubout -in ec-private.pem -out ec-public.pem
```

# ES256
```
openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
openssl ec -pubout -in ec-private.pem -out ec-public.pem
```
