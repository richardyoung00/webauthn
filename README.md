## Registration

1. Client makes request to server with username to get a random challenge string and a server defined user id
2. call navigator.credentials.create()
3. response is serialized to JSON and sent to server
4. server verifies that challenge was the same one sent
5. server verifies that origin is correct
6. verifyAuthenticatorAttestationResponse
7. If verified correctly then save user to DB

Resources:
- https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770
- https://medium.com/@herrjemand/verifying-fido2-safetynet-attestation-bd261ce1978d
