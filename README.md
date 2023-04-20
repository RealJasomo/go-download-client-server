# Go iWantuTake

## Features
- [ ] client can  request a file to download from server
- [ ] client an upload a file to the server
- [ ] server can handle multiple requests at a time
- [ ] server can act as a client but can't find new clients
- [ ] paths are sanitized or rejected to protect against folder escalation `../../etc...` or unresolved environment variables `$VAR`
- [ ] server files are sandboxed and will warn if overwritten. 
- [ ] server will create directories as needed 
- [ ] all client files are encrypted with a public/private key encryption, client will store it's own keys
