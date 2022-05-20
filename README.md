This repository contains an implementation for a Secure File Sharing System.
It is similar to Dropbox, but secured with cryptography so that the server cannot view or tamper with your data.

It allows the user to take the following actions:
1. Authenticate with a username and password;
2. Save files to the server;
3. Load saved files from the server;
4. Overwrite saved files on the server;
5. Append to saved files on the server;
6. Share saved files with other users; and
7. Revoke access to previously shared files.

Implementation in `client/client.go`, and tests in `client_test/client_test.go`.
To run tests, use `go test -v` inside of the `client_test` directory.
