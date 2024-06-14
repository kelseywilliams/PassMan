# PassMan
## Description
PassMan is a command line password manager for storing passwords locally. Enter a domain name to store your different accounts under and even add notes to the account. Passwords are protected behind a single master password that can be changed.  Passwords entered into PassMan are encrypted using Fernet encryption using the master password as the key.
## Dependencies
`colored`
`cryptography`

## Usage
### General Usage
To call PassMan, structure your calls to the application as
`main.py <command> [<domain>] [<account>]`
* domain: optional. A domain name to store or access an account under.
* account: optional. The number of the account to be affected.  
### Commands
* `fetch`: Fetch existing account or accounts under a domain name.  Takes arguments domain and optional argument account.
* `list`: List all domain names in passman.  Takes no arguments.
* `add`: Adds an account under a domain name.  Takes arguments domain.
* `delete`: Deletes an account or all acounts under a domain name. Takes arguments domain and optional argument account.
* `rekey`: Resets master key. Takes no arguments.
