# macos browser secrets stealer

`dump_browser_secrets.py` takes the user login password and dumps the browser secrets such as passwords, credit cards number, and cookies. It uses [chainbreaker](https://github.com/n0fate/chainbreaker) to retrieve the decryption keys from the login keychain. Next, it uses these decryption keys to decrypt the browsers' stored secrets. The method used to retrieve browsers' secrets is taken from the [MacStealer malware](https://www.uptycs.com/blog/macstealer-command-and-control-c2-malware). 

Currently, it supports Chrome and Edge on macOS but it can support other browsers as well. To add support for a browser, just append the browser names to the `Broswer.browsers` variable in the script. 

*Note that, Firefox may use another technique to store its secret data so this script may not work against the Firefox browser.*


### RUN

First install [chainbreaker](https://github.com/n0fate/chainbreaker) and then run the script: 
```sh
python3 dump_browser_screts.py                                                                                                       
[INFO] Read and decrypt browsers stored secrets such as passwords, credit cards details, and cookies
[+] Enter login password:
[INFO] Login keychain path= /Users/dev/Library/Keychains/login.keychain-db
[INFO] Dumping passwords from keychain
[INFO] Available browsers = {'Google-Chrome': '/Users/dev/Library/Application Support/Google/Chrome', 'Microsoft-Edge': '/Users/dev/Library/Application Support/Microsoft Edge'}
[INFO] Getting and Decrypting browser secrets
[INFO] Decrypting credentials
[INFO] Decrypting credit cards number
[INFO] Decrypting cookies
[INFO] Writing the browser secrets to /Users/dev/secret_output
[INFO] Writing login details to a file
[INFO] Writing credit cards info to a file
[INFO] Writing cookies to a file
```
