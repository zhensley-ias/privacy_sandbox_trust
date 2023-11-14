#!/bin/bash

# https://private-state-token-demo.glitch.me/

# the token here is the pubkey of the issued trust token
default_token="AAAAAQQ7W5gOubJT3kTpzNGsekT9RZPXgXGrOMB2+QPw/ZzAuLrM3kc8eyHuTc1KmKjH4sh5+ev5GCI4HVVd46o6rWvNvk0iZQtVuUPhT8X54Ajebng8v5zUnpnPuTjGqlc7+MM="

if [ "$1" != "" ]; then
  default_token="$1"
fi

open -a Google\ Chrome \
  --args \
  --enable-blink-features=PrivateStateTokens,PrivateStateTokensAlwaysAllowIssuance,PrivacySandboxSettings3 \
  --additional-private-state-token-key-commitments='{ "https://trust-token-server.com": { "PrivateStateTokenV1VOPRF": { "protocol_version": "PrivateStateTokenV1VOPRF", "id": 1, "batchsize": 1, "keys": { "1": { "Y": "'$default_token'", "expiry": "1715356984440000" } } } } }'

