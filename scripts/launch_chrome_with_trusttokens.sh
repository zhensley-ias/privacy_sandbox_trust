#!/bin/bash

# https://private-state-token-demo.glitch.me/

# the token here is the pubkey of the issued trust token
default_token="AAAAAQQ7W5gOubJT3kTpzNGsekT9RZPXgXGrOMB2+QPw/ZzAuLrM3kc8eyHuTc1KmKjH4sh5+ev5GCI4HVVd46o6rWvNvk0iZQtVuUPhT8X54Ajebng8v5zUnpnPuTjGqlc7+MM="

if [ "$1" != "" ]; then
  default_token="$1"
fi

discovered_token=$(docker exec -it trust-token-server cat /home/node/privacy_sandbox_trust/cmake-build-debug/keys/pub_key.txt)
echo "discovered_token: $discovered_token"

if [ "$discovered_token" != "" ]; then
  default_token="$discovered_token"
fi

commitments="{ \"https://trust-token-server.com\": { \"PrivateStateTokenV1VOPRF\": { \"protocol_version\": \"PrivateStateTokenV1VOPRF\", \"id\": 1, \"batchsize\": 1, \"keys\": { \"1\": { \"Y\": \"$default_token\", \"expiry\": \"1715356984440000\" } } } } }"

#TEST_ISSUER="https://ias_test_host.com"
TEST_ISSUER="https://trust-token-server.com"

# grab our commitments object, convert to string
commitmentObj=$(curl --insecure https://trust-token-server.com/trust-token-server/.well-known/private-state-token/key-commitment | jq -c "{\"${TEST_ISSUER}\": .}")
echo "commitmentObj: $commitmentObj"

open -a Google\ Chrome \
  --args \
  --enable-blink-features=PrivateStateTokens,PrivateStateTokensAlwaysAllowIssuance,PrivacySandboxSettings3 \
  --additional-private-state-token-key-commitments="$commitmentObj"
