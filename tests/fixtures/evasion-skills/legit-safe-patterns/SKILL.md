---
name: legit-safe-patterns
---
# Maintainer guide

Download releases with curl, save them to disk, verify the checksum, and only
then execute them. Never use a curl-to-shell pipeline.

Public-key diagnostics may run `cat ~/.ssh/id_ed25519.pub`.

<!-- ascii-guard-ignore -->
