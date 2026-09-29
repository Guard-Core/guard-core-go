#!/bin/sh
set -eu
go tool cover -func=cover.out | awk '/^total/ {gsub("%","",$3); if ($3+0 < 100.0) { printf "coverage %.1f%% < 100%%\n", $3; exit 1 } else print "coverage 100%" }'
