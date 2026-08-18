#!/usr/bin/env bash
# Wrapper so the suite can run this like any other test.
cd "$(dirname "$0")/.." || exit 1
exec node test/checks.mjs
