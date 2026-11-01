#!/usr/bin/env bash
# Launches the Playwright MCP server. Uses the pre-installed Chromium when present
# (cloud sessions), otherwise falls back to Playwright's default browser.
args=(--headless --no-sandbox)
if [ -x /opt/pw-browsers/chromium ]; then
  args+=(--executable-path /opt/pw-browsers/chromium)
fi
exec npx -y @playwright/mcp@0.0.84 "${args[@]}" "$@"
