#!/bin/sh
# Install a verified Juardrails release binary for macOS or Linux.
set -eu

case "$(uname -s)" in
  Darwin) platform=darwin ;;
  Linux) platform=linux ;;
  *) echo 'Unsupported OS; use the GitHub Releases page.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) architecture=amd64 ;;
  arm64|aarch64) architecture=arm64 ;;
  *) echo 'Unsupported CPU architecture.' >&2; exit 1 ;;
esac

asset="juardrails-${platform}-${architecture}"
version="${JUARDRAILS_VERSION:-latest}"
case "$version" in
  latest) base='https://github.com/abhaybhargav/juardrails/releases/latest/download' ;;
  v[0-9]*)
    case "$version" in *[!a-zA-Z0-9._-]*) echo 'Invalid version.' >&2; exit 1 ;; esac
    base="https://github.com/abhaybhargav/juardrails/releases/download/${version}" ;;
  *) echo 'JUARDRAILS_VERSION must be a release tag such as v0.1.0.' >&2; exit 1 ;;
esac

command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
curl -fL --retry 3 -o "$temporary/$asset" "$base/$asset"
curl -fL --retry 3 -o "$temporary/SHA256SUMS" "$base/SHA256SUMS"
expected=$(awk -v name="$asset" '$2 == name {print $1}' "$temporary/SHA256SUMS")
[ -n "$expected" ] || { echo 'Release checksum is missing.' >&2; exit 1; }
if command -v shasum >/dev/null; then
  actual=$(shasum -a 256 "$temporary/$asset" | awk '{print $1}')
elif command -v sha256sum >/dev/null; then
  actual=$(sha256sum "$temporary/$asset" | awk '{print $1}')
else
  echo 'A SHA-256 checksum tool is required.' >&2; exit 1
fi
[ "$actual" = "$expected" ] || { echo 'Release checksum mismatch.' >&2; exit 1; }

install_dir="${JUARDRAILS_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$install_dir"
install -m 0755 "$temporary/$asset" "$install_dir/juardrails"
echo "Installed $install_dir/juardrails"
"$install_dir/juardrails" version
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "Add $install_dir to your PATH to run juardrails from any directory." ;;
esac
