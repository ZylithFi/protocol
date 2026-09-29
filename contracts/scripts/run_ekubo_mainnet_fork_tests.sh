#!/usr/bin/env bash

set -euo pipefail

readonly SCARB_VERSION="2.18.0"
readonly SNFORGE_VERSION="0.61.0"
readonly USC_VERSION="2.10.1"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scarb_version="$(scarb --version | sed -n '1p')"
snforge_version="$(snforge --version)"

if [[ "$scarb_version" != "scarb ${SCARB_VERSION} "* ]]; then
  printf 'expected scarb %s, got %s\n' "$SCARB_VERSION" "$scarb_version" >&2
  exit 1
fi
if [[ "$snforge_version" != "snforge ${SNFORGE_VERSION}" ]]; then
  printf 'expected snforge %s, got %s\n' "$SNFORGE_VERSION" "$snforge_version" >&2
  exit 1
fi

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    target="aarch64-apple-darwin"
    archive_sha256="f209b9673e1d77cbb07409485fb5e0b6ac2018dc561f943bb5b9a3046a324454"
    ;;
  Darwin-x86_64)
    target="x86_64-apple-darwin"
    archive_sha256="b84daceab6c0ef7cb078a0560bb6d4f5bdc92d3b209f86258a5595caaf64a7c1"
    ;;
  Linux-aarch64 | Linux-arm64)
    target="aarch64-unknown-linux-gnu"
    archive_sha256="a329e34c5e9710f81a6b58ad100d6e509a52d194f4b566991d5a026411233a72"
    ;;
  Linux-x86_64)
    target="x86_64-unknown-linux-gnu"
    archive_sha256="8f6d9faf2ce644faa99e2acee7e855e3fbeb7919b99ec13d29f57c08089f2fb9"
    ;;
  *)
    printf 'unsupported ekubo fork-test platform: %s-%s\n' "$(uname -s)" "$(uname -m)" >&2
    exit 1
    ;;
esac

usc_root="$(mktemp -d "${TMPDIR:-/tmp}/zylith-ekubo-usc.XXXXXX")"
trap 'rm -rf "$usc_root"' EXIT
archive_name="universal-sierra-compiler-v${USC_VERSION}-${target}.tar.gz"
archive_path="${usc_root}/${archive_name}"
download_url="https://github.com/software-mansion/universal-sierra-compiler/releases/download/v${USC_VERSION}/${archive_name}"

curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --output "$archive_path" "$download_url"
if [[ "$(uname -s)" == "Darwin" ]]; then
  printf '%s  %s\n' "$archive_sha256" "$archive_path" | shasum -a 256 --check
else
  printf '%s  %s\n' "$archive_sha256" "$archive_path" | sha256sum --check --strict
fi

tar -xzf "$archive_path" -C "$usc_root"
compiler_dir="${usc_root}/universal-sierra-compiler-v${USC_VERSION}-${target}/bin"
compiler_version="$("${compiler_dir}/universal-sierra-compiler" --version)"
if [[ "$compiler_version" != "universal-sierra-compiler ${USC_VERSION}" ]]; then
  printf 'expected universal-sierra-compiler %s, got %s\n' "$USC_VERSION" "$compiler_version" >&2
  exit 1
fi

cd "${repo_root}/contracts"
PATH="${compiler_dir}:${PATH}" snforge test --max-threads 1 ekubo_fork
