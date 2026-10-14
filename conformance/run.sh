#!/usr/bin/env bash
# Runs the OpenID Foundation conformance suite against the current commit of
# Clavis (ADR 0017).
#
# Usage: conformance/run.sh [<plan> <configuration file>]...
#
# Without arguments, runs the plans in PLANS. Results and service logs are
# written to conformance/results/. Set KEEP=1 to leave the containers running
# afterwards, so results can be browsed at https://localhost.emobix.co.uk:8443.
set -euo pipefail

cd "$(dirname "$0")"

# Suite release that provides the runner scripts. Keep it in sync with the
# image tags in compose.yaml.
SUITE_COMMIT=7d420f716e49d44f8a6b04f0a3e240ad6d68ab55 # release-v5.3.3
RUNNER_SCRIPTS=(
	"run-test-plan.py 6c05407adf6f381564babf760db1d4d0904a242d86a52b0726bcd3c41da7ab4e"
	"conformance.py 660214cc6ca9b3c09297f61908a575db7b1552e8f44eecd5740d1c27fa2cfca8"
	"test_plan_parser.py 2b00870b2dc46f1d44d047c715c0ef6978f24ece97a4a9d3b48ceeea8d01830f"
)

# Plans run by default, as "<plan name and variants> <configuration file>".
PLANS=(
	"oidcc-config-certification-test-plan config/clavis-oidcc.json"
)

compose() {
	docker compose --file compose.yaml --profile runner "$@"
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d ' ' -f 1
	else
		shasum -a 256 "$1" | cut -d ' ' -f 1
	fi
}

# fetch_runner downloads the suite's runner scripts at SUITE_COMMIT and checks
# them against the pinned digests.
fetch_runner() {
	# run-test-plan.py loads mTLS client certificates from certs-keys/, which
	# the OpenID Connect plans do not use, so the directory stays empty.
	mkdir -p .cache/runner/certs-keys
	local entry name sum path
	for entry in "${RUNNER_SCRIPTS[@]}"; do
		read -r name sum <<<"$entry"
		path=.cache/runner/$name
		if [ -f "$path" ] && [ "$(sha256 "$path")" = "$sum" ]; then
			continue
		fi
		curl --fail --silent --show-error --location --output "$path.tmp" \
			"https://gitlab.com/openid/conformance-suite/-/raw/$SUITE_COMMIT/scripts/$name"
		if [ "$(sha256 "$path.tmp")" != "$sum" ]; then
			echo "run.sh: $name does not match its pinned SHA-256" >&2
			rm -f "$path.tmp"
			exit 1
		fi
		mv "$path.tmp" "$path"
	done
}

# build_clavis builds a static Linux binary of the current commit for the
# Docker host's architecture.
build_clavis() {
	local arch
	arch=$(docker version --format '{{.Server.Arch}}')
	CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o .cache/clavis ../cmd/clavis
}

cleanup() {
	local status=$?
	mkdir -p results
	compose logs --no-color clavis clavis-tls >results/clavis.log 2>&1 || true
	compose logs --no-color server nginx >results/suite.log 2>&1 || true
	if [ "${KEEP:-0}" != 1 ]; then
		compose down --volumes --remove-orphans >/dev/null 2>&1 || true
	fi
	exit "$status"
}

fetch_runner
build_clavis
rm -rf results
export CLAVIS_KEYS_ENCRYPTION_KEY
CLAVIS_KEYS_ENCRYPTION_KEY=$(openssl rand -base64 32)

trap cleanup EXIT
compose up --detach --quiet-pull mongodb server nginx clavis clavis-tls

args=("$@")
if [ ${#args[@]} -eq 0 ]; then
	for plan in "${PLANS[@]}"; do
		read -r name config <<<"$plan"
		args+=("$name" "$config")
	done
fi
# The services are already up; --no-deps keeps compose from recreating them.
compose run --rm --no-deps --quiet-pull runner "${args[@]}"
