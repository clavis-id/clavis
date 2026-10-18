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
# The configuration is generated from config/clavis-oidcc.json with the
# secrets of the clients and user that setup_clavis creates.
PLANS=(
	"oidcc-config-certification-test-plan .cache/clavis-oidcc.json"
	"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] .cache/clavis-oidcc.json"
)

# Redirect URI of the suite's clients for the alias in the configuration.
REDIRECT_URI=https://localhost.emobix.co.uk:8443/test/a/clavis/callback

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

# clavis runs the CLI inside the running Clavis container, against its
# database. The image has no shell, but exec runs the binary directly.
clavis() {
	compose exec -T clavis /clavis "$@"
}

# setup_clavis waits for Clavis, creates the clients and the user the plans
# use, and writes the configuration with their secrets. The clients are
# exempt from PKCE (ADR 0018): the suite sends PKCE in one test only.
setup_clavis() {
	local i secret1 secret2 email password
	for i in $(seq 1 60); do
		if compose exec -T clavis-tls wget -q -O /dev/null http://clavis:8080/readyz 2>/dev/null; then
			break
		fi
		if [ "$i" = 60 ]; then
			echo "run.sh: Clavis did not become ready" >&2
			exit 1
		fi
		sleep 1
	done
	secret1=$(create_client conformance-1)
	secret2=$(create_client conformance-2)
	if [ -z "$secret1" ] || [ -z "$secret2" ]; then
		echo "run.sh: creating the conformance clients printed no secret" >&2
		exit 1
	fi
	email=conformance@clavis.test
	password=$(openssl rand -hex 16)
	printf '%s\n' "$password" | clavis users create "$email" --with-password --email-verified \
		--name "Conformance User" --given-name Conformance --family-name User >/dev/null
	sed -e "s|\${CLIENT_SECRET_1}|$secret1|g" -e "s|\${CLIENT_SECRET_2}|$secret2|g" \
		-e "s|\${USER_EMAIL}|$email|g" -e "s|\${USER_PASSWORD}|$password|g" \
		config/clavis-oidcc.json >.cache/clavis-oidcc.json
}

# create_client registers a confidential client and prints its secret.
create_client() {
	clavis clients create --client-id "$1" --name "Conformance $1" --redirect-uri "$REDIRECT_URI" \
		--scope openid --scope profile --scope email --scope address --scope phone --scope offline_access \
		--pkce-exempt |
		sed -n 's/^Client secret: //p'
}

fetch_runner
build_clavis
rm -rf results
# Created here so the caller owns it. The runner container runs as root, and on
# Linux a directory it creates belongs to root, so cleanup could not write the
# service logs into it.
mkdir results
export CLAVIS_KEYS_ENCRYPTION_KEY
CLAVIS_KEYS_ENCRYPTION_KEY=$(openssl rand -base64 32)

trap cleanup EXIT
compose up --detach --quiet-pull mongodb server nginx clavis clavis-tls
setup_clavis

args=("$@")
if [ ${#args[@]} -eq 0 ]; then
	for plan in "${PLANS[@]}"; do
		read -r name config <<<"$plan"
		args+=("$name" "$config")
	done
fi
# The services are already up; --no-deps keeps compose from recreating them.
compose run --rm --no-deps --quiet-pull runner "${args[@]}"
