#!/bin/sh
# Entry point of the runner container (see compose.yaml). Installs the
# hash-pinned dependencies of the suite's runner scripts, waits until Clavis is
# ready and runs the test plans given as arguments.
set -eu

python -m pip install --quiet --no-cache-dir --root-user-action=ignore \
	--require-hashes --only-binary=:all: -r requirements.txt

python - <<'EOF'
import os
import ssl
import sys
import time
import urllib.request

url = os.environ["CLAVIS_READY_URL"]
# The certificate comes from Caddy's internal CA, which is not trusted here.
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
deadline = time.monotonic() + 120
while True:
    try:
        with urllib.request.urlopen(url, context=ctx, timeout=5) as response:
            if response.status == 200:
                break
            problem = f"HTTP {response.status}"
    except Exception as e:  # Keep polling until the deadline.
        problem = str(e)
    if time.monotonic() > deadline:
        sys.exit(f"Clavis did not become ready at {url}: {problem}")
    time.sleep(1)
EOF

mkdir -p results
exec python .cache/runner/run-test-plan.py --verbose \
	--expected-failures-file expected-failures.json \
	--expected-skips-file expected-skips.json \
	--export-dir results \
	"$@"
