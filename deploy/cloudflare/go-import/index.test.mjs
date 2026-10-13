// Run with: node --test deploy/cloudflare/go-import/index.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";

import worker, { IMPORT_ROOT, REPOSITORY } from "./index.mjs";

const get = (path, init) => worker.fetch(new Request(`https://clavisid.org${path}`, init));
const goImport = `<meta name="go-import" content="${IMPORT_ROOT} git ${REPOSITORY}">`;

test("serves go-import metadata for the root and every package", async () => {
  for (const path of ["/clavis", "/clavis/", "/clavis/store/sqlite", "/clavis/tools/golangci-lint"]) {
    const res = await get(`${path}?go-get=1`);
    assert.equal(res.status, 200, path);
    assert.match(res.headers.get("Content-Type"), /^text\/html/);
    const body = await res.text();
    assert.ok(body.includes(goImport), `${path} lacks the go-import tag`);
    assert.ok(body.includes('<meta name="go-source"'), `${path} lacks the go-source tag`);
  }
});

test("redirects browsers to the repository", async () => {
  const cases = {
    "/": REPOSITORY,
    "/clavis": REPOSITORY,
    "/clavis/store/sqlite": `${REPOSITORY}/tree/master/store/sqlite`,
  };
  for (const [path, location] of Object.entries(cases)) {
    const res = await get(path);
    assert.equal(res.status, 302, path);
    assert.equal(res.headers.get("Location"), location, path);
  }
});

test("rejects unknown paths and unsafe characters", async () => {
  for (const path of ["/clavisx", "/other", "/clavis/a%22b", "/clavis/%3Cscript%3E", "/clavis/a b"]) {
    const res = await get(`${path}?go-get=1`);
    assert.equal(res.status, 404, path);
  }
});

test("allows only GET and HEAD", async () => {
  const res = await get("/clavis?go-get=1", { method: "POST" });
  assert.equal(res.status, 405);
  assert.equal(res.headers.get("Allow"), "GET, HEAD");

  const head = await get("/clavis?go-get=1", { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");
});

test("sends security headers", async () => {
  const res = await get("/clavis?go-get=1");
  assert.equal(res.headers.get("Content-Security-Policy"), "default-src 'none'");
  assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
});
