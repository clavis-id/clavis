// Cloudflare Worker that makes the Go import path clavisid.org/clavis resolve
// to the GitHub repository, as described in `go help importpath` ("Remote
// import paths"). Requests with ?go-get=1 receive the go-import and go-source
// meta tags; browsers are redirected to the repository.

export const IMPORT_ROOT = "clavisid.org/clavis";
export const REPOSITORY = "https://github.com/clavis-id/clavis";
const BRANCH = "master";

// Import paths below the root may only contain these characters, which keeps
// redirect targets and generated HTML free of anything that needs escaping.
const SAFE_SUBPATH = /^(\/[A-Za-z0-9._-]+)*$/;

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'none'",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000",
  "X-Content-Type-Options": "nosniff",
};

export default {
  async fetch(request) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return text(405, "method not allowed", { Allow: "GET, HEAD" });
    }
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "");

    if (path === "") {
      return redirect(REPOSITORY);
    }
    if (path !== "/clavis" && !path.startsWith("/clavis/")) {
      return text(404, "not found");
    }
    const subpath = path.slice("/clavis".length);
    if (!SAFE_SUBPATH.test(subpath)) {
      return text(404, "not found");
    }

    if (url.searchParams.get("go-get") === "1") {
      return new Response(request.method === "HEAD" ? null : page(subpath), {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "public, max-age=3600",
          ...SECURITY_HEADERS,
        },
      });
    }
    return redirect(subpath === "" ? REPOSITORY : `${REPOSITORY}/tree/${BRANCH}${subpath}`);
  },
};

// page returns the HTML read by the go command. Every package below the root
// shares the same metadata: the import root and the repository.
function page(subpath) {
  const source = subpath === "" ? REPOSITORY : `${REPOSITORY}/tree/${BRANCH}${subpath}`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="go-import" content="${IMPORT_ROOT} git ${REPOSITORY}">
<meta name="go-source" content="${IMPORT_ROOT} ${REPOSITORY} ${REPOSITORY}/tree/${BRANCH}{/dir} ${REPOSITORY}/blob/${BRANCH}{/dir}/{file}#L{line}">
<title>${IMPORT_ROOT}${subpath}</title>
</head>
<body>
<p>Source code: <a href="${source}">${source}</a></p>
</body>
</html>
`;
}

function redirect(location) {
  return new Response(null, {
    status: 302,
    headers: { Location: location, "Cache-Control": "public, max-age=3600", ...SECURITY_HEADERS },
  });
}

function text(status, message, extra = {}) {
  return new Response(`${message}\n`, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", ...SECURITY_HEADERS, ...extra },
  });
}
