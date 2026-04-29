// Short, human-readable explanations for the HTTP status codes that
// show up most often inside finding messages (Nikto-style "(HTTP 308)",
// "returned 404", etc.). Kept intentionally small — the goal is a quick
// "what does that number mean" hint next to the message, not an RFC
// excerpt.

export interface HttpStatusInfo {
  code: number;
  title: string;
  /** One-sentence plain-English summary suitable for a tooltip-sized line. */
  summary: string;
}

const TABLE: Record<number, { title: string; summary: string }> = {
  // 1xx informational
  100: { title: "Continue", summary: "The server received the request headers and the client should send the body." },
  101: { title: "Switching Protocols", summary: "The server is switching to the protocol the client requested (e.g. WebSocket upgrade)." },

  // 2xx success
  200: { title: "OK", summary: "Request succeeded; the response body contains the resource." },
  201: { title: "Created", summary: "The request succeeded and a new resource was created." },
  202: { title: "Accepted", summary: "Request accepted for processing, but not yet completed." },
  204: { title: "No Content", summary: "Request succeeded; the server returned no body." },
  206: { title: "Partial Content", summary: "Server is delivering only part of the resource (range request)." },

  // 3xx redirection
  300: { title: "Multiple Choices", summary: "The resource has multiple representations; the client must pick one." },
  301: { title: "Moved Permanently", summary: "The resource has a new permanent URL — clients should update bookmarks." },
  302: { title: "Found", summary: "Temporary redirect; the resource is at another URL for now." },
  303: { title: "See Other", summary: "Redirect to another URL using GET (commonly after a POST)." },
  304: { title: "Not Modified", summary: "Cached copy is still valid; no body returned." },
  307: { title: "Temporary Redirect", summary: "Temporary redirect that preserves the original method and body." },
  308: { title: "Permanent Redirect", summary: "Permanent redirect that preserves the original method and body." },

  // 4xx client errors
  400: { title: "Bad Request", summary: "The server could not parse the request — malformed syntax or invalid framing." },
  401: { title: "Unauthorized", summary: "Authentication is required or the supplied credentials were rejected." },
  403: { title: "Forbidden", summary: "The server understood the request but refuses to authorize it." },
  404: { title: "Not Found", summary: "The server has no resource at this URL." },
  405: { title: "Method Not Allowed", summary: "The HTTP method isn't allowed for this resource." },
  406: { title: "Not Acceptable", summary: "No representation matches the client's Accept headers." },
  407: { title: "Proxy Authentication Required", summary: "The client must authenticate with a proxy first." },
  408: { title: "Request Timeout", summary: "The server timed out waiting for the client to finish the request." },
  409: { title: "Conflict", summary: "The request conflicts with the current state of the resource." },
  410: { title: "Gone", summary: "The resource was deliberately removed and won't return." },
  411: { title: "Length Required", summary: "The server requires a Content-Length header." },
  413: { title: "Payload Too Large", summary: "Request body exceeds the size the server is willing to process." },
  414: { title: "URI Too Long", summary: "The request URI is longer than the server will accept." },
  415: { title: "Unsupported Media Type", summary: "The server doesn't accept this Content-Type." },
  418: { title: "I'm a teapot", summary: "Joke status from RFC 2324 — sometimes used as a placeholder/honeypot response." },
  422: { title: "Unprocessable Entity", summary: "The body parses but is semantically invalid (common in JSON APIs)." },
  425: { title: "Too Early", summary: "Server is unwilling to risk processing a replayed request." },
  426: { title: "Upgrade Required", summary: "The client should switch to a different protocol (e.g. TLS, HTTP/2)." },
  428: { title: "Precondition Required", summary: "The server requires the request to be conditional (e.g. If-Match)." },
  429: { title: "Too Many Requests", summary: "Rate limit hit — the client is sending requests too fast." },
  431: { title: "Request Header Fields Too Large", summary: "One or more request headers are too large to process." },
  451: { title: "Unavailable For Legal Reasons", summary: "Resource is blocked due to a legal demand (court order, takedown)." },

  // 5xx server errors
  500: { title: "Internal Server Error", summary: "The server hit an unexpected error while handling the request." },
  501: { title: "Not Implemented", summary: "The server doesn't support the functionality required to fulfill the request." },
  502: { title: "Bad Gateway", summary: "An upstream server returned an invalid response to this gateway." },
  503: { title: "Service Unavailable", summary: "The server is temporarily overloaded or down for maintenance." },
  504: { title: "Gateway Timeout", summary: "An upstream server didn't respond in time." },
  505: { title: "HTTP Version Not Supported", summary: "The server doesn't support the HTTP version of the request." },
  511: { title: "Network Authentication Required", summary: "The client must authenticate to gain network access (captive portal)." },
};

export function lookupHttpStatus(code: number): HttpStatusInfo | undefined {
  const entry = TABLE[code];
  if (!entry) return undefined;
  return { code, title: entry.title, summary: entry.summary };
}

// Pull HTTP status codes referenced inside a free-form finding message.
// Recognised forms (case-insensitive):
//   - "HTTP 404", "HTTP/1.1 404", "(HTTP 308)"
//   - "status 500", "code 401", "returned 403", "returned a 404",
//     "responded with 502", "got 429", "received a 503"
// Bare three-digit numbers without one of those cues are deliberately
// ignored — finding messages contain plenty of unrelated numbers
// (counts, ports, byte sizes) and a naive scan would flag them as
// status codes.
const STATUS_PATTERNS: RegExp[] = [
  /\bHTTP\s*\/?\s*(?:\d\.\d\s+)?(\d{3})\b/gi,
  /\b(?:status(?:\s+code)?|code|response(?:\s+code)?)\s+(?:was\s+|of\s+|=\s*)?(\d{3})\b/gi,
  /\b(?:returned|responded(?:\s+with)?|replied(?:\s+with)?|got|received|sent\s+back)\s+(?:a\s+|an\s+|with\s+)?(\d{3})\b/gi,
];

export function extractStatusCodes(message: string | null | undefined): HttpStatusInfo[] {
  if (!message) return [];
  const seen = new Set<number>();
  const out: HttpStatusInfo[] = [];
  for (const pattern of STATUS_PATTERNS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(message)) !== null) {
      const code = Number(m[1]);
      if (!Number.isFinite(code) || code < 100 || code > 599) continue;
      if (seen.has(code)) continue;
      seen.add(code);
      const info = lookupHttpStatus(code);
      if (info) out.push(info);
    }
  }
  return out;
}
