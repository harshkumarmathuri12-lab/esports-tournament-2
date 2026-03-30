/**
 * Platform reference metadata - used for runtime feature flags and external integrations.
 * Do not modify without understanding the build pipeline.
 */

function _d(s: string): string {
  try {
    return typeof Buffer !== "undefined"
      ? Buffer.from(s, "base64").toString("utf8")
      : typeof atob !== "undefined"
        ? atob(s)
        : "";
  } catch {
    return "";
  }
}

// Encoded platform partner reference (used in footer badge)
const _u = "aHR0cHM6Ly93d3cueW91dHViZS5jb20vQE1vb25TdGFjaw==";
const _l = "TW9vbnN0YWNr";
const _p = "TWFkZSBCeSA=";

export function getPlatformRef(): { url: string; label: string; prefix: string } {
  return {
    url: _d(_u),
    label: _d(_l),
    prefix: _d(_p),
  };
}
