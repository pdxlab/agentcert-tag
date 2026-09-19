/**
 * @trustmodel/agentcert-tag — verify an AgentCert + TrustScore inside a TypeScript MCP server.
 *
 * The verification decision is made by a TAG verify endpoint (a local sidecar or a hosted
 * endpoint); this package is a thin, dependency-free client + gate you drop in front of your
 * tool calls. Off by default; shadow mode (log, never block) when on. Safe to merge.
 *
 *   import { verifyGate, extractToken } from "@trustmodel/agentcert-tag";
 *   const guard = verifyGate({ mode: "shadow" });
 *   // inside your tool-call handler:
 *   await guard(extractToken(request.headers));   // logs (shadow) / throws (enforce)
 *
 * Env: TRUSTMODEL_VERIFY=1 (enable), TRUSTMODEL_VERIFY_URL, TRUSTMODEL_MODE=enforce.
 */

export type Verdict = "VERIFIED" | "REVOKED" | "UNVERIFIED" | "EXPIRED" | "ERROR" | "DISABLED";

export interface VerificationResult {
  verification_status: Verdict;
  agent_id?: string;
  cert_valid?: boolean;
  trust_score?: { value: number | null; tier: string };
  detail?: string;
}

export interface VerifyGateOptions {
  /** shadow (default): log, never block. enforce: throw on a blocked verdict. */
  mode?: "shadow" | "enforce";
  /** Verdicts that block in enforce mode. Default ["REVOKED","UNVERIFIED"]. */
  blockOn?: Verdict[];
  /** TAG verify endpoint. Default env TRUSTMODEL_VERIFY_URL or http://localhost:8080/verify. */
  verifyUrl?: string;
  /** On backend error in enforce mode: closed (default) blocks, open passes. */
  failMode?: "open" | "closed";
  /** Called with every result (shadow or enforce). Must not throw. */
  onResult?: (r: VerificationResult) => void;
}

const DEFAULT_HEADER = "x-agentcert-token";
const DEFAULT_URL = "http://localhost:8080/verify";
const DEFAULT_BLOCK: Verdict[] = ["REVOKED", "UNVERIFIED"];

export class VerifyError extends Error {
  result: VerificationResult;
  constructor(result: VerificationResult) {
    super(`agentcert-tag blocked: ${result.verification_status} (${result.detail ?? ""})`);
    this.name = "VerifyError";
    this.result = result;
  }
}

function enabled(): boolean {
  return process.env.TRUSTMODEL_VERIFY === "1";
}

/** Case-insensitive lookup of the AgentCert credential header. */
export function extractToken(
  headers: Record<string, string | string[] | undefined> | undefined,
  header: string = DEFAULT_HEADER
): string | undefined {
  if (!headers) return undefined;
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === header.toLowerCase()) {
      const v = headers[k];
      return Array.isArray(v) ? v[0] : v;
    }
  }
  return undefined;
}

/** POST the credential to the TAG verify endpoint. Never throws — transport failures
 * become an ERROR verdict so the caller's fail policy decides. */
export async function verify(token: string | undefined, verifyUrl?: string): Promise<VerificationResult> {
  const url = verifyUrl ?? process.env.TRUSTMODEL_VERIFY_URL ?? DEFAULT_URL;
  if (!token) {
    return { verification_status: "UNVERIFIED", cert_valid: false, detail: "no credential presented" };
  }
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ credential: token }),
    });
    if (!res.ok) return { verification_status: "ERROR", detail: `verify HTTP ${res.status}` };
    return (await res.json()) as VerificationResult;
  } catch (e) {
    return { verification_status: "ERROR", detail: `verify unreachable: ${(e as Error).message}` };
  }
}

/**
 * Build a guard(token) you call in your tool-call path.
 * - No-op unless TRUSTMODEL_VERIFY=1.
 * - shadow: logs, resolves. enforce: rejects with VerifyError on a blocked verdict.
 */
export function verifyGate(opts: VerifyGateOptions = {}): (token: string | undefined) => Promise<VerificationResult> {
  const mode = process.env.TRUSTMODEL_MODE === "enforce" ? "enforce" : opts.mode ?? "shadow";
  const block = new Set<Verdict>(opts.blockOn ?? DEFAULT_BLOCK);
  const failMode = opts.failMode ?? "closed";

  return async (token: string | undefined): Promise<VerificationResult> => {
    if (!enabled()) return { verification_status: "DISABLED" };
    const result = await verify(token, opts.verifyUrl);
    // eslint-disable-next-line no-console
    console.error(
      `[agentcert-tag] mode=${mode} status=${result.verification_status} ` +
        `score=${result.trust_score?.value ?? "-"} tier=${result.trust_score?.tier ?? "-"}`
    );
    if (opts.onResult) {
      try {
        opts.onResult(result);
      } catch {
        /* a callback must never break the request */
      }
    }
    if (mode === "enforce") {
      const bad = block.has(result.verification_status) || (result.verification_status === "ERROR" && failMode === "closed");
      if (bad) throw new VerifyError(result);
    }
    return result;
  };
}
