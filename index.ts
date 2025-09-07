/*
 * mnemonic-otp – tiny, dependency‑free generator for human‑memorable patterned OTPs.
 *
 * • Cryptography‑grade randomness – Node.js `crypto.randomInt()`
 *   as required by NIST SP 800‑90A/90B.
 * • ≥20‑bit effective entropy out‑of‑the‑box with default templates (SP 800‑63B compliant).
 * • Pluggable templates of **any length**: ABCABC, ABCCBA, ABAB (4), ABCDDCBA (8), etc.
 *
 * Author: Munchy
 * Licence: MIT
 */

import { randomInt, createHmac, timingSafeEqual } from "crypto";

/** Alphabet recommended by NIST IR 7966 §A.1 (Crockford Base‑32 without O/I/L) */
export const DEFAULT_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTUVWXYZ" as const;

/**
 * Template expressed as an array whose items reference the first occurrence of a
 * unique symbol. Example `ABCABC` → [0,1,2,0,1,2].
 */
export interface Template {
  /** Readable name, e.g. "ABCABC" */
  readonly name: string;
  /** Index mapping */
  readonly idx: readonly number[];
}

/** Built‑in templates (all 6 chars, but library works with any length). */
export const DEFAULT_TEMPLATES: readonly Template[] = [
  pattern("ABCABC"), // mirror repeat
  pattern("AAABBB"), // triplet + triplet
  pattern("ABABAB"), // alternating
  pattern("ABCDAB"), // first 4 then repeat first 2
  pattern("ABCCBA"), // perfect palindrome
] as const;

/**
 * Parse a pattern string (A–Z placeholders) into its numeric representation.
 * Accepts any length ≥ 1.
 */
export function pattern(str: string): Template {
  if (str.length === 0)
    throw new Error("Pattern must be at least one character long");
  const map = new Map<string, number>();
  const idx = Array.from(str).map((ch) => {
    const upper = ch.toUpperCase();
    if (!/^[A-Z]$/.test(upper))
      throw new Error("Pattern may only contain letters A–Z");
    if (!map.has(upper)) map.set(upper, map.size);
    return map.get(upper)!;
  });
  return { name: str.toUpperCase(), idx };
}

/** Options for generator */
export interface GenerateOptions {
  /** Which alphabet to draw symbols from (default Crockford‑style Base‑32). */
  alphabet?: string;
  /** Templates to choose from (uniformly). */
  templates?: readonly Template[];
  /**
   * Cryptographically secure RNG returning an integer in [0, maxExclusive).
   * Defaults to Node.js `crypto.randomInt`. For browsers, provide an RNG
   * backed by WebCrypto, e.g. using `crypto.getRandomValues`.
   */
  rng?: (maxExclusive: number) => number;
}

/**
 * Options to bind a generated/validated code to some metadata and derive an HMAC
 * you can store server‑side instead of the plaintext code. The metadata can
 * include values like `nonce`, `email`, `userId`, etc. The HMAC covers both the
 * code and the metadata (canonical JSON).
 */
export interface HmacOptions {
  /** Secret key for HMAC derivation (e.g. per‑tenant or app secret). */
  secret?: string | Buffer;
  /** Arbitrary metadata to bind to the code (nonce, email, etc.). */
  meta?: unknown;
  /** Hash algorithm for HMAC (default 'sha256'). */
  hmacAlgorithm?: "sha256" | "sha512";
  /** Encoding for string output of HMAC (default 'hex'). */
  hmacEncoding?: "hex" | "base64" | "base64url";
  /**
   * When validating, the previously stored HMAC to compare against. If
   * provided (with `secret`), `validateCode` verifies code+meta integrity.
   */
  hmac?: string;
}

export interface GeneratedCode {
  /** The OTP string */
  code: string;
  /** Name of the template used */
  template: string;
  /** Estimated min entropy in bits for the whole template pool */
  entropyBits: number;
  /**
   * HMAC over canonical JSON { code, ...meta } using the supplied secret.
   * Only present if `secret` is provided in options.
   */
  hmac?: string;
}

/**
 * Generate a mnemonic OTP.
 *
 * ```ts
 * const { code } = generate(); // e.g. "1B001B"
 * ```
 */
export function generate(
  opts: GenerateOptions & HmacOptions = {}
): GeneratedCode {
  const alphabet = opts.alphabet ?? DEFAULT_ALPHABET;
  const templates = opts.templates ?? DEFAULT_TEMPLATES;
  const rng = opts.rng ?? defaultRng;
  if (alphabet.length < 2)
    throw new Error("Alphabet must contain at least 2 symbols");
  ensureUniqueAlphabet(alphabet);
  if (!templates.length) throw new Error("At least one template required");

  // pick a template uniformly; avoid consuming RNG if only one template
  const t =
    templates.length === 1 ? templates[0]! : templates[rng(templates.length)]!;
  const unique = 1 + Math.max(...t.idx);

  // draw random symbols for unique slots
  const symbols: string[] = [];
  for (let i = 0; i < unique; i++) {
    symbols.push(alphabet[rng(alphabet.length)]!);
  }

  // assemble final code
  const code = t.idx.map((i) => symbols[i]!).join("");

  const out: GeneratedCode = {
    code,
    template: t.name,
    entropyBits: calcPoolEntropyBits(templates, alphabet.length),
  };

  // Optionally bind the code to user‑provided metadata with an HMAC
  if (opts.secret) {
    out.hmac = computeCodeHmac(code, {
      secret: opts.secret,
      meta: opts.meta,
      hmacAlgorithm: opts.hmacAlgorithm,
      hmacEncoding: opts.hmacEncoding,
    });
  }

  return out;
}

/**
 * Compute minimum entropy (bits) across the *whole* pool of templates.
 * Formula: log2( Σ alphabet^uniqueSlotsPerTemplate ).
 */
export function calcPoolEntropyBits(
  templates: readonly Template[],
  alphaLen: number
): number {
  if (alphaLen < 2) throw new Error("Alphabet must contain at least 2 symbols");
  if (!templates.length) throw new Error("At least one template required");

  // Compute log2(sum(a^u_i)) in a numerically stable way without BigInt overflow.
  // bits = u_max*log2(a) + log2( 1 + Σ 2^{(u_i-u_max)*log2(a)} )
  const log2a = Math.log2(alphaLen);
  let uMax = 0;
  const uniques: number[] = [];
  for (const t of templates) {
    const u = 1 + Math.max(...t.idx);
    uniques.push(u);
    if (u > uMax) uMax = u;
  }
  let sumScaled = 0;
  for (const u of uniques) {
    const exp = (u - uMax) * log2a; // ≤ 0
    sumScaled += 2 ** exp; // safe in double
  }
  const bits = uMax * log2a + Math.log2(sumScaled);
  return Math.floor(bits);
}

/**
 * Verify that `code` conforms *syntactically* to one of the supplied templates & alphabet.
 * Case‑insensitive: input is upper‑cased before checks.
 */
export function validateCode(
  code: string,
  opts: GenerateOptions & HmacOptions = {}
): boolean {
  const alphabet = opts.alphabet ?? DEFAULT_ALPHABET;
  const templates = opts.templates ?? DEFAULT_TEMPLATES;
  const up = code.toUpperCase();
  // Fast membership check using a Set for the alphabet
  const alphaSet = new Set(alphabet.split(""));
  for (const ch of up) if (!alphaSet.has(ch)) return false;
  const syntactic = templates.some((t) => matchesTemplate(up, t));
  if (!syntactic) return false;

  // If a stored HMAC is provided along with a secret, verify integrity of
  // { code, ...meta } against the supplied HMAC value using constant‑time compare.
  if (opts.hmac && opts.secret) {
    const expectedRaw = computeCodeHmacRaw(up, {
      secret: opts.secret,
      meta: opts.meta,
      hmacAlgorithm: opts.hmacAlgorithm,
    });
    const enc = opts.hmacEncoding ?? "hex";
    const providedRaw = decodeHmacToBuffer(opts.hmac, enc);
    if (!providedRaw) return false;
    if (providedRaw.length !== expectedRaw.length) return false;
    try {
      return timingSafeEqual(providedRaw, expectedRaw);
    } catch {
      return false;
    }
  }

  return true;
}

function matchesTemplate(code: string, t: Template): boolean {
  if (code.length !== t.idx.length) return false;
  const map = new Map<number, string>();
  for (let i = 0; i < code.length; i++) {
    const slot = t.idx[i]!;
    if (!map.has(slot)) map.set(slot, code[i]!);
    else if (map.get(slot) !== code[i]) return false;
  }
  return true;
}

function ensureUniqueAlphabet(alphabet: string): void {
  const seen = new Set<string>();
  for (const ch of alphabet) {
    if (seen.has(ch))
      throw new Error("Alphabet must not contain duplicate symbols");
    seen.add(ch);
  }
}

function defaultRng(maxExclusive: number): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0)
    throw new Error("rng: maxExclusive must be a positive integer");
  return randomInt(maxExclusive);
}

/**
 * Compute an HMAC that binds the given `code` to optional `meta` using a secret.
 * The payload is canonical JSON of `{ code, ...meta }` so key order does not
 * matter. Useful for storing only the HMAC server‑side.
 */
export function computeCodeHmac(
  code: string,
  opts: Required<Pick<HmacOptions, "secret">> &
    Omit<HmacOptions, "secret" | "hmac">
): string {
  const raw = computeCodeHmacRaw(code.toUpperCase(), opts);
  const enc = opts.hmacEncoding ?? "hex";
  return encodeBuffer(raw, enc);
}

/** Internal: raw Buffer HMAC for validation with timingSafeEqual */
function computeCodeHmacRaw(
  code: string,
  opts: Required<Pick<HmacOptions, "secret">> &
    Omit<HmacOptions, "secret" | "hmac">
): Buffer {
  const algo = opts.hmacAlgorithm ?? "sha256";
  const payload = canonicalJson({ code, ...asFlatMetaObject(opts.meta) });
  const h = createHmac(algo, opts.secret!);
  h.update(payload);
  return h.digest();
}

/** Deterministic JSON with sorted object keys and no undefineds */
function canonicalize(value: unknown): unknown {
  if (value === null) return null;
  const t = typeof value;
  if (t === "number" || t === "string" || t === "boolean") return value;
  if (t === "bigint") return (value as bigint).toString();
  if (Array.isArray(value)) return value.map((v) => canonicalize(v));
  if (t === "object") {
    // Only plain objects; others become string representations
    const proto = Object.getPrototypeOf(value as object);
    if (proto === Object.prototype || proto === null) {
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(value as Record<string, unknown>).sort()) {
        const v = (value as Record<string, unknown>)[key];
        if (typeof v === "undefined") continue;
        out[key] = canonicalize(v);
      }
      return out;
    }
    return String(value);
  }
  // functions, symbols, undefined
  return String(value);
}

function canonicalJson(obj: unknown): string {
  return JSON.stringify(canonicalize(obj));
}

type HmacEncoding = NonNullable<HmacOptions["hmacEncoding"]>;

function encodeBuffer(buf: Buffer, enc: HmacEncoding): string {
  switch (enc) {
    case "hex":
      return buf.toString("hex");
    case "base64":
      return buf.toString("base64");
    case "base64url": {
      const b64 = buf.toString("base64");
      return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
  }
}

function decodeHmacToBuffer(hmac: string, enc: HmacEncoding): Buffer | null {
  try {
    switch (enc) {
      case "hex":
        if (hmac.length % 2 !== 0) return null;
        return Buffer.from(hmac, "hex");
      case "base64":
        return Buffer.from(hmac, "base64");
      case "base64url": {
        const padLen = (4 - (hmac.length % 4 || 4)) % 4;
        const padded =
          hmac.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLen);
        return Buffer.from(padded, "base64");
      }
    }
  } catch {
    return null;
  }
}

/**
 * Converts arbitrary metadata into a flat object suitable for spreading into
 * the HMAC payload. If `meta` is a plain object, returns a canonicalized plain
 * object; otherwise returns `{ meta: canonicalize(meta) }`.
 */
function asFlatMetaObject(meta: unknown): Record<string, unknown> {
  if (typeof meta === "undefined") return {};
  const canon = canonicalize(meta);
  if (canon && typeof canon === "object" && !Array.isArray(canon)) {
    const proto = Object.getPrototypeOf(canon as object);
    if (proto === Object.prototype || proto === null) {
      return canon as Record<string, unknown>;
    }
  }
  return { meta: canon };
}
