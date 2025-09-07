// e2e.test.ts - Bun test runner
import { describe, expect, test } from "bun:test";
import {
  DEFAULT_ALPHABET,
  DEFAULT_TEMPLATES,
  pattern,
  generate,
  validateCode,
  calcPoolEntropyBits,
  type Template,
} from "./index";

// Strong pack (≈30-36 bits with Base32)
const STRONG_TEMPLATES: readonly Template[] = [
  pattern("ABCDEFAB"),
  pattern("ABCDABEF"),
  pattern("ABCAEFBG"),
  pattern("ABCDEFAH"),
  pattern("ABCDGEFA"),
  pattern("ABACDEFG"),
] as const;

function approxBits(templates = DEFAULT_TEMPLATES) {
  return calcPoolEntropyBits(templates, DEFAULT_ALPHABET.length);
}

describe("mnemonic-otp", () => {
  test("quick start example works", () => {
    const { code } = generate();
    expect(typeof code).toBe("string");
    expect(code.length).toBeGreaterThan(0);
    expect(validateCode(code)).toBeTrue();
  });

  test("entropy - default pack >= 20 bits", () => {
    expect(approxBits()).toBeGreaterThanOrEqual(20);
    expect(approxBits()).toBeLessThan(21);
  });

  test("entropy - strong pack >= 30 bits", () => {
    expect(approxBits(STRONG_TEMPLATES)).toBeGreaterThanOrEqual(30);
  });

  test("deterministic rng matches ABCABC pattern", () => {
    let seq = 0;
    const rngDet = (max: number) => seq++ % max;
    const g1 = generate({ rng: rngDet, templates: [pattern("ABCABC")] });
    expect(g1.code.length).toBe(6);
    const a = DEFAULT_ALPHABET;
    const expected = `${a[0]}${a[1]}${a[2]}${a[0]}${a[1]}${a[2]}`;
    expect(g1.code).toBe(expected);
  });

  test("syntactic validation ok and fail cases", () => {
    const { code } = generate({ templates: [pattern("ABCABC")] });
    expect(validateCode(code, { templates: [pattern("ABCABC")] })).toBeTrue();
    expect(
      validateCode("ZZZZZX", { templates: [pattern("ABCABC")] })
    ).toBeFalse();
  });

  test("randomness sanity - low duplicate rate across 5k codes", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 5000; i++) {
      const { code } = generate({ templates: STRONG_TEMPLATES });
      seen.add(code);
    }
    expect(seen.size).toBeGreaterThan(4900);
  });

  test("HMAC binding - valid hmac verifies", () => {
    const secret = Buffer.from("supersecretkey-supersecretkey", "utf8");
    const meta = {
      email: "user@example.com",
      purpose: "login",
      attemptId: "123e4567-e89b-12d3-a456-426614174000",
      attemptNonce: "4f1b2c3d4e5f60718293a4b5c6d7e8f9",
      issuedAt: 1736200000000,
    };
    const { code, hmac } = generate({
      templates: STRONG_TEMPLATES,
      secret,
      meta,
      hmacEncoding: "base64url",
    });
    expect(!!hmac && hmac.length > 16).toBeTrue();
    const ok = validateCode(code, {
      templates: STRONG_TEMPLATES,
      secret,
      meta,
      hmac,
      hmacEncoding: "base64url",
    });
    expect(ok).toBeTrue();
  });

  test("HMAC binding - wrong meta or code fails", () => {
    const secret = Buffer.from("supersecretkey-supersecretkey", "utf8");
    const meta = {
      email: "user@example.com",
      purpose: "login",
      attemptId: "123e4567-e89b-12d3-a456-426614174000",
      attemptNonce: "4f1b2c3d4e5f60718293a4b5c6d7e8f9",
      issuedAt: 1736200000000,
    };
    const { code, hmac } = generate({
      templates: STRONG_TEMPLATES,
      secret,
      meta,
      hmacEncoding: "base64url",
    });
    const bad = validateCode(code, {
      templates: STRONG_TEMPLATES,
      secret,
      meta: { ...meta, attemptNonce: "deadbeef" },
      hmac,
      hmacEncoding: "base64url",
    });
    expect(bad).toBeFalse();

    const bad2 = validateCode(code.slice(0, -1) + "A", {
      templates: STRONG_TEMPLATES,
      secret,
      meta,
      hmac,
      hmacEncoding: "base64url",
    });
    expect(bad2).toBeFalse();
  });

  test("self-acceptance - library always accepts its own outputs", () => {
    for (let i = 0; i < 1000; i++) {
      const g = generate({ templates: STRONG_TEMPLATES });
      expect(validateCode(g.code, { templates: STRONG_TEMPLATES })).toBeTrue();
    }
  });
});
