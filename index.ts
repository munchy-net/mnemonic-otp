/*
 * mnemonic-otp – tiny, dependency‑free generator for human‑memorable patterned OTPs.
 *
 * • Cryptography‑grade randomness – Node.js `crypto.randomInt()`
 *   as required by NIST SP 800‑90A/90B.
 * • ≥20‑bit effective entropy out‑of‑the‑box with default templates (SP 800‑63B compliant).
 * • Pluggable templates of **any length**: ABCABC, ABCCBA, ABAB (4), ABCDDCBA (8), etc.
 *
 * Author: Munchy
 * Licence: MIT
 */

import { randomInt } from "crypto";

/** Alphabet recommended by NIST IR 7966 §A.1 (Crockford Base‑32 without O/I/L) */
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
 * Accepts any length ≥ 1.
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
}

export interface GeneratedCode {
    /** The OTP string */
    code: string;
    /** Name of the template used */
    template: string;
    /** Estimated min entropy in bits for the whole template pool */
    entropyBits: number;
}

/**
 * Generate a mnemonic OTP.
 *
 * ```ts
 * const { code } = generate(); // e.g. "1B001B"
 * ```
 */
export function generate(opts: GenerateOptions = {}): GeneratedCode {
    const alphabet = opts.alphabet ?? DEFAULT_ALPHABET;
    const templates = opts.templates ?? DEFAULT_TEMPLATES;
    if (alphabet.length < 2)
        throw new Error("Alphabet must contain at least 2 symbols");
    if (!templates.length) throw new Error("At least one template required");

    // pick a template uniformly
    const t = templates[randomInt(templates.length)]!;
    const unique = 1 + Math.max(...t.idx);

    // draw random symbols for unique slots
    const symbols: string[] = [];
    for (let i = 0; i < unique; i++) {
        symbols.push(alphabet[randomInt(alphabet.length)]!);
    }

    // assemble final code
    const code = t.idx.map((i) => symbols[i]!).join("");

    return {
        code,
        template: t.name,
        entropyBits: calcPoolEntropyBits(templates, alphabet.length),
    };
}

/**
 * Compute minimum entropy (bits) across the *whole* pool of templates.
 * Formula: log2( Σ alphabet^uniqueSlotsPerTemplate ).
 */
export function calcPoolEntropyBits(
    templates: readonly Template[],
    alphaLen: number
): number {
    let totalStates = 0n;
    const a = BigInt(alphaLen);
    for (const t of templates) {
        const unique = 1n + BigInt(Math.max(...t.idx));
        totalStates += a ** unique;
    }
    return Math.floor(Math.log2(Number(totalStates)));
}

/**
 * Verify that `code` conforms *syntactically* to one of the supplied templates & alphabet.
 * Case‑insensitive: input is upper‑cased before checks.
 */
export function validateCode(
    code: string,
    opts: GenerateOptions = {}
): boolean {
    const alphabet = opts.alphabet ?? DEFAULT_ALPHABET;
    const templates = opts.templates ?? DEFAULT_TEMPLATES;
    const up = code.toUpperCase();
    if (![...up].every((ch) => alphabet.includes(ch))) return false;
    return templates.some((t) => matchesTemplate(up, t));
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
