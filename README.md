# mnemonic-otp

A tiny, dependency‑free TypeScript library for generating human‑memorable patterned One‑Time Passwords (OTPs).

## Features

- **Cryptographically Secure**: Uses Node.js `crypto.randomInt()` as required by NIST SP 800‑90A/90B (or pluggable RNG)
- **Human-Memorable**: Generates codes with memorable patterns like `1B001B`, `AAA999`, `A1B2A1`
- **Configurable Length**: Support for templates of any length (4, 6, 8+ characters)
- **NIST Compliant**: ≥20-bit effective entropy out-of-the-box (SP 800-63B compliant)
- **Pluggable Templates**: Use built-in patterns or create your own
- **Zero Dependencies**: Lightweight with no external dependencies
- **TypeScript**: Full TypeScript support with comprehensive types

## Quick Start

```typescript
import { generate, pattern } from './index.ts';

// Simplest usage
const { code } = generate();
console.log(code); // e.g. "1B001B"

// With specific options
const result = generate({
  alphabet: "0123456789ABCDEF", // Hex alphabet
  templates: [pattern("ABCDAB")]  // Custom template
});
console.log(result.code);        // e.g. "1A2B1A"
console.log(result.template);    // "ABCDAB"
console.log(result.entropyBits); // 20
```

## Installation

Using Bun:
```bash
bun install
```

Using npm:
```bash
npm install
```

## API Reference

### `generate(options?): GeneratedCode`

Generates a mnemonic OTP with the specified options.

**Parameters:**
- `options.alphabet` (string, optional): Character set to use. Default: Crockford Base‑32 (`"0123456789ABCDEFGHJKMNPQRSTUVWXYZ"`). Alphabet must contain unique symbols.
- `options.templates` (Template[], optional): Array of templates to choose from. Default: 5 built‑in templates.
- `options.rng` ((max: number) => number, optional): Cryptographically secure RNG returning an integer in `[0, max)`. Defaults to Node’s `crypto.randomInt`. For browsers, provide an RNG backed by WebCrypto.

Additional HMAC options (optional):
- `options.secret` (string | Buffer): When supplied, an HMAC is returned that binds the generated `code` to any `options.meta` you pass.
- `options.meta` (any, optional): Arbitrary metadata (e.g. `{ nonce, email, userId }`) included in the HMAC payload.
- `options.hmacAlgorithm` ("sha256" | "sha512", optional): Default `"sha256"`.
- `options.hmacEncoding` ("hex" | "base64" | "base64url", optional): Default `"hex"`.

The HMAC is computed over canonical JSON of `{ code, ...meta }` (objects are key‑sorted; `undefined` keys omitted).

**Returns:**
- `code`: The generated OTP string
- `template`: Name of the template used
- `entropyBits`: Estimated minimum entropy in bits
 - `hmac` (when `secret` is provided): HMAC string suitable for storing in a database instead of the plaintext code

### `pattern(str: string): Template`

Creates a template from a pattern string using A-Z placeholders.

```typescript
const t1 = pattern("ABCABC"); // Mirror repeat, 3 unique symbols
const t2 = pattern("AAABBB"); // Triplet + triplet, 2 unique symbols
const t3 = pattern("ABCCBA"); // Palindrome, 3 unique symbols
```

### `validateCode(code: string, options?): boolean`

Validates that a code conforms syntactically to the given templates and alphabet.

If you also pass `options.secret` and `options.hmac`, the function additionally verifies the integrity of `{ code, ...options.meta }` using a constant‑time comparison with the provided HMAC. This lets you store only the HMAC server‑side and never the plaintext OTP.

```typescript
const isValidSyntaxOnly = validateCode("1A001A"); // true (matches ABCCBA pattern)
const isValidSyntaxOnly2 = validateCode("1A2B3C"); // false (no matching pattern)

// Generate, bind to metadata (e.g. nonce + email), and store only HMAC
const { code, hmac } = generate({
  secret: process.env.OTP_SECRET!,
  meta: { nonce: "91fdc3", email: "user@example.com" },
});
// Store: { hmac, meta, createdAt, ... }

// Later, verify: caller provides `code` and you look up stored `hmac`+`meta`
const ok = validateCode(code, {
  secret: process.env.OTP_SECRET!,
  hmac, // the value previously stored in DB
  meta: { nonce: "91fdc3", email: "user@example.com" },
});
// ok === true only if both syntax and HMAC match
```

### `calcPoolEntropyBits(templates: Template[], alphabetLength: number): number`

Calculates the minimum entropy bits across all templates in the pool.

Internally uses a numerically stable computation in log‑space (no BigInt overflow), so it remains accurate even with large alphabets and template pools.

## Built-in Templates

The library includes 5 default templates, all 6 characters long:

| Pattern | Description | Example |
|---------|-------------|---------|
| `ABCABC` | Mirror repeat | `1A01A0` |
| `AAABBB` | Triplet + triplet | `111AAA` |
| `ABABAB` | Alternating | `1A1A1A` |
| `ABCDAB` | First 4 + repeat first 2 | `1A2B1A` |
| `ABCCBA` | Perfect palindrome | `1A22A1` |

## Custom Templates

Create your own patterns for any length:

```typescript
import { generate, pattern } from './index.ts';

// 4-character patterns
const shortTemplates = [
  pattern("ABAB"), // A1B2A1B2 → 1A1A
  pattern("AABB"), // A1A1B2B2 → 11AA
];

// 8-character patterns  
const longTemplates = [
  pattern("ABCDDCBA"), // Palindrome
  pattern("ABCDABCD"), // Double repeat
];

const { code } = generate({ templates: shortTemplates });
```

## Security Considerations

- Entropy: Default template pool with the default alphabet yields ≥20 bits of effective entropy (SP 800‑63B guidance for low‑risk OTPs). Increase templates or alphabet size for higher entropy.
- Randomness: Uses cryptographically secure randomness. In Node, the default RNG is `crypto.randomInt`. In browsers, supply a WebCrypto‑backed RNG via `options.rng`.
- Alphabet: Ensure the alphabet contains unique symbols. The default alphabet follows NIST IR 7966 (Crockford Base‑32 without O/I/L).
- Validation: Always validate codes server‑side using `validateCode` with the same template pool and alphabet used to generate them.
- HMAC binding: Prefer storing only the HMAC of `{ code, ...meta }` using a server‑side secret. Include a per‑attempt `nonce` or contextual fields (like email, userId) in `meta` so codes cannot be replayed across contexts.
- Side‑channels: `validateCode` is not constant‑time; do not rely on timing behavior for security. Rate‑limit and throttle verification attempts as usual.
- Resource limits: Extremely large templates or pools can be computationally expensive. Bound input sizes in untrusted contexts.

Browser RNG example using WebCrypto:

```ts
function webCryptoRng(max: number): number {
  if (!crypto || !crypto.getRandomValues) throw new Error('WebCrypto unavailable');
  if (!Number.isInteger(max) || max <= 0) throw new Error('max must be > 0');
  // Rejection sampling for unbiased range [0, max)
  const maxUint = 0xffffffff;
  const limit = Math.floor(maxUint / max) * max;
  const buf = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(buf);
    const x = buf[0]!;
    if (x < limit) return x % max;
  }
}

const { code } = generate({ rng: webCryptoRng });
```

## Use Cases

- **Two-Factor Authentication**: Human-readable backup codes
- **Password Reset**: Memorable temporary passwords  
- **Account Verification**: Email/SMS verification codes
- **Gaming**: Lobby codes, room IDs
- **Support**: Ticket reference numbers

## Development

Run the library:
```bash
bun run index.ts
```

Build (if needed):
```bash
bun build index.ts
```

## License

MIT License - see LICENSE file for details.

## Author

Created by Munchy
