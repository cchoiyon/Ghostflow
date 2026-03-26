/**
 * Case-insensitive patterns that identify sensitive variable names.
 * Consolidated here to ensure consistent threat detection across all scanner components
 * (both local AST scanning and cross-file export analysis).
 */
export const SENSITIVE_PATTERNS: ReadonlyArray<string> = [
    'key', 'secret', 'pass', 'password', 'token', 'credential', 'auth', 'apikey',
    'jwt', 'cert', 'certific', 'cookie', 'session', 'bearer', 'oauth',
    'signingkey', 'private', 'ssh', 'rsa', 'dsa', 'ecdsa', 'ed25519',
    'pem', 'pfx', 'p12', 'ssn', 'social', 'creditcard', 'ccnum', 'stripe'
];

/**
 * Case-insensitive patterns that identify functions performing data sanitization,
 * hashing, or encryption. If a sensitive source passes through these functions,
 * the resulting data flow is marked as Secure (Green) rather than Insecure (Red).
 */
export const SANITIZER_PATTERNS: ReadonlyArray<string> = [
    'encrypt', 'hash', 'sanitize', 'escape', 'bcrypt', 'crypto', 'hmac', 'cipher', 'encode'
];
