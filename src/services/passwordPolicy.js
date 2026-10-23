const crypto = require("crypto");

// ── Password policy ───────────────────────────────────────────────────────────
// bcrypt only uses the first 72 *bytes* of a password. A longer password is
// silently truncated, which would make two different passwords equivalent.
// The limit is therefore enforced in bytes, not in characters.
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_BYTES = 72;

/**
 * Validates a plaintext password against the TrustVault policy.
 *
 * @param {unknown} password
 * @returns {string|null} an error message, or null when the password is fine
 */
function passwordProblem(password) {
    if (typeof password !== "string" || password.length === 0) {
        return "Password is required";
    }

    const byteLength = Buffer.byteLength(password, "utf8");

    if (password.length < MIN_PASSWORD_LENGTH) {
        return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
    }

    if (byteLength > MAX_PASSWORD_BYTES) {
        return `Password must not exceed ${MAX_PASSWORD_BYTES} bytes`;
    }

    return null;
}

// Characters that are easy to misread when a password is copied by hand are
// deliberately excluded from the generated pool.
const PASSWORD_ALPHABET =
    "ABCDEFGHJKLMNPQRSTUVWXYZ" + // no I, O
    "abcdefghijkmnopqrstuvwxyz" + // no l
    "23456789" + // no 0, 1
    "!@#$%^&*?-_=+";

/**
 * Generates a cryptographically random one-time password.
 *
 * Used when an administrator creates an account without supplying a password.
 * The value is handed back to the administrator exactly once and is never
 * stored or logged in plaintext.
 *
 * @param {number} length number of characters (minimum 16)
 * @returns {string}
 */
function generateTemporaryPassword(length = 20) {
    const size = Math.max(length, 16);
    const bytes = crypto.randomBytes(size);
    let password = "";

    for (let i = 0; i < size; i += 1) {
        password += PASSWORD_ALPHABET[bytes[i] % PASSWORD_ALPHABET.length];
    }

    // Guarantee the policy minimum even if the caller asks for something short.
    while (password.length < MIN_PASSWORD_LENGTH) {
        password += PASSWORD_ALPHABET[crypto.randomInt(PASSWORD_ALPHABET.length)];
    }

    return password;
}

module.exports = {
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_BYTES,
    passwordProblem,
    generateTemporaryPassword
};
