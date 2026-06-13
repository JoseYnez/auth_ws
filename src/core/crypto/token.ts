import { createHash, randomBytes } from "node:crypto";

/** Refresh token opaco: 256 bits CSPRNG en base64url (CLAUDE.md §6). */
export function generateOpaqueToken(): string {
    return randomBytes(32).toString("base64url");
}

/** A la BD solo viajan hashes (session_token_hash, token_hash, jti). */
export function sha256Hex(value: string): string {
    return createHash("sha256").update(value, "utf8").digest("hex");
}
