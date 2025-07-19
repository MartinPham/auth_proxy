/**
 * WebAuthn Shared Helper Functions
 *
 * This file contains shared helper functions for WebAuthn operations
 * that are used by both login.html and register.html.
 */

// base64url > base64 > Uint8Array > ArrayBuffer
const bufferDecode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0))
    .buffer;

// ArrayBuffer > Uint8Array > base64 > base64url
const bufferEncode = value => btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

