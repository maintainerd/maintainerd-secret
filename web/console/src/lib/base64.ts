/**
 * Base64 <-> bytes, for secret values on the wire.
 *
 * Values on this API are base64 of the RAW plaintext bytes, because a secret can
 * be a binary key, a certificate or a password containing a newline, and a JSON
 * string cannot carry arbitrary bytes losslessly. `atob`/`btoa` alone are not
 * enough: they are byte-oriented, so a value the operator typed with any
 * non-ASCII character in it has to go through a UTF-8 encode first or it is
 * silently mangled.
 */

function base64ToBytes(value: string): Uint8Array {
  const binary = window.atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function encodeUtf8ToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return window.btoa(binary)
}

/**
 * Decodes base64 to text. Bytes that are not valid UTF-8 are replaced rather
 * than throwing: a binary value should render as something the operator can see
 * is binary, not blow up the dialog that was going to tell them so.
 */
export function decodeBase64ToUtf8(value: string): string {
  return new TextDecoder('utf-8').decode(base64ToBytes(value))
}

/** True when the base64 payload round-trips as valid, NUL-free UTF-8 text. */
export function isPrintableUtf8(value: string): boolean {
  try {
    const bytes = base64ToBytes(value)
    // A NUL byte means binary even when the strict decoder accepts the sequence.
    if (bytes.includes(0)) return false
    new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    return true
  } catch {
    return false
  }
}

/** Byte length of a base64 payload, for "N bytes" on a binary value. */
export function base64ByteLength(value: string): number {
  const clean = value.replace(/=+$/, '')
  return Math.floor((clean.length * 3) / 4)
}
