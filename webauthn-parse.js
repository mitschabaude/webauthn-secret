// this submodule contains parser/encoding functions needed by
// both ./webauthn-elliptic and ./webauthn-secret
import CBOR from './cbor.js';

export function parseCoseKey(attestationResponse) {
  let authData;
  try {
    authData = CBOR.decode(attestationResponse.attestationObject).authData;
  } catch (err) {
    console.error(err);
    console.error('Could not decode CBOR object');
    return;
  }
  if (!authData) {
    console.error('No authData property in CBOR object');
    return;
  }
  if (!(authData[32] & (1 << 6))) {
    console.error('Attestation data flag not set');
    return;
  }
  let authDataView = new DataView(
    authData.buffer,
    authData.byteOffset,
    authData.byteLength
  );
  let credIdLen = authDataView.getUint16(53);
  let keyStartPosition = 55 + credIdLen;
  if (authData.length <= keyStartPosition) {
    console.error('Byte length of authData smaller than expected');
    return;
  }
  return authData.slice(55 + credIdLen);
}

export async function parseSignature(assertionResponse) {
  let {clientDataJSON, authenticatorData, signature} = assertionResponse;
  let authData = new Uint8Array(authenticatorData);
  let cDataHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', clientDataJSON)
  );
  let msg = concatBytes(authData, cDataHash);
  let msgHash = new Uint8Array(await crypto.subtle.digest('SHA-256', msg));

  return {msgHash, signature: new Uint8Array(signature)};
}

// our key encoding
export function encodeXYKey({x, y}) {
  return new Uint8Array(CBOR.encode({x, y}));
}
export function decodeXYKey(keyBytes) {
  return CBOR.decode(keyBytes.buffer);
}

// helper functions
export function bytesToBase64(bytes) {
  bytes = new Uint8Array(bytes);
  let n = bytes.length;
  let chars = new Array(n);
  for (let i = 0; i < n; i++) {
    chars[i] = String.fromCharCode(bytes[i]);
  }
  return window.btoa(chars.join(''));
}
export function base64ToBytes(base64) {
  let binaryString = window.atob(base64);
  let n = binaryString.length;
  let bytes = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}
export function concatBytes(...arrays) {
  let totalLength = arrays.reduce((sum, array) => sum + array.length, 0);
  let concatenated = new Uint8Array(totalLength);
  let offset = 0;
  for (let array of arrays) {
    concatenated.set(array, offset);
    offset += array.length;
  }
  return concatenated;
}
export function isEqualBytes(array1, array2) {
  if (array1.length !== array2.length) return false;
  let n = array1.length;
  for (let i = 0; i < n; i++) {
    if (array1[i] !== array2[i]) return false;
  }
  return true;
}

export function bytesToHex(bytes) {
  bytes = new Uint8Array(bytes);
  let n = bytes.length;
  let hexBytes = new Array(n);
  for (let i = 0; i < n; i++) {
    hexBytes[i] = bytes[i].toString(16).padStart(2, '0');
  }
  return hexBytes.join('');
}
export function hexToBytes(hexString) {
  let n = hexString.length;
  if (n % 2)
    throw Error('hex string has uneven length, last byte not well-defined');
  let halfn = Math.round(n / 2);
  let bytes = new Uint8Array(halfn);
  for (let i = 0; i < halfn; i++) {
    let hexByte = hexString.charAt(2 * i) + hexString.charAt(2 * i + 1);
    bytes[i] = parseInt(hexByte, 16);
  }
  return bytes;
}

// currently unused, but could be useful later
// adapted from https://github.com/webauthn-open-source/fido2-lib/blob/master/lib/parser.js
export function parseAuthData(attestationResponse) {
  let {authData} = CBOR.decode(attestationResponse.attestationObject);
  let authDataView = new DataView(
    authData.buffer,
    authData.byteOffset,
    authData.byteLength
  );

  let rpIdHash = authData.slice(0, 32);
  let flagInt = authDataView.getUint8(32);
  let flags = {
    UP: !!(flagInt & (1 << 0)),
    UV: !!(flagInt & (1 << 2)),
    AT: !!(flagInt & (1 << 6)),
    ED: !!(flagInt & (1 << 7)),
  };
  let counter = authDataView.getUint32(33);

  let aaguid, credId, keyCose;
  if (flags.AT) {
    let credIdLen = authDataView.getUint16(53);
    aaguid = authData.slice(37, 53);
    credId = authData.slice(55, 55 + credIdLen);
    keyCose = authData.slice(55 + credIdLen);
  }

  if (flags.ED) {
    throw new Error('authenticator extensions not supported');
  }

  return {
    rpIdHash,
    flags,
    counter,
    aaguid,
    credId,
    keyCose,
  };
}
