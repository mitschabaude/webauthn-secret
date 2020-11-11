import {bytesToBase64, base64ToBytes, concatBytes} from './webauthn-parse.js';
import {recoverKey, parseKey, verify} from './webauthn-elliptic.js';
import {base58} from './base-x.js';

export {createSecret, getSecret, verifySecret};

const CHALLENGE_LENGTH = 32; // length in bytes
const KEY_HASH_LENGTH = 24; // must be <= 32
const SALT_LENGTH = 24;

async function createSecret({rp, user, password} = {}) {
  let challenge = crypto.getRandomValues(new Uint8Array(CHALLENGE_LENGTH));
  let credential = await navigator.credentials
    .create({
      publicKey: {
        challenge,
        rp: {
          id: rp?.id || window?.location.hostname || 'unknown',
          name: rp?.name || window?.location.hostname || 'unknown',
        },
        user: {
          id: user?.id || new ArrayBuffer(),
          name: user?.name || '',
          displayName: user?.displayName || '',
        },
        pubKeyCredParams: [{type: 'public-key', alg: -7}],
      },
    })
    .catch(console.error);
  if (!credential) {
    console.error('navigator.credentials.create failed, returning null');
    return null;
  }
  let key = parseKey(credential.response);
  if (!key) {
    console.error('could not parse key, returning null');
    return null;
  }

  let salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  let secret = await deriveSecret(key, salt, password);

  // hash key to compare later
  let keyHash = await computeKeyHash(key);
  // keyHash (32) and salt (32) have fixed length so we can just concatenate
  let handle = encodeHandle({id: credential.rawId, keyHash, salt});

  return {secret, handle};
}

async function getSecret(handle, {rpId, userVerification, password} = {}) {
  let {keyHash, salt, id} = decodeHandle(handle);

  let challenge = crypto.getRandomValues(new Uint8Array(CHALLENGE_LENGTH));
  let credential = await navigator.credentials
    .get({
      publicKey: {
        challenge,
        rpId,
        userVerification,
        allowCredentials: [{type: 'public-key', id}],
      },
    })
    .catch(console.error);
  if (!credential) {
    console.error('navigator.credentials.get failed, returning null');
    return null;
  }
  let key = await recoverKey(credential.response, keyHash, computeKeyHash);
  if (!key) {
    console.error('key recovery failed, returning null');
    return null;
  }
  return await deriveSecret(key, salt, password);
}

// for testing/validation: verify that recovered public key can actually be used to
// verify the signature returned by authenticator
async function verifySecret(handle, {rpId, userVerification} = {}) {
  let {keyHash, id} = decodeHandle(handle);
  let challenge = crypto.getRandomValues(new Uint8Array(CHALLENGE_LENGTH));
  let credential = await navigator.credentials
    .get({
      publicKey: {
        challenge,
        rpId,
        userVerification,
        allowCredentials: [{type: 'public-key', id}],
      },
    })
    .catch(console.error);
  if (!credential) {
    console.error('navigator.credentials.get failed');
    return false;
  }
  try {
    let key = await recoverKey(credential.response, keyHash, computeKeyHash);
    if (!key) return false;
    let valid = await verify(credential.response, key);
    return valid;
  } catch (err) {
    console.error(err);
    return false;
  }
}

async function computeKeyHash(keyBytes) {
  return new Uint8Array(
    (await crypto.subtle.digest('SHA-256', keyBytes)).slice(0, KEY_HASH_LENGTH)
  );
}

async function deriveSecret(key, salt, password = '') {
  let passwordBytes = new TextEncoder().encode(password);
  let baseKeyBytes = concatBytes(key, passwordBytes);
  let baseKey = await crypto.subtle.importKey(
    'raw',
    baseKeyBytes,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  let secret = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey,
    {name: 'AES-GCM', length: 256},
    true,
    ['encrypt', 'decrypt']
  );
  let secretBuffer = await crypto.subtle.exportKey('raw', secret);
  return base58.encode(secretBuffer);
}

function encodeHandle({keyHash, salt, id}) {
  if (keyHash.length !== KEY_HASH_LENGTH) throw Error('invalid key hash');
  if (salt.length !== SALT_LENGTH) throw Error('invalid salt');
  return bytesToBase64(keyHash) + bytesToBase64(salt) + bytesToBase64(id);
}
function decodeHandle(handle) {
  let l1 = base64Length(KEY_HASH_LENGTH);
  let l2 = l1 + base64Length(SALT_LENGTH);
  if (handle.length <= l2) throw Error('invalid handle');

  let keyHash = base64ToBytes(handle.slice(0, l1));
  let salt = base64ToBytes(handle.slice(l1, l2));
  let id = base64ToBytes(handle.slice(l2));
  return {keyHash, salt, id};
}

function base64Length(byteLength) {
  return Math.ceil(byteLength / 3) * 4;
}
