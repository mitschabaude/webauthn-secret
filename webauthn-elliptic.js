// this submodule contains all functions that depend on the elliptic package
// should make it easy to swap to different elliptic curve implementations later
import CBOR from './cbor.js';
import elliptic from 'https://cdn.skypack.dev/elliptic';
import {
  encodeXYKey,
  decodeXYKey,
  parseSignature,
  parseCoseKey,
  isEqualBytes,
} from './webauthn-parse.js';
const EC = elliptic.ec;
const ec = new EC('p256');

export {recoverKey, verify, parseKey};

async function recoverKey(assertionResponse, keyHash, computeKeyHash) {
  let {msgHash, signature} = await parseSignature(assertionResponse);
  for (let i = 0; i < 4; i++) {
    try {
      let key = ec.recoverPubKey(msgHash, signature, i);
      let {x, y} = {x: key.getX().toArray(), y: key.getY().toArray()};
      let keyBytes = encodeXYKey({x, y});
      let keyHash_ = await computeKeyHash(keyBytes);
      if (isEqualBytes(keyHash, keyHash_)) return keyBytes;
    } catch (err) {}
  }
  return;
}

async function verify(assertionResponse, keyBytes) {
  let {x, y} = decodeXYKey(keyBytes);
  let key = ec.keyFromPublic({x, y});

  let {msgHash, signature} = await parseSignature(assertionResponse);
  return key.verify(msgHash, signature);
}

function parseKey(attestationResponse) {
  let keyCose = parseCoseKey(attestationResponse);
  if (!keyCose) return;
  let {'-2': x, '-3': y} = CBOR.decode(keyCose.buffer);
  if (!x || !y) return;
  try {
    let key = ec.keyFromPublic({x, y}).pub;
    x = key.getX().toArray();
    y = key.getY().toArray();
  } catch (err) {
    console.error(err);
    return;
  }
  return encodeXYKey({x, y});
}
