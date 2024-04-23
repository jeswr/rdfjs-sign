import { Quad } from '@rdfjs/types';
import { RDFC10 } from 'rdfjs-c14n';
import { subtle, webcrypto } from 'crypto';

export const keyParams = {
  name: 'ECDSA',
  namedCurve: 'P-384',
};

export const signParams = {
  name: keyParams.name,
  hash: 'SHA-512',
};

async function hashDataGraph(input: Iterable<Quad>) {
  const rdfc10 = new RDFC10();
  const normalized = (await rdfc10.c14n(input)).canonicalized_dataset;
  const hash = await rdfc10.hash(normalized);
  return new TextEncoder().encode(hash);
}

async function signDataGraph(input: Quad[], privateKey: webcrypto.CryptoKey) {
  return subtle.sign(signParams, privateKey, await hashDataGraph(input));
}

export async function signQuads(content: Quad[], privateKey: webcrypto.CryptoKey) {
  return Buffer.from(await signDataGraph(content, privateKey)).toString('base64');
}

export async function verifyQuads(
  input: Quad[],
  signature: string,
  publicKey: webcrypto.CryptoKey,
) {
  return subtle.verify(
    signParams,
    publicKey,
    Buffer.from(signature, 'base64'),
    await hashDataGraph(input),
  );
}

export function generateKeyPair() {
  return subtle.generateKey(keyParams, true, ['sign', 'verify']);
}

export function importKey(key: string) {
  return subtle.importKey('raw', Buffer.from(key, 'base64'), keyParams, true, ['verify']);
}

export async function exportKey(key: CryptoKey) {
  return Buffer.from(await subtle.exportKey('raw', key)).toString('base64');
}
