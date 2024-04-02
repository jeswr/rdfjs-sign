import { DataFactory } from 'n3';
import {
  generateKeyPair, exportKey, signQuads, verifyQuads, importKey,
} from '../lib/index';

const { quad, namedNode } = DataFactory;

it('can sign and verify', async () => {
  const q1 = quad(namedNode('http://example.org/s'), namedNode('http://example.org/p'), namedNode('http://example.org/o1'));
  const q2 = quad(namedNode('http://example.org/s'), namedNode('http://example.org/p'), namedNode('http://example.org/o2'));
  const q3 = quad(namedNode('http://example.org/s'), namedNode('http://example.org/p'), namedNode('http://example.org/o3'));
  const keyPair = await generateKeyPair();
  const signature = await signQuads([q1, q2], keyPair.privateKey);

  expect(await verifyQuads([q2, q1], signature, keyPair.publicKey)).toBe(true);
  expect(await verifyQuads([q1, q3], signature, keyPair.publicKey)).toBe(false);

  expect(
    await verifyQuads([q2, q1], signature, await importKey(await exportKey(keyPair.publicKey))),
  ).toBe(true);
  expect(
    await verifyQuads([q1, q3], signature, await importKey(await exportKey(keyPair.publicKey))),
  ).toBe(false);
});
