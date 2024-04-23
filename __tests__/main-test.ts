import { DataFactory, Store } from 'n3';
import * as path from 'path';
import * as fs from 'fs';
import mockConsole from 'jest-mock-console';
import * as rdfDeref from 'rdf-dereference-store';
import {
  generateKeyPair, exportKey, signQuads, verifyQuads, importKey,
  exportPrivateKey, hashDataGraph,
} from '../lib/index';
import { main } from '../lib/bin/main';

const { quad, namedNode } = DataFactory;

jest.mock('fs');
jest.mock('rdf-dereference-store');

describe('test signing', () => {
  const q = [
    quad(namedNode('http://example.org/s'), namedNode('http://example.org/p'), namedNode('http://example.org/o1')),
    quad(namedNode('http://example.org/s'), namedNode('http://example.org/p'), namedNode('http://example.org/o2')),
    quad(namedNode('http://example.org/s'), namedNode('http://example.org/p'), namedNode('http://example.org/o3')),
  ];
  const graph = [q[0], q[1]];
  const baseArgs = [
    'node',
    'script.js',
    '--private-key',
    './privateKey.json',
  ];
  let keyPair: CryptoKeyPair;
  let privateKey: string;
  let hash: string;
  let restoreConsole: ReturnType<typeof mockConsole>;

  beforeEach(async () => {
    keyPair = await generateKeyPair();
    privateKey = JSON.stringify(await exportPrivateKey(keyPair.privateKey));
    hash = Buffer.from(await hashDataGraph(graph)).toString('utf8');

    const fileMap = {
      [path.join(__dirname, 'privateKey.json')]: privateKey,
      // [path.join(__dirname, 'data.ttl')]: dataContent,
    };

    jest.spyOn(fs, 'readFileSync').mockImplementation((req) => fileMap[req as string]);
    jest.spyOn(rdfDeref, 'default').mockImplementation(async (req) => {
      if (req === path.join(__dirname, 'data.ttl')) return { store: new Store(graph), prefixes: {} };
      throw new Error('ENOENT');
    });

    restoreConsole = mockConsole();
  });

  afterEach(() => {
    restoreConsole();
  });

  it('can sign and verify', async () => {
    const signature = await signQuads(graph, keyPair.privateKey);

    expect(await verifyQuads([q[1], q[0]], signature, keyPair.publicKey)).toBe(true);
    expect(await verifyQuads([q[0], q[2]], signature, keyPair.publicKey)).toBe(false);

    await expect(
      verifyQuads([q[1], q[0]], signature, await importKey(await exportKey(keyPair.publicKey))),
    ).resolves.toBe(true);
    await expect(
      verifyQuads([q[0], q[2]], signature, await importKey(await exportKey(keyPair.publicKey))),
    ).resolves.toBe(false);
  });

  it.each([
    ['--data'],
    ['--hash'],
  ])('can sign from CLI using %s', async (arg) => {
    await main({
      argv: [
        ...baseArgs,
        arg,
        arg === '--hash' ? Buffer.from(hash).toString('utf8') : './data.ttl',
      ],
      cwd: () => __dirname,
      exit: jest.fn((): never => {
        throw new Error('process.exit() was called');
      }),
    } as Partial<NodeJS.Process> as NodeJS.Process);

    // @ts-ignore
    // eslint-disable-next-line no-console
    const { calls }: { calls: string[][] } = console.log.mock;

    const result = calls[0][0].slice(calls[0][0].indexOf('[', -1));
    return expect(verifyQuads(graph, result, keyPair.publicKey)).resolves.toBe(true);
  });

  it.each(
    [
      baseArgs,
      baseArgs.slice(0, -2),
    ].map((arg) => [arg.join(', '), arg]),
  )('cli errors on missing %s', async (_, args) => {
    await expect(main({
      argv: args,
      cwd: () => __dirname,
      exit: jest.fn((code): never => {
        throw new Error(`process.exit(${code}) was called`);
      }),
    } as Partial<NodeJS.Process> as NodeJS.Process)).rejects.toThrow('process.exit(1) was called');

    expect(console.log).not.toHaveBeenCalled();
    expect(console.error).toHaveBeenCalledWith('Missing required arguments');
  });
});
