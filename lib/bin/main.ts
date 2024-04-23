import fs from 'fs';
import path from 'path';
import { subtle } from 'crypto';
import dereference from 'rdf-dereference-store';
import { signParams, importPrivateKey, hashDataGraph } from '..';

export async function main(proc: NodeJS.Process) {
  const args = proc.argv.slice(2);

  const signatureIndex = args.indexOf('--private-key');
  const hashIndex = args.indexOf('--hash');
  const dataIndex = args.indexOf('--data');

  const signature = signatureIndex !== -1 ? args[signatureIndex + 1] : null;
  const hash = hashIndex !== -1 ? args[hashIndex + 1] : null;
  const data = dataIndex !== -1 ? args[dataIndex + 1] : null;

  if (!signature || (!hash && !data)) {
    console.error('Missing required arguments');
    proc.exit(1);
  }

  const privateKey = await importPrivateKey(JSON.parse(fs.readFileSync(path.join(proc.cwd(), signature), 'utf-8')));
  const dataHash = hash ? Uint8Array.from(Buffer.from(hash, 'utf8')) : await hashDataGraph((await dereference(path.join(proc.cwd(), data!), { localFiles: true })).store);
  const sign = await subtle.sign(signParams, privateKey, dataHash);
  console.log(`The signature is [${Buffer.from(sign).toString('base64')}]`);
}
