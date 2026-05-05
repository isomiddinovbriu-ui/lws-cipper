import { asconEncrypt, asconDecrypt } from '../algorithms/ascon';
import { hexToBytes, bytesToHex } from '../utils/helpers';

async function run() {
  const keyHex = 'ff558dfb8e233bb4237eeb280ac154ac';
  const nonceHex = '00112233445566778899aabbccddeeff';
  const key = hexToBytes(keyHex);
  const nonce = hexToBytes(nonceHex);

  const text = 'hello ascon';
  const plaintext = new TextEncoder().encode(text);
  const aad = new Uint8Array(0);

  const enc = asconEncrypt(plaintext, key, nonce, aad, false);
  console.log('ciphertext (hex):', bytesToHex(enc.ciphertext));
  console.log('tag (enc):', enc.tag);

  const dec = asconDecrypt(enc.ciphertext, key, nonce, aad, enc.tag, false);
  console.log('decrypted text:', new TextDecoder().decode(dec.ciphertext));
  console.log('tag (dec):', dec.tag);
  console.log('valid:', dec.valid);
  console.log('tags equal:', enc.tag === dec.tag);
}

run().catch(err => {
  console.error('error:', err);
  process.exit(1);
});
