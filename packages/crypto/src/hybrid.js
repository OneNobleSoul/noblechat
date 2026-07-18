// Hybrid post-quantum key encapsulation (PQXDH-style).
//
// The session secret is derived from BOTH a classical X25519 Diffie-Hellman
// AND an ML-KEM-768 encapsulation. It stays secure as long as *either* the
// discrete-log assumption OR the Module-LWE assumption holds - so a future
// quantum computer that breaks X25519 does not break recorded messages.
import { x25519 } from "@noble/curves/ed25519";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { concatBytes } from "./util.js";
import { deriveKey, hash } from "./kdf.js";

const INFO = "noblechat/hybrid-kem/v1";

export function generateKemKeypair() {
  const xSecret = x25519.utils.randomPrivateKey();
  const xPublic = x25519.getPublicKey(xSecret);
  const kem = ml_kem768.keygen();
  return {
    x: { publicKey: xPublic, secretKey: xSecret },
    kem: { publicKey: kem.publicKey, secretKey: kem.secretKey },
  };
}

export function kemPublicBundle(kp) {
  return { x: kp.x.publicKey, kem: kp.kem.publicKey };
}

function transcript(ephX, recipX, recipKem, kct) {
  return hash(concatBytes(ephX, recipX, recipKem, kct));
}

// Sender side: produce a header the recipient needs plus the shared secret.
export function encapsulate(recipientBundle) {
  const ephSecret = x25519.utils.randomPrivateKey();
  const ephPublic = x25519.getPublicKey(ephSecret);
  const dh = x25519.getSharedSecret(ephSecret, recipientBundle.x);
  const { cipherText, sharedSecret: kemSs } = ml_kem768.encapsulate(recipientBundle.kem);
  const salt = transcript(ephPublic, recipientBundle.x, recipientBundle.kem, cipherText);
  const sharedSecret = deriveKey(concatBytes(dh, kemSs), salt, INFO, 32);
  return { header: { epk: ephPublic, kct: cipherText }, sharedSecret };
}

// Recipient side: recompute the same shared secret from the header.
export function decapsulate(kp, header) {
  const dh = x25519.getSharedSecret(kp.x.secretKey, header.epk);
  const kemSs = ml_kem768.decapsulate(header.kct, kp.kem.secretKey);
  const salt = transcript(header.epk, kp.x.publicKey, kp.kem.publicKey, header.kct);
  return deriveKey(concatBytes(dh, kemSs), salt, INFO, 32);
}
