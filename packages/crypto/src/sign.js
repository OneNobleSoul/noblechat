// Hybrid signatures: a message is signed with BOTH Ed25519 and ML-DSA-65.
// Verification requires both to pass, so a break of one scheme alone does not
// let an attacker forge identities.
import { ed25519 } from "@noble/curves/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";

export function generateSignKeypair() {
  const edSecret = ed25519.utils.randomPrivateKey();
  const edPublic = ed25519.getPublicKey(edSecret);
  const dsa = ml_dsa65.keygen();
  return {
    ed: { publicKey: edPublic, secretKey: edSecret },
    dsa: { publicKey: dsa.publicKey, secretKey: dsa.secretKey },
  };
}

export function signPublicBundle(kp) {
  return { ed: kp.ed.publicKey, dsa: kp.dsa.publicKey };
}

export function sign(kp, message) {
  return {
    ed: ed25519.sign(message, kp.ed.secretKey),
    dsa: ml_dsa65.sign(kp.dsa.secretKey, message),
  };
}

export function verify(pubBundle, message, sig) {
  try {
    return (
      ed25519.verify(sig.ed, message, pubBundle.ed) &&
      ml_dsa65.verify(pubBundle.dsa, message, sig.dsa)
    );
  } catch {
    return false;
  }
}
