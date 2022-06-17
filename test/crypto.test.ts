import assert from 'assert';
import * as secp from '@noble/secp256k1';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { base64, base64url } from '@scure/base';

describe('crypto', () => {
  it('Combine BIP32 with BIP340', async () => {
    // BIP0340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#public-key-conversion

    /**
     * Public Key Conversion
     *
     * As an alternative to generating keys randomly, it is also possible and safe to repurpose existing key generation algorithms for ECDSA in a compatible way.
     * The secret keys constructed by such an algorithm can be used as sk directly.
     * The public keys constructed by such an algorithm (assuming they use the 33-byte compressed encoding) need to be converted by dropping the first byte.
     * Specifically, BIP32 and schemes built on top of it remain usable.
     */

    const text = 'hello world';
    // const messageArray = new TextEncoder().encode(text);
    const messageArray = new Uint8Array(Buffer.from(text));

    const prv1 =
      '6ff043f290f94df6566b2ccb94e8b6d10b9557045e0f895312988b3bfe0a2167';
    const pub1 =
      '039ea2b936be11e39f4e40b8c42ed876b34fc6eb1df18dd488a65eb8c4bbc897cc';

    const prv2 =
      'd8acabee355659fd308c13d289125c46bd96c3fcedeb03969fc0cfb138b120a6';
    const pub2 =
      '023fd1cd2a5f8358c5633a5349618cb74f3b0e981ee9a512f9d1e1c71a4f83af82';

    // const privateKey = secp.utils.randomPrivateKey();
    const messageHash = await secp.utils.sha256(messageArray);

    const publicKey1 = secp.getPublicKey(prv1, true);
    const publicKey2 = secp.getPublicKey(prv2, true);
    const publicKeySchnorr1 = secp.schnorr.getPublicKey(prv1);
    const publicKeySchnorr2 = secp.schnorr.getPublicKey(prv2);

    // No matter if the ECDSA Y value is odd or even, it will be same as schnorr pubkey.
    // Specification: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#public-key-conversion
    assert.deepEqual(publicKey1.slice(1), publicKeySchnorr1);
    assert.deepEqual(publicKey2.slice(1), publicKeySchnorr2);

    // Create signatures of ECDSA and Schnorr:
    const signature1 = await secp.sign(messageHash, prv1);
    const signature2 = await secp.sign(messageHash, prv2);
    const signatureSchnorr1 = await secp.schnorr.sign(messageHash, prv1);
    const signatureSchnorr2 = await secp.schnorr.sign(messageHash, prv2);

    // Verify using ECDSA compressed public key:
    assert.equal(secp.verify(signature1, messageHash, publicKey1), true);
    assert.equal(secp.verify(signature2, messageHash, publicKey2), true);

    // Attempting to verify using schnorr key:
    assert.equal(
      await secp.schnorr.verify(
        signatureSchnorr1,
        messageHash,
        publicKeySchnorr1
      ),
      true
    );
    assert.equal(
      await secp.schnorr.verify(
        signatureSchnorr2,
        messageHash,
        publicKeySchnorr2
      ),
      true
    );

    // Here follows an example where one must be careful not to use schnorr public keys
    // against the ECSDA verification methods. This will work in ~50% of cases.

    // Attempt to verify ECSDA signature using Schnorr public key, this should fail (odd key):
    assert.equal(
      secp.verify(signature1, messageHash, publicKeySchnorr1),
      false
    );

    // This actually works, because they key is even (probably default):
    assert.equal(secp.verify(signature2, messageHash, publicKeySchnorr2), true);

    // Verify using Schnorr method with ECSDA pubkey, this will work in ~50% of cases (odd/even).
    assert.equal(
      await secp.schnorr.verify(signatureSchnorr1, messageHash, publicKey1),
      false
    );
    assert.equal(
      await secp.schnorr.verify(signatureSchnorr2, messageHash, publicKey2),
      true
    );

    // Next step is combining with BIP32:
    const recoveryPhrase =
      'rescue interest concert clinic build half glow exchange oak holiday garlic scrub';

    const network = {
      public: 0x0488b21e,
      private: 0x0488ade4,
    };

    const seed = mnemonicToSeedSync(recoveryPhrase);
    const masterNode = HDKey.fromMasterSeed(seed, network);

    const accountNode = masterNode.derive(`m/302'/616'/0'`);
    const xpub = accountNode.publicExtendedKey;
    const addressNode1 = accountNode.deriveChild(0).deriveChild(0); // even pub key
    const addressNode2 = accountNode.deriveChild(0).deriveChild(2); // odd pub key

    const pubEcdsa = secp.getPublicKey(addressNode1.privateKey!, true);
    const pubSchnorr = secp.schnorr.getPublicKey(addressNode1.privateKey!);

    assert.equal(pubEcdsa.length, 33);
    assert.equal(pubSchnorr.length, 32);

    const pubHex = secp.utils.bytesToHex(pubSchnorr);


    const pub = secp.Point.fromHex(pubHex);
    const xHex = pub.x.toString(16);
    const bytesOfX = secp.utils.hexToBytes(xHex);

    console.log('Base64 encodings:');
    console.log(Buffer.from(bytesOfX).toString('base64'));
    console.log(Buffer.from(bytesOfX).toString('base64url'));
    console.log(base64.encode(bytesOfX));
    console.log(base64url.encode(bytesOfX));

    // console.log(base64.encode(array));
    // console.log(base64.encode(buffer));

    // console.log(pub.x);
    // console.log(pub.y);

    // // Buffer.from(pub.x, 'base64');
    // // Buffer.from(rawData, 'base64');
    // // buffer.toString('hex');
    // const buffer = Buffer.from(pub.x.toString(16));
    // console.log(buffer.length);

    // // base64.encode(pub.x.toString(16));
    // // Uint8Array.from(pub.x.toString(16));

    // console.log(pub.x.toString(16));
    // console.log(pub.y.toString(16));

    // console.log(base64url.encode(buffer));

    // const [x, y] = [pub.x, pub.y].map((n) => pad(n));

    // console.log(x.length);

    // const jwk = {
    //   hex: pub.toHex(true), x, y
    // };

    // console.log('JWK: ', JSON.stringify(jwk));

    // Restore from xpub:
    const accountNodePub = HDKey.fromExtendedKey(xpub, network);
    const addressNodePub = accountNodePub.deriveChild(0).deriveChild(0);
    const addressNodePubSliced = addressNodePub.publicKey!.slice(1);

    const addressNodePub2 = accountNodePub.deriveChild(0).deriveChild(2);
    const addressNodePubSliced2 = addressNodePub2.publicKey!.slice(1);

    // Verify that the public key derived from private key, is exactly the same as the compressed ECSDA without prefix:
    assert.deepEqual(pubSchnorr, addressNodePubSliced);

    // Take the BIP32 derived private key, sign and then verify using the sliced key:
    const signatureFromNode1 = await secp.schnorr.sign(
      messageHash,
      addressNode1.privateKey!
    );

    assert.equal(
      await secp.schnorr.verify(
        signatureFromNode1,
        messageHash,
        addressNodePubSliced
      ),
      true
    );

    const signatureFromNode2 = await secp.schnorr.sign(
      messageHash,
      addressNode2.privateKey!
    );

    assert.equal(
      await secp.schnorr.verify(
        signatureFromNode2,
        messageHash,
        addressNodePubSliced2
      ),
      true
    );
  });
});
