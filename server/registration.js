import {randomBase64URLBuffer} from "./security.js";
import base64url from "base64url";
import cbor from "cbor";
import crypto from "crypto";

export function generateServerMakeCredRequest(username, userId) {
    return {
        challenge: randomBase64URLBuffer(32),

        rp: {
            name: "ACME Corporation",
        },

        user: {
            id: userId,
            name: username,
            displayName: username
        },

        attestation: 'direct',

        pubKeyCredParams: [
            {
                type: "public-key",
                alg: -7 // "ES256" IANA COSE Algorithms registry
            },
        ]
    }
}

/*
* https://w3c.github.io/webauthn/#sctn-authenticator-data
* */
function parseAuthData(buffer) {
    let rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);

    let flagsBuf = buffer.slice(0, 1);
    buffer = buffer.slice(1);
    let flagsByte = flagsBuf[0];
    let flags = new Set()
    if (flagsByte & 0x01) flags.add("UP");
    if (flagsByte & 0x04) flags.add("UV");
    if (flagsByte & 0x40) flags.add("AT");
    if (flagsByte & 0x80) flags.add("ED");

    let counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);

    let aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);

    let credIDLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);

    let credIDLen = credIDLenBuf.readUInt16BE(0);
    let credID = buffer.slice(0, credIDLen);
    buffer = buffer.slice(credIDLen);

    let COSEPublicKey = buffer;
    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}

}

/*
* https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
* */
export function verifyNewCredential(publicKeyCredential, expectations) {
    const clientDataJSON = JSON.parse(base64url.decode(publicKeyCredential.response.clientDataJSON));

    // Verify that the value of C.type is webauthn.create.
    if (clientDataJSON.type !== 'webauthn.create') {
        throw new Error('Expected type to be webauthn.create')
    }

    // Verify that the value of C.challenge equals the base64url encoding of options.challenge.
    if (base64url.decode(clientDataJSON.challenge) !== expectations.challenge) {
        throw new Error('Challenge does not match')
    }

    // Verify that the value of C.origin matches the Relying Party's origin.
    if (clientDataJSON.origin !== expectations.origin) {
        throw new Error('Origin does not match')
    }

    // todo: implement TokenBinding step 7 in registering new credential

    // Perform CBOR decoding on the attestationObject
    const attestationObject = cbor.decodeAllSync(base64url.toBuffer(publicKeyCredential.response.attestationObject))[0];

    const authData = parseAuthData(attestationObject.authData)

    // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID (domain string) expected by the Relying Party.
    const domain = new URL(clientDataJSON.origin).hostname;
    const domainHash = new Uint8Array(crypto.createHash("sha256").update(domain).digest()).buffer;

    if (Buffer.compare(Buffer.from(domainHash), Buffer.from(authData.rpIdHash)) !== 0) {
        throw new Error('rpIdHash does not match hash of RP ID (domain string)')
    }

    // Verify that the User Present bit of the flags in authData is set.
    // Usually just pressing a button
    if (!authData.flags.has('UP')) {
        throw new Error('User was not present during authentication')
    }

    // [Optional] Verify that the User Verification bit of the flags in authData is set.
    // Such as pin code, password, biometrics etc
    if (!authData.flags.has('UV')) {
        throw new Error('User was not verified as a part of authentication')
    }

    // Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
    const publicKey = cbor.decodeFirstSync(authData.COSEPublicKey);
    if (publicKey.get(3) !== -7) {
        throw new Error('Algorithm used for public key is not one of the expected ones')
    }
}
