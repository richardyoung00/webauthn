import {randomBase64URLBuffer} from "./security.js";
import base64url from "base64url";
import cbor from "cbor";
import crypto from "crypto";
import coseToJwk from "cose-to-jwk"
import jwkToPem from "jwk-to-pem"

export function generateServerMakeCredRequest(username, userId) {
    return {
        challenge: randomBase64URLBuffer(32),

        rp: {
            name: "ACME Corporation",
        },
        authenticatorSelection: {
            requireResidentKey: false,
            userVerification: "discouraged",
        },
        user: {
            id: userId,
            name: username,
            displayName: username
        },

        attestation: 'none',

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
    let flags = new Set();
    if (flagsByte & 0x01) flags.add("UP");
    if (flagsByte & 0x04) flags.add("UV");
    if (flagsByte & 0x40) flags.add("AT");
    if (flagsByte & 0x80) flags.add("ED");

    let counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);

    let aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);

    let credIdLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);

    let credIdLen = credIdLenBuf.readUInt16BE(0);
    let credIdArrayBuffer = buffer.slice(0, credIdLen);
    const credId = base64url.encode(new Buffer(credIdArrayBuffer));
    buffer = buffer.slice(credIdLen);

    let publicKeyCose = buffer;
    const publicKeyJwk = coseToJwk(publicKeyCose);
    const publicKeyPem = jwkToPem(publicKeyJwk)
    return {rpIdHash, flags, counter, aaguid, credId, publicKeyCose, publicKeyJwk, publicKeyPem}

}

/*
* https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
* */
export function verifyNewCredential(publicKeyCredential, expectations) {
    const clientDataJSON = JSON.parse(base64url.decode(publicKeyCredential.response.clientDataJSON));

    // Verify that the value of C.type is webauthn.create.
    if (clientDataJSON.type !== 'webauthn.create') {
        return {
            success: false,
            message: 'Expected type to be webauthn.create'
        }
    }

    // Verify that the value of C.challenge equals the base64url encoding of options.challenge.
    if (clientDataJSON.challenge !== expectations.challenge) {
        return {
            success: false,
            message: 'Challenge does not match'
        }
    }

    // Verify that the value of C.origin matches the Relying Party's origin.
    if (clientDataJSON.origin !== expectations.origin) {
        return {
            success: false,
            message: 'Origin does not match'
        }
    }

    // todo: implement TokenBinding step 7 in registering new credential

    // Perform CBOR decoding on the attestationObject
    const attestationObject = cbor.decodeFirstSync(base64url.toBuffer(publicKeyCredential.response.attestationObject));

    const authData = parseAuthData(attestationObject.authData);

    // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID (domain string) expected by the Relying Party.
    const domain = new URL(clientDataJSON.origin).hostname;
    const domainHash = new Uint8Array(crypto.createHash("sha256").update(domain).digest()).buffer;

    if (Buffer.compare(Buffer.from(domainHash), Buffer.from(authData.rpIdHash)) !== 0) {
        return {
            success: false,
            message: 'rpIdHash does not match hash of RP ID (domain string)'
        }
    }

    // Verify that the User Present bit of the flags in authData is set.
    // Usually just pressing a button
    if (!authData.flags.has('UP')) {
        return {
            success: false,
            message: 'User was not present during authentication'
        }
    }

    // [Optional] Verify that the User Verification bit of the flags in authData is set.
    // Such as pin code, password, biometrics etc
    if (!authData.flags.has('UV')) {
        return {
            success: false,
            message: 'User was not verified as a part of authentication'
        }
    }

    // Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
    const publicKey = cbor.decodeFirstSync(authData.publicKeyCose);
    if (publicKey.get(3) !== -7) {
        return {
            success: false,
            message: 'Algorithm used for public key is not one of the expected ones'
        }
    }

    // todo support any extensions here
    // todo verify attestationObject.fmt

    return {
        success: true,
        publicKey: authData.publicKeyPem,
        credentialId: authData.credId,
        counter: authData.counter
    }
}
