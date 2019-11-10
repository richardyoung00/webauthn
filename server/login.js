import {randomBase64URLBuffer} from "./security.js";
import base64url from "base64url";
import crypto from "crypto";

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} bufferInput - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseGetAssertAuthData = (bufferInput) => {
    let buffer = bufferInput.slice(0)
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

    return {rpIdHash, flags, flagsBuf, counter, counterBuf}
}

export let generatePublicKeyCredentialRequestOptions = (authenticators) => {
    let allowCredentials = [];
    for (let authenticator of authenticators) {
        allowCredentials.push({
            type: 'public-key',
            id: authenticator.credentialId,
            // transports: ['usb', 'nfc', 'ble']
        })
    }
    return {
        challenge: randomBase64URLBuffer(32),
        allowCredentials: allowCredentials,
        userVerification: "discouraged",
        //rpId: "localhost:3000"
    }
}

export function verifyExistingCredential(publicKeyCredential, expectations) {
    const clientDataJSON = JSON.parse(base64url.decode(publicKeyCredential.response.clientDataJSON));

    console.log('clientDataJSON');
    console.log(JSON.stringify(clientDataJSON, null, 2));

    // Verify that the value of C.type is webauthn.get.
    if (clientDataJSON.type !== 'webauthn.get') {
        return {
            success: false,
            message: 'Expected type to be webauthn.get'
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

    // todo: implement TokenBinding step 14 in verifying existing credential

    let authenticatorData = base64url.toBuffer(publicKeyCredential.response.authenticatorData);
    let authData = parseGetAssertAuthData(authenticatorData);

    // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party

    console.log('authData')
    console.log(JSON.stringify(authData, null, 2))

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
    // if (!authData.flags.has('UV')) {
    //     return {
    //         success: false,
    //         message: 'User was not verified as a part of authentication'
    //     }
    // }

    // Find the authenticator that matches the credential ID
    const authenticator = expectations.authenticators.find(auth => auth.credentialId === publicKeyCredential.id);

    if (!authenticator) {
        return {
            success: false,
            message: 'Authenticator not registered'
        }
    }

    // Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.

    const signature = base64url.toBuffer(publicKeyCredential.response.signature);
    const publicKey = authenticator.publicKey;
    const rawClientData = base64url.toBuffer(publicKeyCredential.response.clientDataJSON);
    const clientDataHash = crypto.createHash('SHA256').update(rawClientData).digest();
    const clientDataHashArrayBuff = Buffer.from(clientDataHash);

    let rawAuthenticatorData = base64url.toBuffer(publicKeyCredential.response.authenticatorData);

    const verify = crypto.createVerify("SHA256");
    verify.write(rawAuthenticatorData);
    verify.write(clientDataHashArrayBuff);
    verify.end();

    const isSigValid = verify.verify(publicKey, signature);

    if (!isSigValid) {
        return {
            success: false,
            message: 'Public key signature not valid'
        }
    }

    return {
        success: true
    }
}
