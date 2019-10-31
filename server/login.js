import {randomBase64URLBuffer} from "./security.js";


export let generatePublicKeyCredentialRequestOptions = (authenticators) => {
    let allowCredentials = [];
    for(let authenticator of authenticators) {
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

}
