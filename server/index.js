import express from "express";
import bodyParser from "body-parser";
import cookieSession from "cookie-session";
import crypto from "crypto";
import {randomBase64URLBuffer, generateServerGetAssertion} from "./security.js";
import path from 'path'
import url from 'url'
import base64url from "base64url";
import {verifyNewCredential, generateServerMakeCredRequest} from "./registration.js";

import Fido2Lib from "fido2-lib";
const f2l = new Fido2Lib.Fido2Lib();

const app = express();
const port = 3000;

const __dirname = path.dirname(new url.URL(import.meta.url).pathname);

app.use(express.static(__dirname + '/../client/'));
app.use(bodyParser.json());

app.use(cookieSession({
    name: 'session',
    keys: [crypto.randomBytes(32).toString('hex')],

    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}));

const database = {
    users: {}
};

app.post('/register', (req, res) => {
    if (!req.body.username) {
        res.json({status: 'error', message: 'Username is required'});
        return
    }
    const username = req.body.username.toLowerCase();
    if (database.users[username]) {
        res.json({status: 'error', message: 'Username already exists, try logging in'});
        return
    }

    // save user in db
    // todo do we need to do this now? can we wait until the user sends us an authenticator response?
    // if we save the user here should we not save challenge here and not in cookies?
    const userId = randomBase64URLBuffer();
    let user = {
        'username': username,
        'id': userId,
        'authenticators': []
    };

    database.users[username] = user;

    let challengeMakeCred = generateServerMakeCredRequest(username, userId);
    req.session.challenge = challengeMakeCred.challenge;
    req.session.username  = username;

    challengeMakeCred.status = 'ok';

    res.json(challengeMakeCred)
});

/*
* https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
* */
app.post('/verify-registration', async (req, res) => {
    let publicKeyCredential = req.body;

    const expectations = {
        origin: 'http://localhost:3000',
        challenge: req.session.challenge,
    };

    try {
        const result = verifyNewCredential(publicKeyCredential, expectations);

        /* things to save
        *   cred.set("publicKey", result.authnrData.get("credentialPublicKeyPem"));
            cred.set("credId", coerceToBase64(result.authnrData.get("credId")));
            cred.set("prevCounter", result.authnrData.get("counter"));
        * */

        database.users[req.session.username].authenticators.push(result)

        if (result.success !== true) {
            res.json({
                'status': 'failed',
                'message': result.message
            })
            return
        }
    } catch(e) {
        console.error(e)
        res.json({
            'status': 'failed',
            'message': e.message
        })
        return
    }

    res.json({
        'status': 'ok',
    })
});

app.post('/verify-login', (req, res) => {

})

app.post('/login', (req, res) => {
    if(!req.body || !req.body.username) {
        res.json({
            'status': 'failed',
            'message': 'Request missing username field!'
        });

        return;
    }

    let username = req.body.username;

    console.log('database')
    console.log(JSON.stringify(database, null, 2))

    if(!database.users[username]) {
        res.json({
            'status': 'failed',
            'message': `User ${username} does not exist!`
        });

        return
    }

    if(database.users[username].authenticators.length === 0) {
        res.json({
            'status': 'failed',
            'message': `User ${username} has no registered authenticators!`
        });

        return
    }

    // todo make new
    let getAssertion = generateServerGetAssertion(database.users[username].authenticators)
    getAssertion.status = 'ok'

    req.session.challenge = getAssertion.challenge;
    req.session.username  = username;

    res.json(getAssertion)
});


app.listen(port, () => console.log(`Example app listening on port ${port}!`));
