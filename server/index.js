import express from "express";
import bodyParser from "body-parser";
import cookieSession from "cookie-session";
import crypto from "crypto";
import {generateServerMakeCredRequest, randomBase64URLBuffer,
    verifyAuthenticatorAttestationResponse, verifyAuthenticatorAssertionResponse, generateServerGetAssertion} from "./security.js";
import path from 'path'
import url from 'url'
import base64url from "base64url";
import {verifyNewCredential} from "./registration.js";

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
        res.json({error: 'Username is required'});
        return
    }
    const username = req.body.username.toLowerCase();
    if (database.users[username]) {
        res.json({error: 'Username already exists, try logging in'});
        return
    }

    // save user in db
    // todo do we need to do this now? can we wait until the user sends us an authenticator response?
    // if we save the user here should we not save challenge here and not in cookies?
    const userId = randomBase64URLBuffer();
    let user = {
        'username': username,
        'registered': false,
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
app.post('/verify-registration', (req, res) => {
    let publicKeyCredential = req.body;

    const expectations = {
        origin: 'http://localhost:3000',
        challenge: req.session.challenge
    };

    try {
        verifyNewCredential(publicKeyCredential, expectations);
    } catch(e) {
        res.json({
            'status': 'failed',
            'message': e.message
        })
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
    console.log(JSON.stringify(database))
    if(!database.users[username]) {
        res.json({
            'status': 'failed',
            'message': `User ${username} does not exist!`
        });

        return
    }

    if(!database.users[username].registered) {
        res.json({
            'status': 'failed',
            'message': `User ${username} has not been registered!`
        });

        return
    }

    let getAssertion    = generateServerGetAssertion(database[username].authenticators)
    getAssertion.status = 'ok'

    req.session.challenge = getAssertion.challenge;
    req.session.username  = username;

    req.json(getAssertion)
});


app.listen(port, () => console.log(`Example app listening on port ${port}!`));
