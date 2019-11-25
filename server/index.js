import express from "express";
import bodyParser from "body-parser";
import cookieSession from "cookie-session";
import crypto from "crypto";
import {randomBase64URLBuffer} from "./security.js";
import path from 'path'
import url from 'url'
import {verifyNewCredential, generatePublicKeyCredentialCreationOptions} from "./registration.js";
import {verifyExistingCredential, generatePublicKeyCredentialRequestOptions} from "./login.js"

const app = express();
const port = process.env.PORT || 3000;

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

    const userId = randomBase64URLBuffer();

    let challengeMakeCred = generatePublicKeyCredentialCreationOptions(username, userId);
    req.session.challenge = challengeMakeCred.challenge;
    req.session.username  = username;
    req.session.userId  = userId;

    challengeMakeCred.status = 'ok';

    res.json(challengeMakeCred)
});

/**
* https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
* */
app.post('/verify-registration', async (req, res) => {
    let publicKeyCredential = req.body;

    const expectations = {
        origin: process.env.HOST || 'http://localhost:3000',
        challenge: req.session.challenge,
    };

    try {
        const authenticatorData = verifyNewCredential(publicKeyCredential, expectations, { requireUserVerification: false });

        if (authenticatorData.success !== true) {
            res.json({
                'status': 'failed',
                'message': authenticatorData.message
            });
            return
        }

        let user = {
            'username': req.session.username,
            'id': req.session.userId,
            'authenticators': [authenticatorData]
        };

        database.users[req.session.username] = user;

    } catch(e) {
        console.error(e);
        res.json({
            'status': 'failed',
            'message': e.message
        });
        return
    }

    res.json({
        'status': 'ok',
    })
});

app.post('/login', (req, res) => {
    if(!req.body || !req.body.username) {
        res.json({
            'status': 'failed',
            'message': 'Request missing username field!'
        });

        return;
    }

    let username = req.body.username.toLowerCase();


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

    let getAssertion = generatePublicKeyCredentialRequestOptions(database.users[username].authenticators);
    getAssertion.status = 'ok';

    req.session.challenge = getAssertion.challenge;
    req.session.username  = username;

    res.json(getAssertion)
});

/**
 * https://w3c.github.io/webauthn/#sctn-verifying-assertion
 */
app.post('/verify-login', (req, res) => {
    let publicKeyCredential = req.body;

    const expectations = {
        origin: process.env.HOST || 'http://localhost:3000',
        challenge: req.session.challenge,
        authenticators: database.users[req.session.username].authenticators
    };

    try {

        const result = verifyExistingCredential(publicKeyCredential, expectations, { requireUserVerification: false });

        if (result.success !== true) {
            res.json({
                'status': 'failed',
                'message': result.message
            });
            return
        }

        res.json({
            'status': 'ok',
        })
    } catch (e) {
        console.error(e);
        res.json({
            'status': 'failed',
            'message': e.message
        })
    }


});


app.listen(port, () => console.log(`WebAuthn demo listening on port ${port}!`));
