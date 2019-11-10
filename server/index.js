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

    let challengeMakeCred = generatePublicKeyCredentialCreationOptions(username, userId);
    req.session.challenge = challengeMakeCred.challenge;
    req.session.username  = username;

    challengeMakeCred.status = 'ok';

    res.json(challengeMakeCred)
});

/**
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

app.post('/login', (req, res) => {
    if(!req.body || !req.body.username) {
        res.json({
            'status': 'failed',
            'message': 'Request missing username field!'
        });

        return;
    }

    let username = req.body.username;


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

    let getAssertion = generatePublicKeyCredentialRequestOptions(database.users[username].authenticators)
    getAssertion.status = 'ok'

    req.session.challenge = getAssertion.challenge;
    req.session.username  = username;

    res.json(getAssertion)
});

/**
 * https://w3c.github.io/webauthn/#sctn-verifying-assertion
 */
app.post('/verify-login', (req, res) => {
    let publicKeyCredential = req.body;
    console.log('publicKeyCredential')
    console.log(publicKeyCredential)

    const expectations = {
        origin: 'http://localhost:3000',
        challenge: req.session.challenge,
        authenticators: database.users[req.session.username].authenticators
    };

    try {

        const result = verifyExistingCredential(publicKeyCredential, expectations);

        console.log('result')

        console.log(JSON.stringify(result, null, 2))

        return
    } catch (e) {
        console.error(e)
        res.json({
            'status': 'failed',
            'message': e.message
        })
    }


})


app.listen(port, () => console.log(`Example app listening on port ${port}!`));
