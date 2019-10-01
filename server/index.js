import express from "express";
import bodyParser from "body-parser";
import cookieSession from "cookie-session";
import crypto from "crypto";
import {generateServerMakeCredRequest, randomBase64URLBuffer,
    verifyAuthenticatorAttestationResponse, verifyAuthenticatorAssertionResponse} from "./security.js";
import path from 'path'
import url from 'url'
import base64url from "base64url";

const app = express();
const port = 3000;

const origin = 'http://localhost:3000';

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
    users: []
};

app.post('/register', (req, res) => {
    if (!req.body.username) {
        res.json({error: 'Username is required'});
        return
    }
    const username = req.body.username.toLowerCase();
    database.users.find((user) => user.username === username);
    if (database.users.find((user) => user.username === username)) {
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


    res.json(challengeMakeCred)
});

app.post('/save-new-key', (req, res) => {
    console.log(req.body);
    if (!req.body || !req.body.id
        || !req.body.rawId || !req.body.response
        || !req.body.type || req.body.type !== 'public-key') {
        res.json({
            'status': 'failed',
            'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        });
        return
    }

    let webauthnResp = req.body;
    const clientData = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

    const clientChallenge = base64url.decode(clientData.challenge);

    /* Check challenge... */
    if (clientChallenge !== req.session.challenge) {
        res.json({
            'status': 'failed',
            'message': 'Challenges don\'t match!'
        });
        return
    }

    /* ...and origin */
    if (clientData.origin !== origin) {
        res.json({
            'status': 'failed',
            'message': 'Origins don\'t match!'
        });
        return
    }

    let result;

    if(webauthnResp.response.attestationObject !== undefined) {
        /* This is create cred */
        console.log('This is create');
        result = verifyAuthenticatorAttestationResponse(webauthnResp);

        if(result.verified) {
            database[req.session.username].authenticators.push(result.authrInfo);
            database[req.session.username].registered = true
        }
    } else if(webauthnResp.response.authenticatorData !== undefined) {
        /* This is get assertion */
        console.log('This is login');

        result = verifyAuthenticatorAssertionResponse(webauthnResp, database[req.session.username].authenticators);
    } else {
        res.json({
            'status': 'failed',
            'message': 'Can not determine type of response!'
        })
    }

    if(result.verified) {
        req.session.loggedIn = true;
        res.json({ 'status': 'ok' })
    } else {
        res.json({
            'status': 'failed',
            'message': 'Can not authenticate signature!'
        })
    }
});

app.post('/login', (req, res) => {
    if(!req.body || !req.body.username) {
        res.json({
            'status': 'failed',
            'message': 'Request missing username field!'
        });


    }
});


app.listen(port, () => console.log(`Example app listening on port ${port}!`));
