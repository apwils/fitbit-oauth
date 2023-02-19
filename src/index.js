require('dotenv').config()
const { randomBytes, createHash } = require("crypto");
const express = require('express')
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const cookieParser = require('cookie-parser');
const app = express()

app.use(express.json())
app.use(cookieParser());
app.use(express.static('public'))

app.get('/api/oauth', (req, res) => {
    let { challenge, verifier } = generatePKCEPair()
    console.log(verifier)
    var cookie = req.cookies.PKCE;
    if (cookie === undefined) {
        res.cookie('PKCE', verifier, { maxAge: 900000 });
    }
    res.json({ url: `https://www.fitbit.com/oauth2/authorize?client_id=${process.env.CLIENT_ID}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&scope=activity%20heartrate%20location%20nutrition%20oxygen_saturation%20profile%20respiratory_rate%20settings%20sleep%20social%20temperature%20weight` })
})

app.get('/auth', async (req, res) => {
    let { code } = req.query
    var verifier = req.cookies.PKCE;
    console.log(verifier)
    let response = await fetch(`https://api.fitbit.com/oauth2/token?client_id=${process.env.CLIENT_ID}&code=${code}&code_verifier=${verifier}&grant_type=authorization_code`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64')}`
        }
    })
    let data = await response.json()
    console.log(data)
    var cookie = req.cookies.OAUTH;
    if (cookie === undefined) {
        res.cookie('OAUTH', JSON.stringify(data), { maxAge: 900000 });
    }
    res.redirect('/')
})

app.listen(3000)

function generatePKCEPair() {
    const NUM_OF_BYTES = 22; // Total of 44 characters (1 Bytes = 2 char) (standard states that: 43 chars <= verifier <= 128 chars)
    const HASH_ALG = "sha256";
    const randomVerifier = randomBytes(NUM_OF_BYTES).toString('hex')
    const hash = createHash(HASH_ALG).update(randomVerifier).digest('base64');
    const challenge = hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); // Clean base64 to make it URL safe
    return { verifier: randomVerifier, challenge }
}


console.log()