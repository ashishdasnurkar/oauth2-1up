var express = require('express');
var db = require('./db')
var randomstring = require('randomstring')
var moment = require('moment')


const app = express();
// app.use(express.urlencoded({ extended: true}))
app.use(express.json())

app.set('view engine', 'ejs')


app.get('/', (req, res) => {
  res.send("Welcome to OAUth 2.0 1 Up Server")
})

app.get("/authorize", (req, res) => {
  const clientID = req.query.client_id
  if(!clientID) {
    return res.status(400).render('error' , { "message" : "Missing required parameter: client_id"})
  }

  const client = db.getClientByID(clientID)
  if(!client) {
    return res.status(400).render('error' , { "message" : "Invalid client ID"})
  }

  const responseType = req.query.response_type
  if(!responseType) {
    return res.status(400).render('error' , { "message" : "Missing required parameter: response_type"})
  }

  const supportedResTypes = ['code']
  if(!supportedResTypes.includes(responseType)) {
    return res.status(400).render('error' , { "message" : "Invalid response type"})
  }

  // Redirect URI validation
  const validURIs = client.redirect_uris
  if (!validURIs || !validURIs.length) {
    return res.status(400).render('error', { message: 'No redirect URIs configured for the client' })
  }

  let redirectUri = req.query.redirect_uri || null
  if (redirectUri && !validURIs.includes(redirectUri)) {
    return res.status(400).render('error', { message: 'Invalid redirect URI: ' + redirectUri })
  }
  if (!redirectUri) {
    redirectUri = validURIs[0]
  }

  // check session
  // If no session, redirect to /login

  const code = randomstring.generate({length: 32, charset: "alphanumeric"})
  const expiresAt = moment().add(10, 'minutes').valueOf()
  const context = {
    code,
    clientID,
    expiresAt,
    redirectUri:  req.query.redirect_uri,
    user_id: "1"
  }

  // save in db
  db.saveCodeContext(context);

  const url = new URL(redirectUri)

  url.searchParams.set("code", code)
  // return res.status(501).render('error' , { "message" : "/authorize not fully implemented yet"})
  res.redirect(url)

})

app.post('/token', (req, res) => {
  const body = req.body || {}
  const grant = body.grant_type
  if(!grant) {
    return res.status(400).json({'error' : 'invalid_grant', 'error description': 'Missing grant type' })
  }
  if(grant != "authorization_code") {
    return res.status(400).json({'error' : 'unsupported_grant_type', 'error_description': 'Unsupported grant type' })
  }

  const auth = req.headers["authorization"]
  let client = null
  if(auth) {
    // basic auth
    const parts = auth.trim().split(" ")
    if(parts.length != 2 || parts[0].toLowerCase() !== 'basic' ) {
      res.set("WWW-Authenticate", "Basic")
      return res.status(401).send({"error" : "invalid_client", "error_description" : "Unsupported client authentication method"})
    }

    const creds = Buffer.from(parts[1], "base64").toString('ascii').split(":")
    client = db.getClientByID(creds[0])

    if(!client || client.secret !== creds[1]) {
      res.set("WWW-Authenticate", "Basic")
      return res.status(401).send({"error" : "invalid_client", "error_description" : "invalid client or secret"})
    }
  } else {
    // json body auth
    if(!body.client_id || !body.client_secret) {
      return res.status(401).send({"error" : "invalid_client", "error_description" : "Client authentication failed"})
    }
    client = db.getClientByID(body.client_id)
    if(!client || client.secret !== body.client_secret) {
      res.set("WWW-Authenticate", "Basic")
      return res.status(401).send({"error" : "invalid_client", "error_description" : "invalid client or secret"})
    }
  }

  if(!body.code) {
    return res.status(400).send({"error" : "invalid_request", "error_description" : "missing required parameter: code"})
  }

  const ctx = db.getCodeContext(body.code)

  if(!ctx) {
    return res.status(400).send({"error" : "invalid_grant", "error_description" : "Invalid authorization code"})
  }

  db.deleteCodeContext(body.code)


  if(moment().isAfter(ctx.expiresAt)) {
    return res.status(400).send({"error" : "invalid_grant", "error_description" : "Expired authorization code"})
  }

  if(ctx.clientID !== client.id) {
    return res.status(400).send({"error" : "invalid_grant", "error_description" : "Invalid authorization code"})
  }

  if(ctx.redirectUri) {
    if(body.redirect_uri !== ctx.redirectUri) {
      return res.status(400).send({"error" : "invalid_grant", "error_description" : "Invalid redirect uri"})
    }
  }

  const token = 'at-' + randomstring.generate({length: 32, charset: 'alphanumeric'})
  const tokenCtx = {
    token,
    expiresIn: moment().add(120, 'minutes').valueOf(),
    clientID: ctx.clientID,
    userID: ctx.userID,
  }
  db.saveAccessToken(tokenCtx);
  res.set('Cache-Control', 'no-store')
  res.set('Pragma', 'no-cache')
  res.status(200).json({
    access_token: token,
    token_type: "Bearer",
    expires_in: 120 * 60
  })
})


const PORT = 8500;

app.listen(PORT, () => console.log('All your tokens belong to us'))