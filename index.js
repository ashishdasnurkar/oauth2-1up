var express = require('express');
var db = require('./db')
var randomstring = require('randomstring')
var moment = require('moment')


const app = express();
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
    redirectUri,
    user_id: "1"
  }

  // save in db
  db.saveCodeContext(context);

  const url = new URL(redirectUri)

  url.searchParams.set("code", code)
  // return res.status(501).render('error' , { "message" : "/authorize not fully implemented yet"})
  res.redirect(url)

})


const PORT = 8500;

app.listen(PORT, () => console.log('All your tokens belong to us'))