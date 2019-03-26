var express = require('express');

const app = express();
app.set('view engine', 'ejs')
app.get('/', (req, res) => {
  res.send("Welcome to OAUth 2.0 1 Up Server")
})

app.get("/authorize", (req, res) => {
  res.status(501).render('error' , { "message" : "/authorize is not implemented yet"})
})
const PORT = 8500;

app.listen(PORT, () => console.log('All your tokens belong to us'))