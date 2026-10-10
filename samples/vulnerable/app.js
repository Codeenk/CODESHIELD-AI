// Deliberately vulnerable sample — used by the demo and tests.
const express = require("express");
const app = express();

app.get("/user", (req, res) => {
  // SQL injection via string interpolation
  db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`, (err, rows) => {
    res.send(rows);
  });
});

function renderProfile(name, el) {
  // DOM XSS
  el.innerHTML = "<h1>Hello " + name + "</h1>";
}

app.get("/fetch", async (req, res) => {
  // SSRF
  const data = await fetch("http://internal/" + req.query.path);
  res.send(await data.text());
});

// Prototype pollution via deep merge of request body
function merge(target, req) {
  return Object.assign(target, req.body);
}

module.exports = app;
