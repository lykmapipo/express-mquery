'use strict';


//global imports
const path = require('path')
const express = require('express');
const bodyParser = require('body-parser');

//local imports
const parse = require(path.join(__dirname, '..', 'lib', 'parser')).parse;

//prepare express app
const app = express();

//bind body parsing middlewares
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json({ limit: '2mb' }));

//TODO add express-mquery middleware

app.get('/', function(request, response) {
  console.log('before: ', request.query);
  parse(request.query, function(error, query) {
    console.log('after: ', query);
    response.json(error || query);
  });

});

app.listen(9999);