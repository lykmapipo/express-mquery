'use strict';


//global imports
const path = require('path');
const _ = require('lodash');
const express = require('express');
const bodyParser = require('body-parser');

//local imports
const mquery = require(path.join(__dirname, '..'));

//prepare express app
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({ limit: '2mb' }));
app.use(mquery());

//handle requests
app.get('/', function (request, response) {
  const options = _.merge({}, request.mquery);
  console.log(options);
  response.json(options);
});

const PORT = 3000;
app.listen(PORT, function (error) {
  if (error) {
    throw error;
  } else {
    console.log(`visit http://0.0.0.0:${PORT}`);
  }
});