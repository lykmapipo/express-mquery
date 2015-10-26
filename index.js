'use strict';

//dependencies
var path = require('path');
var parser = require(path.join(__dirname, 'lib', 'parser'));
var middleware = require(path.join(__dirname, 'lib', 'middleware'));

//export express middleware
exports.middleware = middleware;

//export mongoose plugin
exports.parser = parser;