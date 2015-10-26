'use strict';

//dependencies
var path = require('path');
var expect = require('chai').expect;
var mquery = require(path.join(__dirname, '..', '..'));

//load schemas
// require(path.join(__dirname, '..', 'models', 'User'));


describe('express-mquery', function() {

    it('should export express middleware', function() {
        expect(mquery.middleware).to.be.a('function');
    });

    it('should export mongoose plugin', function() {
        expect(mquery.mquery).to.be.a('function');
    });
});