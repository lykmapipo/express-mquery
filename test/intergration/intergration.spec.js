'use strict';

//dependencies
var path = require('path');
var expect = require('chai').expect;
var request = require('supertest');
var express = require('express');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var mquery = require(path.join(__dirname, '..', '..'));
var init = require(path.join(__dirname, 'setup'))();

//setup express app
var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(mquery.middleware());

describe('express-mquery', function() {

    before(function(done) {
        init.initialize();
        init.seed(done);
    });

    before(function() {
        app.get('/customers', function(request, response) {
            var Customer = mongoose.model('Customer');

            Customer
                .mquery(request)
                .exec(function(error, users) {
                    if (error) {
                        response.status(500).json({
                            error: error.message
                        });
                    } else {
                        response.json(users);
                    }
                });
        });
    });

    after(function(done) {
        init.reset(done);
    });

    it('should export express middleware', function() {
        expect(mquery.middleware).to.be.a('function');
    });

    it('should export mongoose plugin', function() {
        var Customer = mongoose.model('Customer');
        expect(mquery.plugin).to.be.a('function');
        expect(Customer.mquery).to.be.a('function');
    });


    it('GET /customers 200', function(done) {

        request(app)
            .get('/customers')
            .query({
                select: 'firstName'
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
                expect(error).to.not.exist;
                expect(response.body.length).to.be.equal(3);
                done(error, response);
            });
    });

});