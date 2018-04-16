'use strict';


//global imports
const path = require('path');
const _ = require('lodash');
const chai = require('chai');
const express = require('express');
const request = require('supertest');
const expect = chai.expect;
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));

describe('headers', function () {

  it('should be a function', function () {
    expect(parser.headers).to.exist;
    expect(parser.headers).to.be.a('function');
    expect(parser.headers.name).to.be.equal('headers');
    expect(parser.headers.length).to.be.equal(2);
  });

  it('should parse json based headers', function (done) {
    const query = {
      headers: {
        'if-modified-since': new Date().toISOString()
      }
    };
    const expected = {
      ifModifiedSince: new Date(query.headers['if-modified-since'])
    };

    parser
      .headers(JSON.stringify(query), function (error, headers) {
        expect(error).to.not.exist;
        expect(headers).to.exist;
        expect(headers).to.eql(expected);
        done(error, headers);
      });

  });

  it('should parse object based headers', function (done) {
    const query = {
      headers: {
        'if-modified-since': new Date().toISOString()
      }
    };
    const expected = {
      ifModifiedSince: new Date(query.headers['if-modified-since'])
    };

    parser
      .headers(query, function (error, headers) {
        expect(error).to.not.exist;
        expect(headers).to.exist;
        expect(headers).to.eql(expected);
        done(error, headers);
      });

  });


  describe('http', function () {

    const app = express();
    app.use('/headers', function (request, response) {
      const query =
        _.merge({}, request.query, { headers: request.headers });
      parser
        .headers(query, function (error, headers) {
          if (error) {
            throw error;
          } else {
            response.json(headers);
          }
        });
    });

    it('should parse json based headers', function (done) {
      const query = {
        headers: {
          'if-modified-since': new Date().toISOString()
        }
      };
      const expected = {
        ifModifiedSince: query.headers['if-modified-since']
      };

      request(app)
        .get('/headers')
        .query(query)
        .expect(200, function (error, response) {
          expect(error).to.not.exist;
          const headers = response.body;
          expect(headers).to.exist;
          expect(headers).to.eql(expected);
          done(error, response);
        });
    });

    it('should parse http based headers', function (done) {
      const date = new Date().toISOString();
      const expected = {
        ifModifiedSince: date
      };

      request(app)
        .get('/headers')
        .set('If-Modified-Since', date)
        .expect(200, function (error, response) {
          expect(error).to.not.exist;
          const headers = response.body;
          expect(headers).to.exist;
          expect(headers).to.eql(expected);
          done(error, response);
        });
    });

  });

});