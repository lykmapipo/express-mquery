'use strict';


//global imports
const path = require('path');
const chai = require('chai');
const express = require('express');
const request = require('supertest');
const expect = chai.expect;
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));

describe.only('select', function() {

  it('should be a function', function() {
    expect(parser.select).to.exist;
    expect(parser.select).to.be.a('function');
    expect(parser.select.name).to.be.equal('select');
    expect(parser.select.length).to.be.equal(2);
  });

  describe('fields', function() {

    it('should parse json based projection', function(done) {
      const fields = { name: 1, email: 1 };
      const query = { fields: fields };

      parser
        .select(JSON.stringify(query), function(error,
          projection) {
          expect(error).to.not.exist;
          expect(projection).to.exist;
          expect(projection).to.eql(fields);
          done(error, projection);
        });

    });


    it('should parse object based projection', function(
      done) {
      const fields = { name: 1, email: 1 };
      const query = { fields: fields };

      parser
        .select(query, function(error, projection) {
          expect(error).to.not.exist;
          expect(projection).to.exist;
          expect(projection).to.eql(fields);
          done(error, projection);
        });

    });

    it('should parse string based projection', function(done) {
      const fields = { name: 1, email: 1 };
      const query = { fields: 'name,email' };

      parser
        .select(JSON.stringify(query), function(error,
          projection) {
          expect(error).to.not.exist;
          expect(projection).to.exist;
          expect(projection).to.eql(fields);
          done(error, projection);
        });

    });


    it('should parse string based projection', function(
      done) {
      const fields = { name: 0, email: 0 };
      const query = { fields: '-name,-email' };

      parser
        .select(query, function(error, projection) {
          expect(error).to.not.exist;
          expect(projection).to.exist;
          expect(projection).to.eql(fields);
          done(error, projection);
        });

    });

  });


  describe('select', function() {

    it('should parse json based projection', function(done) {
      const select = { name: 1, email: 1 };
      const query = { select: select };

      parser
        .select(JSON.stringify(query), function(error,
          projection) {
          expect(error).to.not.exist;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, projection);
        });

    });


    it('should parse object based projection', function(
      done) {
      const select = { name: 1, email: 1 };
      const query = { select: select };

      parser
        .select(query, function(error, projection) {
          expect(error).to.not.exist;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, projection);
        });

    });

    it('should parse string based projection', function(done) {
      const select = { name: 1, email: 1 };
      const query = { select: 'name,email' };

      parser
        .select(JSON.stringify(query), function(error,
          projection) {
          expect(error).to.not.exist;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, projection);
        });

    });


    it('should parse string based projection', function(
      done) {
      const select = { name: 0, email: 0 };
      const query = { select: '-name,-email' };

      parser
        .select(query, function(error, projection) {
          expect(error).to.not.exist;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, projection);
        });

    });

  });


  describe('http', function() {

    const app = express();
    app.use('/select', function(request, response) {
      console.log('http request query: ', request.query);
      parser.select(request.query, function(error, projections) {
        if (error) {
          throw error;
        } else {
          response.json(projections);
        }
      });
    });

    it('should parse json based projection', function(done) {
      const select = { name: 1, email: 1 };
      const query = { select: select };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, function(error, response) {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse json based projection', function(done) {
      const select = { name: 0, email: 0 };
      const query = { select: select };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, function(error, response) {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse json based projection', function(done) {
      const select = { 'location.name': 1, 'location.address': 1 };
      const query = { select: select };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, function(error, response) {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse string based projection', function(done) {
      const select = { name: 1, email: 1 };
      const query = { select: 'name,email' };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, function(error, response) {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse string based projection', function(done) {
      const select = { 'location.name': 1, 'location.address': 1 };
      const query = { select: 'location.name,location.address' };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, function(error, response) {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });


    it('should parse string based projection', function(
      done) {
      const select = { name: 0, email: 0 };
      const query = { select: '-name,-email' };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, function(error, response) {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });


    it('should parse string based projection', function(done) {
      const select = { 'location.name': 0, 'location.address': 0 };
      const query = { select: '-location.name,-location.address' };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, function(error, response) {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should check populate & select');
    //?includes=profile&fields[profile]=name

  });


});