'use strict';


//global imports
const path = require('path');
const chai = require('chai');
const express = require('express');
const request = require('supertest');
const expect = chai.expect;
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));

describe('sort', function () {

  it('should be a function', function () {
    expect(parser.sort).to.exist;
    expect(parser.sort).to.be.a('function');
    expect(parser.sort.name).to.be.equal('sort');
    expect(parser.sort.length).to.be.equal(2);
  });

  it('should parse json based sort', function (done) {
    const _sort = { name: 1, email: 1 };
    const query = { sort: _sort };

    parser
      .sort(JSON.stringify(query), function (error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });


  it('should parse json based sort', function (done) {
    const _sort = { name: 'desc', email: 'asc' };
    const query = { sort: _sort };

    parser
      .sort(JSON.stringify(query), function (error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });


  it('should parse json based sort', function (done) {
    const _sort = { name: 'descending', email: 'ascending' };
    const query = { sort: _sort };

    parser
      .sort(JSON.stringify(query), function (error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });


  it('should parse object based sort', function (done) {
    const _sort = { name: 1, email: 1 };
    const query = { sort: _sort };

    parser
      .sort(query, function (error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });

  it('should parse object based sort', function (done) {
    const _sort = { name: 'desc', email: 'asc' };
    const query = { sort: _sort };

    parser
      .sort(query, function (error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });

  it('should parse object based sort', function (done) {
    const _sort = { name: 'descending', email: 'ascending' };
    const query = { sort: _sort };

    parser
      .sort(query, function (error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });

  it('should parse string based sort', function (done) {
    const _sort = { name: 1, email: 1 };
    const query = { sort: 'name,email' };

    parser
      .sort(JSON.stringify(query), function (error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });


  it('should parse string based projection', function (done) {
    const _sort = { name: 0, email: 0 };
    const query = { sort: '-name,-email' };

    parser
      .sort(query, function (error, projection) {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(_sort);
        done(error, projection);
      });

  });

  describe('http', function () {

    const app = express();
    app.use('/sort', function (request, response) {
      parser
        .sort(request.query, function (error, sorts) {
          if (error) {
            throw error;
          } else {
            response.json(sorts);
          }
        });
    });

    it('should parse json based sort', function (done) {
      const _sort = { name: 1, email: 1 };
      const query = { sort: _sort };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, function (error, response) {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });


    it('should parse json based sort', function (done) {
      const _sort = { name: 'desc', email: 'asc' };
      const query = { sort: _sort };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, function (error, response) {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });


    it('should parse json based sort', function (done) {
      const _sort = { name: 'descending', email: 'ascending' };
      const query = { sort: _sort };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, function (error, response) {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse string based sort', function (done) {
      const _sort = { name: 1, email: 1 };
      const query = { sort: 'name,email' };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, function (error, response) {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });


    it('should parse string based projection', function (done) {
      const _sort = { name: 0, email: 0 };
      const query = { sort: '-name,-email' };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, function (error, response) {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse string based projection', function (done) {
      const _sort = { name: 0, email: 1 };
      const query = { sort: '-name,email' };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, function (error, response) {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse string based projection', function (done) {
      const _sort = { name: 0, email: 1 };

      request(app)
        .get('/sort?sort[name]=0&sort[email]=1')
        .expect(200, function (error, response) {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

  });

});