'use strict';


//global imports
const path = require('path');
const chai = require('chai');
const expect = chai.expect;


//local imports
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));


describe.only('select', function() {

  it('should be a function', function() {
    expect(parser.select).to.exist;
    expect(parser.select).to.be.a('function');
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


});