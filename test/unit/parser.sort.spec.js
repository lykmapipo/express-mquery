'use strict';


//global imports
const path = require('path');
const chai = require('chai');
const expect = chai.expect;
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));

describe('sort', function() {

  it('should be a function', function() {
    expect(parser.sort).to.exist;
    expect(parser.sort).to.be.a('function');
  });

  it('should parse json based sort', function(done) {
    const _sort = { name: 1, email: 1 };
    const query = { sort: _sort };

    parser
      .sort(JSON.stringify(query), function(error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });


  it('should parse json based sort', function(done) {
    const _sort = { name: 'desc', email: 'asc' };
    const query = { sort: _sort };

    parser
      .sort(JSON.stringify(query), function(error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });


  it('should parse json based sort', function(done) {
    const _sort = { name: 'descending', email: 'ascending' };
    const query = { sort: _sort };

    parser
      .sort(JSON.stringify(query), function(error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });


  it('should parse object based sort', function(done) {
    const _sort = { name: 1, email: 1 };
    const query = { sort: _sort };

    parser
      .sort(query, function(error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });

  it('should parse object based sort', function(done) {
    const _sort = { name: 'desc', email: 'asc' };
    const query = { sort: _sort };

    parser
      .sort(query, function(error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });

  it('should parse object based sort', function(done) {
    const _sort = { name: 'descending', email: 'ascending' };
    const query = { sort: _sort };

    parser
      .sort(query, function(error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });

  it('should parse string based sort', function(done) {
    const _sort = { name: 1, email: 1 };
    const query = { sort: 'name,email' };

    parser
      .sort(JSON.stringify(query), function(error, sort) {
        expect(error).to.not.exist;
        expect(sort).to.exist;
        expect(sort).to.eql(_sort);
        done(error, sort);
      });

  });


  it('should parse string based projection', function(done) {
    const _sort = { name: 0, email: 0 };
    const query = { sort: '-name,-email' };

    parser
      .sort(query, function(error, projection) {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(_sort);
        done(error, projection);
      });

  });

});