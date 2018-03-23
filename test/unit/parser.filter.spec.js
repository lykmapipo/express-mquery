'use strict';


//global imports
const path = require('path');
const chai = require('chai');
const expect = chai.expect;
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));

describe('filter', function() {

  it('should be a function', function() {
    expect(parser.filter).to.exist;
    expect(parser.filter).to.be.a('function');
  });


  describe('search', function() {

    it('should parse search query', function(done) {
      const query = { filters: { q: 'a' } };

      parser
        .filter(JSON.stringify(query), function(error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter.q).to.exist;
          expect(filter.q).to.be.eql(query.filters.q);
          done(error, filter);
        });

    });

    it('should parse search query', function(done) {

      const query = { q: 'a' };

      parser
        .filter(JSON.stringify(query), function(error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter.q).to.exist;
          expect(filter.q).to.be.eql(query.q);
          done(error, filter);
        });

    });

  });

});