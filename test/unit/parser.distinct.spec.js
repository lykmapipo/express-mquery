'use strict';


//global imports
const path = require('path');
const chai = require('chai');
const expect = chai.expect;


//local imports
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));


describe('distinct', function() {

  it('should be a function', function() {
    expect(parser.distinct).to.exist;
    expect(parser.distinct).to.be.a('function');
  });

  it('should parse', function(done) {

    const _distinct = 'name';
    const query = { distinct: 'name' };

    parser
      .distinct(query, function(error, distinct) {
        expect(error).to.not.exist;
        expect(distinct).to.exist;
        expect(distinct).to.eql(_distinct);
        done(error, distinct);
      });

  });

});