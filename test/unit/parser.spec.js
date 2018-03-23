'use strict';


//global imports
const path = require('path');
const chai = require('chai');
const expect = chai.expect;
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));

describe('parser', function() {

  it('should be an object', function() {
    expect(parser).to.exist;
    expect(parser).to.be.an('object');
  });

  it('should have all required parser', function() {
    expect(parser.distinct).to.exist;
    expect(parser.filter).to.exist;
    expect(parser.paginate).to.exist;
    expect(parser.populate).to.exist;
    expect(parser.select).to.exist;
    expect(parser.sort).to.exist;
  });

});