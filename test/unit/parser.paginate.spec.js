'use strict';


//global imports
const path = require('path');
const chai = require('chai');
const expect = chai.expect;
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));

describe('paginate', function() {

  it('should be a function', function() {
    expect(parser.paginate).to.exist;
    expect(parser.paginate).to.be.a('function');
  });

  describe('limit', function() {

    it('should parse limit when not specified', function(done) {

      const query = {};

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.eql(10);
          done(error, paginate);
        });

    });


    it('should parse limit', function(done) {

      const query = { limit: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.eql(query.limit);
          done(error, paginate);
        });

    });

    it('should parse limit from max', function(done) {

      const query = { max: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.eql(query.max);
          done(error, paginate);
        });

    });

    it('should parse limit from size', function(done) {

      const query = { size: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.eql(query.size);
          done(error, paginate);
        });

    });

    it('should parse limit from rpp', function(done) {

      const query = { rpp: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.eql(query.rpp);
          done(error, paginate);
        });

    });

    it('should parse limit from count', function(done) {

      const query = { count: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.eql(query.count);
          done(error, paginate);
        });

    });

    it('should parse limit from perPage', function(done) {

      const query = { perPage: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.eql(query.perPage);
          done(error, paginate);
        });

    });

    it('should parse limit from per_page', function(done) {

      const query = {
        'per_page': 10
      };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit)
            .to.be.eql(_.get(query, 'per_page'));
          done(error, paginate);
        });

    });

    it('should parse limit from cursor', function(done) {

      const query = {
        cursor: 10
      };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.eql(query.cursor);
          done(error, paginate);
        });

    });

  });

  describe('skip', function() {

    it('should parse skip when not specified', function(done) {

      const query = {};

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.skip).to.be.eql(0);
          done(error, paginate);
        });

    });


    it('should parse skip', function(done) {

      const query = { skip: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.skip).to.be.eql(query.skip);
          done(error, paginate);
        });

    });

    it('should parse skip from offset', function(done) {

      const query = { offset: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.skip).to.be.eql(query.offset);
          done(error, paginate);
        });

    });

    it('should parse skip from start', function(done) {

      const query = { start: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.skip).to.be.eql(query.start);
          done(error, paginate);
        });

    });

  });

  describe('page', function() {

    it('should parse page when not specified', function(done) {

      const query = {};

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.page).to.exist;
          expect(paginate.page).to.be.eql(1);
          done(error, paginate);
        });

    });


    it('should parse page', function(done) {

      const query = { page: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.page).to.exist;
          expect(paginate.page).to.be.eql(query.page);
          done(error, paginate);
        });

    });

    it('should parse', function(done) {

      const query = { number: 10, size: 10 };

      parser
        .paginate(JSON.stringify(query), function(error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.page).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.page).to.be.eql(query.number);
          expect(paginate.limit).to.be.eql(query.size);
          done(error, paginate);
        });

    });

  });

});