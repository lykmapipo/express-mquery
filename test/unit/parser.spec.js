'use strict';


//global imports
const path = require('path');
const chai = require('chai');
const expect = chai.expect;


//local imports
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));


describe.only('parse', function() {

  describe('structure', function() {

    it('should be an object', function() {
      expect(parser).to.exist;
      expect(parser).to.be.an('object');
    });

    it('should have all required parser', function() {
      expect(parser.select).to.exist;
      expect(parser.distinct).to.exist;
    });

  });

  describe('select', function() {

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


  describe('populate', function() {

    it('should be a function', function() {
      expect(parser.populate).to.exist;
      expect(parser.populate).to.be.a('function');
    });


    it('should parse string based path population', function(done) {

      const _populate = { path: 'customer' };
      const query = { populate: 'customer' };

      parser
        .populate(JSON.stringify(query), function(error, populate) {
          expect(error).to.not.exist;
          expect(populate).to.exist;
          expect(populate).to.have.length(1);
          expect(populate[0]).to.eql(_populate);
          done(error, populate);
        });

    });


    it('should parse string based paths population', function(done) {

      const _populate = [{ path: 'customer' }, { path: 'items' }];
      const query = { populate: 'customer,items' };

      parser
        .populate(JSON.stringify(query), function(error, populate) {
          expect(error).to.not.exist;
          expect(populate).to.exist;
          expect(populate).to.have.length(2);
          expect(populate).to.eql(_populate);
          done(error, populate);
        });

    });

    it('should parse string based path with select population',
      function(done) {

        const _populate = { path: 'customer', select: { name: 1 } };
        const query = { populate: 'customer.name' };

        parser
          .populate(JSON.stringify(query), function(error, populate) {
            expect(error).to.not.exist;
            expect(populate).to.exist;
            expect(populate).to.have.length(1);
            expect(populate[0]).to.eql(_populate);
            done(error, populate);
          });

      });


    it('should parse string based paths with select population',
      function(done) {

        const _populate = [
          { path: 'customer', select: { name: 1 } },
          { path: 'items', select: { name: 1, price: 1 } }
        ];
        const query = { populate: 'customer.name,items.name,items.price' };

        parser
          .populate(JSON.stringify(query), function(error, populate) {
            expect(error).to.not.exist;
            expect(populate).to.exist;
            expect(populate).to.have.length(2);
            expect(populate).to.eql(_populate);
            done(error, populate);
          });

      });

    it('should parse string based paths with exclude select population',
      function(done) {

        const _populate = [
          { path: 'customer', select: { name: 1 } },
          { path: 'items', select: { price: 0 } }
        ];
        const query = { populate: 'customer.name,-items.price' };

        parser
          .populate(JSON.stringify(query), function(error, populate) {
            expect(error).to.not.exist;
            expect(populate).to.exist;
            expect(populate).to.have.length(2);
            expect(populate).to.eql(_populate);
            done(error, populate);
          });

      });

  });


});