'use strict';


//global imports
const path = require('path');
const _ = require('lodash');
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

    it('should parse object based population', function(done) {
      const _populate = { path: 'customer' };
      const query = { populate: _populate };

      parser
        .populate(query, function(error, populate) {
          expect(error).to.not.exist;
          expect(populate).to.exist;
          expect(populate[0]).to.eql(_populate);
          done(error, populate);
        });

    });

    it('should parse object based population with string select',
      function(done) {
        const _populate = { path: 'customer', select: { name: 1 } };
        const query = { populate: { path: 'customer', select: 'name' } };

        parser
          .populate(query, function(error, populate) {
            expect(error).to.not.exist;
            expect(populate).to.exist;
            expect(populate[0]).to.eql(_populate);
            done(error, populate);
          });

      });

    it('should parse object based population with string select',
      function(done) {
        const _populate = {
          path: 'customer',
          select: {
            name: 1,
            price: 0
          }
        };
        const query = { populate: { path: 'customer', select: 'name,-price' } };

        parser
          .populate(query, function(error, populate) {
            expect(error).to.not.exist;
            expect(populate).to.exist;
            expect(populate[0]).to.eql(_populate);
            done(error, populate);
          });

      });

    it('should parse array based population', function(done) {
      const _populate = [{ path: 'customer' }, { path: 'items' }];
      const query = { populate: _populate };

      parser
        .populate(query, function(error, populate) {
          expect(error).to.not.exist;
          expect(populate).to.exist;
          expect(populate).to.eql(_populate);
          done(error, populate);
        });

    });


    it('should parse array based population with selection',
      function(done) {
        const _populate = [
          { path: 'customer', select: { name: 1 } },
          { path: 'items', select: { name: 1, price: 0 } }
        ];
        const query = {
          populate: [
            { path: 'customer', select: 'name' },
            { path: 'items', select: 'name,-price' }
          ]
        };

        parser
          .populate(query, function(error, populate) {
            expect(error).to.not.exist;
            expect(populate).to.exist;
            expect(populate).to.eql(_populate);
            done(error, populate);
          });

      });

  });

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


  describe('filters', function() {

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


});