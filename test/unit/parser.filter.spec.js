'use strict';


//global imports
const path = require('path');
const _ = require('lodash');
const chai = require('chai');
const express = require('express');
const request = require('supertest');
const expect = chai.expect;
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));

describe.only('filter', function () {

  it('should be a function', function () {
    expect(parser.filter).to.exist;
    expect(parser.filter).to.be.a('function');
  });


  describe('search', function () {

    it('should parse search query', function (done) {
      const query = { filters: { q: 'a' } };

      parser
        .filter(JSON.stringify(query), function (error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter.q).to.exist;
          expect(filter.q).to.be.eql(query.filters.q);
          done(error, filter);
        });

    });

    it('should parse search query', function (done) {

      const query = { q: 'a' };

      parser
        .filter(JSON.stringify(query), function (error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter.q).to.exist;
          expect(filter.q).to.be.eql(query.q);
          done(error, filter);
        });

    });

  });


  describe('comparison', function () {

    const comparisons = {
      $eq: { qty: { $eq: 20 } },
      $gt: { qty: { $gt: 20 } },
      $gte: { qty: { $gte: 20 } },
      $in: { qty: { $in: [5, 15] } },
      $lt: { qty: { $lt: 20 } },
      $lte: { qty: { $lte: 20 } },
      $ne: { qty: { $ne: 20 } },
      $nin: { qty: { $nin: [5, 15] } }
    };

    _.forEach(comparisons, function (comparison, key) {

      it('should parse fields ' + key + ' operator', function (done) {
        const query = { filters: comparison };

        parser
          .filter(JSON.stringify(query), function (error,
            filter) {
            expect(error).to.not.exist;
            expect(filter).to.exist;
            expect(filter).to.be.eql(comparison);
            done(error, filter);
          });
      });

    });

  });

  describe('logical', function () {

    const logicals = {
      $and: { $and: [{ price: { $ne: 1.99 } }, { price: { $exists: true } }] },
      $not: { price: { $not: { $gt: 1.99 } } },
      $or: { $or: [{ quantity: { $lt: 20 } }, { price: 10 }] },
      $nor: { $nor: [{ price: 1.99 }, { sale: true }] }
    };

    _.forEach(logicals, function (logical, key) {

      it('should parse fields ' + key + ' operator', function (done) {
        const query = { filters: logical };

        parser
          .filter(JSON.stringify(query), function (error,
            filter) {
            expect(error).to.not.exist;
            expect(filter).to.exist;
            expect(filter).to.be.eql(logical);
            done(error, filter);
          });
      });

    });

  });


  describe('element', function () {

    const elements = {
      $exists: { a: { $exists: true } },
      $type: { zipCode: { $type: 'string' } }
    };

    _.forEach(elements, function (element, key) {

      it('should parse fields ' + key + ' operator', function (done) {
        const query = { filters: element };

        parser
          .filter(JSON.stringify(query), function (error,
            filter) {
            expect(error).to.not.exist;
            expect(filter).to.exist;
            expect(filter).to.be.eql(element);
            done(error, filter);
          });
      });

    });

  });


  describe('http', function () {

    const app = express();
    app.use('/filter', function (request, response) {
      parser
        .filter(request.query, function (error, projections) {
          if (error) {
            throw error;
          } else {
            response.json(projections);
          }
        });
    });

    describe('search', function () {

      it('should parse search query', function (done) {
        const query = { filters: { q: 'a' } };

        request(app)
          .get('/filter')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const filter = response.body;
            expect(filter).to.exist;
            expect(filter.q).to.exist;
            expect(filter.q).to.be.eql(query.filters.q);
            done(error, response);
          });

      });

      it('should parse search query', function (done) {
        const query = { filters: { q: 'a' } };

        request(app)
          .get('/filter?q=a')
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const filter = response.body;
            expect(filter).to.exist;
            expect(filter.q).to.exist;
            expect(filter.q).to.be.eql(query.filters.q);
            done(error, response);
          });

      });

    });

    describe('comparison - query', function () {

      const comparisons = {
        $eq: { qty: { $eq: 20 } },
        $gt: { qty: { $gt: 20 } },
        $gte: { qty: { $gte: 20 } },
        $in: { qty: { $in: [5, 15] } },
        $lt: { qty: { $lt: 20 } },
        $lte: { qty: { $lte: 20 } },
        $ne: { qty: { $ne: 20 } },
        $nin: { qty: { $nin: [5, 15] } }
      };

      _.forEach(comparisons, function (comparison, key) {

        it('should parse fields ' + key + ' operator', function (
          done) {
          const query = { filters: comparison };

          request(app)
            .get('/filter')
            .query(query)
            .expect(200, function (error, response) {
              expect(error).to.not.exist;
              const filter = response.body;
              expect(filter).to.exist;
              expect(filter).to.be.eql(comparison);
              done(error, response);
            });
        });

      });


    });

    describe('comparison - json encoded', function () {

      const comparisons = {
        $eq: { qty: { $eq: 20 } },
        $gt: { qty: { $gt: 20 } },
        $gte: { qty: { $gte: 20 } },
        $in: { qty: { $in: [5, 15] } },
        $lt: { qty: { $lt: 20 } },
        $lte: { qty: { $lte: 20 } },
        $ne: { qty: { $ne: 20 } },
        $nin: { qty: { $nin: [5, 15] } }
      };

      _.forEach(comparisons, function (comparison, key) {

        it('should parse fields ' + key + ' operator', function (
          done) {
          const query = JSON.stringify(comparison);
          request(app)
            .get('/filter?filter=' + query)
            .expect(200, function (error, response) {
              expect(error).to.not.exist;
              const filter = response.body;
              expect(filter).to.exist;
              expect(filter).to.be.eql(comparison);
              done(error, response);
            });
        });

      });

    });

    describe('comparison - url encoded', function () {

      const comparisons = {
        $eq: {
          url: '[qty][$eq]=20',
          parsed: { qty: { $eq: 20 } }
        },
        $gt: {
          url: '[qty][$gt]=20',
          parsed: { qty: { $gt: 20 } }
        },
        $gte: {
          url: '[qty][$gte]=20',
          parsed: { qty: { $gte: 20 } }
        },
        $in: {
          url: '[qty][$in]=[5,15]',
          parsed: { qty: { $in: [5, 15] } }
        },
        $lt: {
          url: '[qty][$lt]=20',
          parsed: { qty: { $lt: 20 } }
        },
        $lte: {
          url: '[qty][$lte]=20',
          parsed: { qty: { $lte: 20 } }
        },
        $ne: {
          url: '[qty][$ne]=20',
          parsed: { qty: { $ne: 20 } }
        },
        $nin: {
          url: '[qty][$nin]=[5,15]',
          parsed: { qty: { $nin: [5, 15] } }
        }
      };

      _.forEach(comparisons, function (comparison, key) {

        it('should parse fields ' + key + ' operator', function (
          done) {

          request(app)
            .get('/filter?filter' + comparison.url)
            .expect(200, function (error, response) {
              expect(error).to.not.exist;
              const filter = response.body;
              expect(filter).to.exist;
              expect(filter).to.be.eql(comparison.parsed);
              done(error, response);
            });

        });

      });

    });

    describe('logical - query', function () {

      const logicals = {
        $and: { $and: [{ price: { $ne: 1.99 } }, { price: { $exists: true } }] },
        $not: { price: { $not: { $gt: 1.99 } } },
        $or: { $or: [{ quantity: { $lt: 20 } }, { price: 10 }] },
        $nor: { $nor: [{ price: 1.99 }, { sale: true }] }
      };

      _.forEach(logicals, function (logical, key) {

        it('should parse fields ' + key + ' operator', function (
          done) {
          const query = { filters: JSON.stringify(logical) };

          request(app)
            .get('/filter')
            .query(query)
            .expect(200, function (error, response) {
              expect(error).to.not.exist;
              const filter = response.body;
              expect(filter).to.exist;
              expect(filter).to.be.eql(logical);
              done(error, response);
            });
        });

      });

    });

    describe('element - query', function () {

      const elements = {
        $exists: { a: { $exists: true } },
        $type: { zipCode: { $type: 'string' } }
      };

      _.forEach(elements, function (element, key) {

        it('should parse fields ' + key + ' operator', function (
          done) {
          const query = { filters: JSON.stringify(element) };

          request(app)
            .get('/filter')
            .query(query)
            .expect(200, function (error, response) {
              expect(error).to.not.exist;
              const filter = response.body;
              expect(filter).to.exist;
              expect(filter).to.be.eql(element);
              done(error, response);
            });
        });

      });

    });

  });

});