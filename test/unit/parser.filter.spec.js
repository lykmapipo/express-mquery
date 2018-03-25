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
    expect(parser.filter.name).to.be.equal('filter');
    expect(parser.filter.length).to.be.equal(2);
  });

  describe('by search', function () {

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


  describe('by comparison query operators', function () {

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

        function next(error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(comparison);
          done(error, filter);
        }

        parser.filter(JSON.stringify(query), next);

      });

    });

  });


  describe('by logical query operators', function () {

    const logicals = {
      $and: { $and: [{ price: { $ne: 1.99 } }, { price: { $exists: true } }] },
      $not: { price: { $not: { $gt: 1.99 } } },
      $or: { $or: [{ quantity: { $lt: 20 } }, { price: 10 }] },
      $nor: { $nor: [{ price: 1.99 }, { sale: true }] }
    };

    _.forEach(logicals, function (logical, key) {

      it('should parse fields ' + key + ' operator', function (done) {
        const query = { filters: logical };

        function next(error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(logical);
          done(error, filter);
        }

        parser.filter(JSON.stringify(query), next);

      });

    });

  });


  describe('by element query operators', function () {

    const elements = {
      $exists: { a: { $exists: true } },
      $type: { zipCode: { $type: 'string' } }
    };

    _.forEach(elements, function (element, key) {

      it('should parse fields ' + key + ' operator', function (done) {
        const query = { filters: element };

        function next(error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(element);
          done(error, filter);
        }

        parser.filter(JSON.stringify(query), next);

      });

    });

  });


  describe('by evaluation query operators', function () {

    const evaluations = {
      $expr: { $expr: { $gt: ['$spent', '$budget'] } },
      $jsonSchema: {},
      $mod: { qty: { $mod: [4, 0] } },
      $regex: { sku: { $regex: '/789$/' } },
      $text: { $text: { $search: 'coffee' } },
      $$where: {}
    };

    _.forEach(evaluations, function (evaluation, key) {

      it('should parse fields ' + key + ' operator', function (done) {
        const query = { filters: evaluation };

        function next(error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(evaluation);
          done(error, filter);
        }

        parser.filter(JSON.stringify(query), next);

      });

    });

  });


  describe('by geospatial query operators', function () {

    const geospatials = {
      $geoIntersects: {
        loc: {
          $geoIntersects: {
            $geometry: {
              type: 'Polygon',
              coordinates: [
                [
                  [0, 0],
                  [3, 6],
                  [6, 1],
                  [0, 0]
                ]
              ]
            }
          }
        }
      },
      $geoWithin: {
        loc: {
          $geoWithin: {
            $geometry: {
              type: 'Polygon',
              coordinates: [
                [
                  [0, 0],
                  [3, 6],
                  [6, 1],
                  [0, 0]
                ]
              ]
            }
          }
        }
      },
      $near: {
        loc: {
          $near: {
            $geometry: { type: 'Point', coordinates: [-73.9667, 40.78] },
            $minDistance: 1000,
            $maxDistance: 5000
          }
        }
      },
      $nearSphere: {
        loc: {
          $nearSphere: {
            $geometry: {
              type: 'Point',
              coordinates: [-73.9667, 40.78]
            },
            $minDistance: 1000,
            $maxDistance: 5000
          }
        }
      },
      $box: {
        loc: {
          $geoWithin: {
            $box: [
              [0, 0],
              [100, 100]
            ]
          }
        }
      },
      $center: {
        loc: {
          $geoWithin: {
            $center: [
              [-74, 40.74], 10
            ]
          }
        }
      },
      $centerSphere: {
        loc: {
          $geoWithin: {
            $centerSphere: [
              [-88, 30], 10 / 3963.2
            ]
          }
        }
      },
      $maxDistance: {
        loc: {
          $near: [-74, 40],
          $maxDistance: 10
        }
      },
      $minDistance: {
        loc: {
          $near: [-74, 40],
          $minDistance: 10
        }
      },
      $polygon: {
        loc: {
          $geoWithin: {
            $polygon: [
              [0, 0],
              [3, 6],
              [6, 0]
            ]
          }
        }
      }
    };

    _.forEach(geospatials, function (geospatial, key) {

      it('should parse fields ' + key + ' operator', function (done) {
        const query = { filters: geospatial };

        function next(error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(geospatial);
          done(error, filter);
        }

        parser.filter(JSON.stringify(query), next);

      });

    });

  });


  describe('by array query operators', function () {

    const arrays = {
      $all: {
        tags: {
          $all: [
            ['ssl', 'security']
          ]
        }
      },
      $elemMatch: { results: { $elemMatch: { $gte: 80, $lt: 85 } } },
      $size: { field: { $size: 1 } }
    };

    _.forEach(arrays, function (array, key) {

      it('should parse fields ' + key + ' operator', function (done) {
        const query = { filters: array };

        function next(error, filter) {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(array);
          done(error, filter);
        }

        parser.filter(JSON.stringify(query), next);

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