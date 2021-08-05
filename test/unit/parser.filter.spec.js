import { _ } from 'lodash';
import qs from 'qs';
import chai from 'chai';
import express from 'express';
import request from 'supertest';
import * as parser from '../../src';

const { expect } = chai;

describe('filter', () => {
  const app = express();
  app.use('/filter', (req, response) => {
    parser.filter(req.query, (error, projections) => {
      if (error) {
        throw error;
      } else {
        response.json(projections);
      }
    });
  });

  it('should be a function', () => {
    expect(parser.filter).to.exist;
    expect(parser.filter).to.be.a('function');
    expect(parser.filter.name).to.be.equal('filter');
    expect(parser.filter.length).to.be.equal(2);
  });

  describe('by search', () => {
    it('should parse search query', (done) => {
      const query = { filters: { q: 'a' } };
      parser.filter(JSON.stringify(query), (error, filter) => {
        expect(error).to.not.exist;
        expect(filter).to.exist;
        expect(filter.q).to.exist;
        expect(filter.q).to.be.eql(query.filters.q);
        done(error, filter);
      });
    });

    it('should parse search query', (done) => {
      const query = { q: 'a' };
      parser.filter(JSON.stringify(query), (error, filter) => {
        expect(error).to.not.exist;
        expect(filter).to.exist;
        expect(filter.q).to.exist;
        expect(filter.q).to.be.eql(query.q);
        done(error, filter);
      });
    });

    it('should parse http uri encode search query', (done) => {
      const query = { filters: { q: 'a' } };

      request(app)
        .get('/filter')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const filter = response.body;
          expect(filter).to.exist;
          expect(filter.q).to.exist;
          expect(filter.q).to.be.eql(query.filters.q);
          done(error, response);
        });
    });

    it('should parse http uri encode search query', (done) => {
      const query = { filters: { q: 'a' } };

      request(app)
        .get('/filter?q=a')
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const filter = response.body;
          expect(filter).to.exist;
          expect(filter.q).to.exist;
          expect(filter.q).to.be.eql(query.filters.q);
          done(error, response);
        });
    });
  });

  describe('by comparison query operators', () => {
    const comparisons = {
      $eq: { qty: { $eq: 20 } },
      $gt: { qty: { $gt: 20 } },
      $gte: { qty: { $gte: 20 } },
      $in: { qty: { $in: [5, 15] } },
      $lt: { qty: { $lt: 20 } },
      $lte: { qty: { $lte: 20 } },
      $ne: { qty: { $ne: 20 } },
      $nin: { qty: { $nin: [5, 15] } },
    };

    _.forEach(comparisons, (comparison, key) => {
      const encoded = qs.stringify({ filters: comparison });

      it(`should parse fields ${key} operator`, (done) => {
        const query = { filters: comparison };

        const next = (error, filter) => {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(comparison);
          done(error, filter);
        };

        parser.filter(JSON.stringify(query), next);
      });

      it(`should parse ${key} http uri encoded query operator`, (done) => {
        request(app)
          .get(`/filter?${encoded}`)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const filter = response.body;
            expect(filter).to.exist;
            expect(filter).to.be.eql(comparison);
            done(error, response);
          });
      });

      it(`should parse ${key} http json encoded query operator`, (done) => {
        const query = JSON.stringify(comparison);

        request(app)
          .get(`/filter?filter=${query}`)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const filter = response.body;
            expect(filter).to.exist;
            expect(filter).to.be.eql(comparison);
            done(error, response);
          });
      });

      it(`should parse ${key} http query operator`, (done) => {
        const query = { filters: comparison };

        request(app)
          .get('/filter')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const filter = response.body;
            expect(filter).to.exist;
            expect(filter).to.be.eql(comparison);
            done(error, response);
          });
      });
    });
  });

  describe('by logical query operators', () => {
    const logicals = {
      $and: { $and: [{ price: { $ne: 1.99 } }, { price: { $exists: true } }] },
      $not: { price: { $not: { $gt: 1.99 } } },
      $or: { $or: [{ quantity: { $lt: 20 } }, { price: 10 }] },
      $nor: { $nor: [{ price: 1.99 }, { sale: true }] },
    };

    _.forEach(logicals, (logical, key) => {
      const encoded = qs.stringify({ filters: logical });

      it(`should parse fields ${key} operator`, (done) => {
        const query = { filters: logical };

        const next = (error, filter) => {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(logical);
          done(error, filter);
        };

        parser.filter(JSON.stringify(query), next);
      });

      it(`should parse ${key} http uri encoded query operator`, (done) => {
        request(app)
          .get(`/filter?${encoded}`)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const filter = response.body;
            expect(filter).to.exist;
            expect(filter).to.be.eql(logical);
            done(error, response);
          });
      });

      it.skip(`should parse ${key} http json encoded query operator`, (done) => {
        const query = JSON.stringify(logical);

        request(app)
          .get(`/filter?filter=${query}`)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const filter = response.body;
            expect(filter).to.exist;
            expect(filter).to.be.eql(logical);
            done(error, response);
          });
      });

      it.skip(`should parse ${key} http query operator`, (done) => {
        const query = { filters: logical };

        request(app)
          .get('/filter')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const filter = response.body;
            expect(filter).to.exist;
            expect(filter).to.be.eql(logical);
            done(error, response);
          });
      });
    });
  });

  describe('by element query operators', () => {
    const elements = {
      $exists: { a: { $exists: true } },
      $type: { zipCode: { $type: 'string' } },
    };

    _.forEach(elements, (element, key) => {
      it(`should parse fields ${key} operator`, (done) => {
        const query = { filters: element };

        const next = (error, filter) => {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(element);
          done(error, filter);
        };

        parser.filter(JSON.stringify(query), next);
      });
    });
  });

  describe('by evaluation query operators', () => {
    const evaluations = {
      $expr: { $expr: { $gt: ['$spent', '$budget'] } },
      $jsonSchema: {},
      $mod: { qty: { $mod: [4, 0] } },
      $regex: { sku: { $regex: '/789$/' } },
      $text: { $text: { $search: 'coffee' } },
      $$where: {},
    };

    _.forEach(evaluations, (evaluation, key) => {
      it(`should parse fields ${key} operator`, (done) => {
        const query = { filters: evaluation };

        const next = (error, filter) => {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(evaluation);
          done(error, filter);
        };

        parser.filter(JSON.stringify(query), next);
      });
    });
  });

  describe('by geospatial query operators', () => {
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
                  [0, 0],
                ],
              ],
            },
          },
        },
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
                  [0, 0],
                ],
              ],
            },
          },
        },
      },
      $near: {
        loc: {
          $near: {
            $geometry: { type: 'Point', coordinates: [-73.9667, 40.78] },
            $minDistance: 1000,
            $maxDistance: 5000,
          },
        },
      },
      $nearSphere: {
        loc: {
          $nearSphere: {
            $geometry: {
              type: 'Point',
              coordinates: [-73.9667, 40.78],
            },
            $minDistance: 1000,
            $maxDistance: 5000,
          },
        },
      },
      $box: {
        loc: {
          $geoWithin: {
            $box: [
              [0, 0],
              [100, 100],
            ],
          },
        },
      },
      $center: {
        loc: {
          $geoWithin: {
            $center: [[-74, 40.74], 10],
          },
        },
      },
      $centerSphere: {
        loc: {
          $geoWithin: {
            $centerSphere: [[-88, 30], 10 / 3963.2],
          },
        },
      },
      $maxDistance: {
        loc: {
          $near: [-74, 40],
          $maxDistance: 10,
        },
      },
      $minDistance: {
        loc: {
          $near: [-74, 40],
          $minDistance: 10,
        },
      },
      $polygon: {
        loc: {
          $geoWithin: {
            $polygon: [
              [0, 0],
              [3, 6],
              [6, 0],
            ],
          },
        },
      },
    };

    _.forEach(geospatials, (geospatial, key) => {
      it(`should parse fields ${key} operator`, (done) => {
        const query = { filters: geospatial };

        const next = (error, filter) => {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(geospatial);
          done(error, filter);
        };

        parser.filter(JSON.stringify(query), next);
      });
    });
  });

  describe('by array query operators', () => {
    const arrays = {
      $all: {
        tags: {
          $all: [['ssl', 'security']],
        },
      },
      $elemMatch: { results: { $elemMatch: { $gte: 80, $lt: 85 } } },
      $size: { field: { $size: 1 } },
    };

    _.forEach(arrays, (array, key) => {
      it(`should parse fields ${key} operator`, (done) => {
        const query = { filters: array };

        const next = (error, filter) => {
          expect(error).to.not.exist;
          expect(filter).to.exist;
          expect(filter).to.be.eql(array);
          done(error, filter);
        };

        parser.filter(JSON.stringify(query), next);
      });
    });
  });
});
