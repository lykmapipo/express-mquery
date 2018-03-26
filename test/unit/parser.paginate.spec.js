'use strict';


//global imports
const path = require('path');
const _ = require('lodash');
const express = require('express');
const request = require('supertest');
const chai = require('chai');
const expect = chai.expect;
const parser = require(path.join(__dirname, '..', '..', 'lib', 'parser'));

describe('paginate', function () {

  it('should be a function', function () {
    expect(parser.paginate).to.exist;
    expect(parser.paginate).to.be.a('function');
    expect(parser.paginate.name).to.be.equal('paginate');
    expect(parser.paginate.length).to.be.equal(2);
  });

  describe('limit', function () {

    it('should parse limit when not specified', function (done) {

      const query = {};

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.equal(10);
          done(error, paginate);
        });

    });


    it('should parse limit', function (done) {

      const query = { limit: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.equal(query.limit);
          done(error, paginate);
        });

    });

    it('should parse limit from max', function (done) {

      const query = { max: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.equal(query.max);
          done(error, paginate);
        });

    });

    it('should parse limit from size', function (done) {

      const query = { size: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.equal(query.size);
          done(error, paginate);
        });

    });

    it('should parse limit from size', function (done) {

      const query = { page: { size: 10 } };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.equal(query.page.size);
          done(error, paginate);
        });

    });

    it('should parse limit from rpp', function (done) {

      const query = { rpp: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.equal(query.rpp);
          done(error, paginate);
        });

    });

    it('should parse limit from count', function (done) {

      const query = { count: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.equal(query.count);
          done(error, paginate);
        });

    });

    it('should parse limit from perPage', function (done) {

      const query = { perPage: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.equal(query.perPage);
          done(error, paginate);
        });

    });

    it('should parse limit from per_page', function (done) {

      const query = {
        'per_page': 10
      };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit)
            .to.be.eql(_.get(query, 'per_page'));
          done(error, paginate);
        });

    });

    it('should parse limit from cursor', function (done) {

      const query = {
        cursor: 10
      };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.limit).to.be.equal(query.cursor);
          done(error, paginate);
        });

    });

  });

  describe('skip', function () {

    it('should parse skip when not specified', function (done) {

      const query = {};

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.skip).to.be.eql(0);
          done(error, paginate);
        });

    });


    it('should parse skip', function (done) {

      const query = { skip: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.skip).to.be.eql(query.skip);
          done(error, paginate);
        });

    });

    it('should parse skip from offset', function (done) {

      const query = { offset: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.skip).to.be.eql(query.offset);
          done(error, paginate);
        });

    });

    it('should parse skip from start', function (done) {

      const query = { start: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.skip).to.be.eql(query.start);
          done(error, paginate);
        });

    });

    it('should parse skip from page', function (done) {

      const query = { page: 5 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.page).to.be.eql(query.page);
          expect(paginate.skip).to.be.eql(40);
          done(error, paginate);
        });

    });


    it('should parse skip from page offset', function (done) {

      const query = { page: { offset: 5 } };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.skip).to.exist;
          expect(paginate.skip).to.be.eql(query.page.offset);
          done(error, paginate);
        });

    });

  });

  describe('page', function () {

    it('should parse page when not specified', function (done) {

      const query = {};

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.page).to.exist;
          expect(paginate.page).to.be.eql(1);
          done(error, paginate);
        });

    });


    it('should parse page', function (done) {

      const query = { page: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.page).to.exist;
          expect(paginate.page).to.be.eql(query.page);
          done(error, paginate);
        });

    });

    it('should parse page number and page size', function (done) {

      const query = { number: 10, size: 10 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.page).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.page).to.be.eql(query.number);
          expect(paginate.limit).to.be.equal(query.size);
          done(error, paginate);
        });

    });

    it('should parse page and skip', function (done) {

      const query = { page: 1, skip: 1000 };

      parser
        .paginate(JSON.stringify(query), function (error,
          paginate) {
          expect(error).to.not.exist;
          expect(paginate).to.exist;
          expect(paginate.page).to.exist;
          expect(paginate.limit).to.exist;
          expect(paginate.page).to.be.eql(query.page);
          expect(paginate.skip).to.be.eql(query.skip);
          expect(paginate.limit).to.be.equal(10);
          done(error, paginate);
        });

    });

  });

  describe('http', function () {

    const app = express();
    app.use('/paginations', function (request, response) {
      parser
        .paginate(request.query, function (error, paginate) {
          if (error) {
            throw error;
          } else {
            response.json(paginate);
          }
        });
    });

    describe('limit', function () {

      it('should parse limit when not specified', function (done) {

        const query = {};

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(10);
            done(error, response);
          });

      });


      it('should parse limit', function (done) {

        const query = { limit: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.limit);
            done(error, response);
          });

      });

      it('should parse limit from max', function (done) {

        const query = { max: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.max);
            done(error, response);
          });

      });

      it('should parse limit from size', function (done) {

        const query = { size: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.size);
            done(error, response);
          });

      });

      it('should parse limit from size', function (done) {

        const query = { page: { size: 10 } };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.page.size);
            done(error, response);
          });

      });

      it('should parse limit from rpp', function (done) {

        const query = { rpp: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.rpp);
            done(error, response);
          });

      });

      it('should parse limit from count', function (done) {

        const query = { count: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.count);
            done(error, response);
          });

      });

      it('should parse limit from perPage', function (done) {

        const query = { perPage: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.perPage);
            done(error, response);
          });

      });

      it('should parse limit from per_page', function (done) {

        const query = {
          'per_page': 10
        };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit)
              .to.be.eql(_.get(query, 'per_page'));
            done(error, response);
          });

      });

      it('should parse limit from cursor', function (done) {

        const query = {
          cursor: 10
        };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.cursor);
            done(error, response);
          });

      });

    });

    describe('skip', function () {

      it('should parse skip when not specified', function (done) {

        const query = {};

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(0);
            done(error, response);
          });

      });


      it('should parse skip', function (done) {

        const query = { skip: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(query.skip);
            done(error, response);
          });

      });

      it('should parse skip from offset', function (done) {

        const query = { offset: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(query.offset);
            done(error, response);
          });

      });

      it('should parse skip from start', function (done) {

        const query = { start: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(query.start);
            done(error, response);
          });

      });

      it('should parse skip from page', function (done) {

        const query = { page: 5 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(40);
            done(error, response);
          });

      });

      it('should parse skip from page offset', function (done) {

        const query = { page: { offset: 10 } };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(query.page.offset);
            done(error, response);
          });

      });

    });

    describe('page', function () {

      it('should parse page when not specified', function (done) {

        const query = {};

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(1);
            done(error, response);
          });

      });


      it('should parse page', function (done) {

        const query = { page: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(query.page);
            done(error, response);
          });

      });

      it('should parse page number and page size', function (done) {

        const query = { number: 10, size: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(query.number);
            expect(paginate.limit).to.be.equal(query.size);
            done(error, response);
          });

      });

      it('should parse page number and page size', function (done) {

        const query = { number: 10, size: 10 };

        request(app)
          .get('/paginations?page[number]=10&page[size]=10')
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(query.number);
            expect(paginate.limit).to.be.equal(query.size);
            done(error, response);
          });

      });

      it('should parse page and skip', function (done) {

        const query = { page: 1, skip: 1000 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(query.page);
            expect(paginate.skip).to.be.equal(query.skip);
            done(error, response);
          });

      });

      it('should parse page and skip', function (done) {

        const query = { page: 1, skip: 1000 };

        request(app)
          .get('/paginations?page=1&skip=1000')
          .expect(200, function (error, response) {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(query.page);
            expect(paginate.skip).to.be.equal(query.skip);
            done(error, response);
          });

      });

    });

  });

});