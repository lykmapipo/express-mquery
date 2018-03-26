'use strict';

//dependencies
//global imports
const path = require('path');
const _ = require('lodash');
const async = require('async');
const faker = require('faker');
const chai = require('chai');
const express = require('express');
const request = require('supertest');
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const ObjectId = Schema.Types.ObjectId;
const expect = chai.expect;
const mquery = require(path.join(__dirname, '..', '..'));

describe.only('integration', function () {

  mongoose.plugin(mquery.plugin);
  const User = mongoose.model('User', new Schema({
    name: { type: String, searchable: true },
    age: { type: Number },
    year: { type: Number },
    mother: { type: ObjectId, ref: 'User' },
    father: { type: ObjectId, ref: 'User' }
  }));

  const father = { name: faker.name.firstName(), age: 58, year: 1960 };
  const mother = { name: faker.name.firstName(), age: 48, year: 1970 };
  const kids = _.map(_.range(1, 31), (age) => {
    return { name: faker.name.firstName(), age: age, year: 1980 + age };
  });

  const app = express();
  app.use(mquery.middleware({ limit: 10, maxLimit: 50 }));
  app.use('/mquery', function (request, response) {
    response.json(request.mquery);
  });

  before(function (done) {
    mongoose.connect('mongodb://localhost/express-mquery', done);
  });

  before(function (done) {
    User.remove(done);
  });

  //seed userh
  before(function (done) {
    async.waterfall([
      function (next) {
        async.parallel({
          mother: function (next) {
            User.create(mother, next);
          },
          father: function (next) {
            User.create(father, next);
          }
        }, next);
      },
      function (parents, next) {
        User
          .create(
            _.map(kids, (kid) => { return _.merge({}, kid, parents); }),
            next
          );
      }
    ], done);

  });

  it('should add mquery mongoose plugin', function () {
    expect(User.search).to.exist;
    expect(User.search).to.be.a('function');
    expect(User.countAndPaginate).to.exist;
    expect(User.countAndPaginate).to.be.a('function');
  });


  it('should be able to countAndPaginate without options', function (done) {

    User
      .countAndPaginate(function (error, results) {
        expect(error).to.not.exist;
        expect(results).to.exist;
        expect(results.docs).to.exist;
        expect(results.docs).to.have.length(10);
        expect(results.total).to.exist;
        expect(results.total).to.be.equal(32);
        expect(results.limit).to.exist;
        expect(results.limit).to.be.equal(10);
        expect(results.skip).to.exist;
        expect(results.skip).to.be.equal(0);
        expect(results.page).to.exist;
        expect(results.page).to.be.equal(1);
        expect(results.pages).to.exist;
        expect(results.pages).to.be.equal(4);
        done(error, results);
      });

  });

  it('should be able to countAndPaginate with options', function (done) {

    const options = { page: 1, limit: 20 };
    User
      .countAndPaginate(options, function (error, results) {
        expect(error).to.not.exist;
        expect(results).to.exist;
        expect(results.docs).to.exist;
        expect(results.docs).to.have.length(20);
        expect(results.total).to.exist;
        expect(results.total).to.be.equal(32);
        expect(results.limit).to.exist;
        expect(results.limit).to.be.equal(20);
        expect(results.skip).to.exist;
        expect(results.skip).to.be.equal(0);
        expect(results.page).to.exist;
        expect(results.page).to.be.equal(1);
        expect(results.pages).to.exist;
        expect(results.pages).to.be.equal(2);
        done(error, results);
      });

  });

  it('should be able to countAndPaginate with mquery options',
    function (done) {

      const mquery = { paginate: { page: 1, limit: 20 } };
      User
        .countAndPaginate(mquery, function (error, results) {
          expect(error).to.not.exist;
          expect(results).to.exist;
          expect(results.docs).to.exist;
          expect(results.docs).to.have.length(20);
          expect(results.total).to.exist;
          expect(results.total).to.be.equal(32);
          expect(results.limit).to.exist;
          expect(results.limit).to.be.equal(20);
          expect(results.skip).to.exist;
          expect(results.skip).to.be.equal(0);
          expect(results.page).to.exist;
          expect(results.page).to.be.equal(1);
          expect(results.pages).to.exist;
          expect(results.pages).to.be.equal(2);
          done(error, results);
        });

    });

  it('should be able to countAndPaginate with mquery options',
    function (done) {

      const mquery = { filter: { q: father.name } };
      User
        .countAndPaginate(mquery, function (error, results) {
          expect(error).to.not.exist;
          expect(results).to.exist;
          expect(results.docs).to.exist;
          expect(results.docs).to.have.length(1);
          expect(results.total).to.exist;
          expect(results.total).to.be.equal(1);
          expect(results.limit).to.exist;
          expect(results.limit).to.be.equal(10);
          expect(results.skip).to.exist;
          expect(results.skip).to.be.equal(0);
          expect(results.page).to.exist;
          expect(results.page).to.be.equal(1);
          expect(results.pages).to.exist;
          expect(results.pages).to.be.equal(1);
          done(error, results);
        });

    });


  it('should parse filter options', function (done) {
    request(app)
      .get('/mquery?filter[age]=10&filter[year]=2018')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.filter).to.exist;
        expect(body.filter.age).to.exist;
        expect(body.filter.age).to.be.equal(10);
        expect(body.filter.year).to.exist;
        expect(body.filter.year).to.be.equal(2018);
        done(error, response);
      });
  });

  it('should parse filter options', function (done) {
    request(app)
      .get('/mquery?filter[age][$gte]=10&filter[year][$eq]=2018')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.filter).to.exist;
        expect(body.filter.age).to.exist;
        expect(body.filter.age).to.be.eql({ $gte: 10 });
        expect(body.filter.year).to.exist;
        expect(body.filter.year).to.be.eql({ $eq: 2018 });
        done(error, response);
      });
  });

  it('should parse page options', function (done) {
    request(app)
      .get('/mquery')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.paginate).to.exist;
        expect(body.paginate.page).to.exist;
        expect(body.paginate.limit).to.exist;
        expect(body.paginate.skip).to.exist;
        done(error, response);
      });
  });

  it('should parse page options', function (done) {
    request(app)
      .get('/mquery?page=1&limit=20&skip=20')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.paginate).to.exist;
        expect(body.paginate.page).to.exist;
        expect(body.paginate.page).to.be.equal(1);
        expect(body.paginate.limit).to.exist;
        expect(body.paginate.limit).to.be.equal(20);
        expect(body.paginate.skip).to.exist;
        expect(body.paginate.skip).to.be.equal(20);
        done(error, response);
      });
  });

  it('should parse page options', function (done) {
    request(app)
      .get('/mquery?page=1&limit=100&skip=20')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.paginate).to.exist;
        expect(body.paginate.page).to.exist;
        expect(body.paginate.page).to.be.equal(1);
        expect(body.paginate.limit).to.exist;
        expect(body.paginate.limit).to.be.equal(50);
        expect(body.paginate.skip).to.exist;
        expect(body.paginate.skip).to.be.equal(20);
        done(error, response);
      });
  });

  it('should parse page options', function (done) {
    request(app)
      .get('/mquery?page=-1&limit=-10&skip=-20')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.paginate).to.exist;
        expect(body.paginate.page).to.exist;
        expect(body.paginate.page).to.be.equal(1);
        expect(body.paginate.limit).to.exist;
        expect(body.paginate.limit).to.be.equal(10);
        expect(body.paginate.skip).to.exist;
        expect(body.paginate.skip).to.be.equal(0);
        done(error, response);
      });
  });

  it('should parse page options', function (done) {
    request(app)
      .get('/mquery?page[number]=2&page[limit]=20&page[skip]=20')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.paginate).to.exist;
        expect(body.paginate.page).to.exist;
        expect(body.paginate.page).to.be.equal(2);
        expect(body.paginate.limit).to.exist;
        expect(body.paginate.limit).to.be.equal(20);
        expect(body.paginate.skip).to.exist;
        expect(body.paginate.skip).to.be.equal(20);
        done(error, response);
      });
  });


  it('should parse populate options', function (done) {
    const populate = [{ path: 'father' }, { path: 'mother' }];
    request(app)
      .get('/mquery?populate=father,mother')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.populate).to.exist;
        expect(body.populate).to.be.eql(populate);
        done(error, response);
      });
  });

  it('should parse populate options', function (done) {
    const populate = [{ path: 'father' }, { path: 'mother' }];
    request(app)
      .get('/mquery?include=father,mother')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.populate).to.exist;
        expect(body.populate).to.be.eql(populate);
        done(error, response);
      });
  });

  it('should parse populate options', function (done) {
    const populate = [{ path: 'father' }, { path: 'mother', select: { name: 1 } }];
    request(app)
      .get('/mquery?include=father,mother&fields[mother]=name')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.populate).to.exist;
        expect(body.populate).to.be.eql(populate);
        done(error, response);
      });
  });

  it('should parse select options', function (done) {
    const select = { name: 1, age: 1, year: 0 };
    request(app)
      .get('/mquery?select=name,age,-year')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.select).to.exist;
        expect(body.select).to.be.eql(select);
        done(error, response);
      });
  });

  it('should parse select options', function (done) {
    const select = { 'name.firstname': 1, age: 1, year: 0 };
    request(app)
      .get('/mquery?select=name.firstname,age,-year')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.select).to.exist;
        expect(body.select).to.be.eql(select);
        done(error, response);
      });
  });


  it('should parse sort options', function (done) {
    const sort = { name: -1, age: 1, year: -1 };
    request(app)
      .get('/mquery?sort=-name,age,-year')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const body = response.body;
        expect(body).to.exist;
        expect(body.sort).to.exist;
        expect(body.sort).to.be.eql(sort);
        done(error, response);
      });
  });


  after(function (done) {
    User.remove(done);
  });

});