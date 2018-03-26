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

describe('integration', function () {

  mongoose.plugin(mquery.plugin);
  const User = mongoose.model('User', new Schema({
    name: { type: String, searchable: true, index: true },
    age: { type: Number, index: true },
    year: { type: Number, index: true },
    mother: { type: ObjectId, ref: 'User', index: true },
    father: { type: ObjectId, ref: 'User', index: true }
  }));

  const father = { name: faker.name.firstName(), age: 58, year: 1960 };
  const mother = { name: faker.name.firstName(), age: 48, year: 1970 };
  const kids = _.map(_.range(1, 31), (age) => {
    return { name: faker.name.firstName(), age: age, year: 1980 + age };
  });

  const app = express();
  app.use(mquery.middleware({ limit: 10, maxLimit: 50 }));
  app.use('/mquery', function (request, response) {
    User
      .countAndPaginate(request.mquery, function (error, results) {
        if (error) {
          throw error;
        } else {
          response.status(200);
          response.json(results);
        }
      });
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
      .get('/mquery?filter[age]=10')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const results = response.body;
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
        done(error, response);
      });
  });

  it('should parse filter options', function (done) {
    request(app)
      .get('/mquery?filter[age][$gt]=10')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const results = response.body;
        expect(results).to.exist;
        expect(results.docs).to.exist;
        expect(results.docs).to.have.length(10);
        expect(results.total).to.exist;
        expect(results.total).to.be.equal(22);
        expect(results.limit).to.exist;
        expect(results.limit).to.be.equal(10);
        expect(results.skip).to.exist;
        expect(results.skip).to.be.equal(0);
        expect(results.page).to.exist;
        expect(results.page).to.be.equal(1);
        expect(results.pages).to.exist;
        expect(results.pages).to.be.equal(3);
        done(error, response);
      });
  });


  it('should parse page options', function (done) {
    request(app)
      .get('/mquery?page=1&limit=20')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const results = response.body;
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
        done(error, response);
      });
  });


  it('should parse page options', function (done) {
    request(app)
      .get('/mquery?page=-1&limit=-10&skip=-20')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const results = response.body;
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
        done(error, response);
      });
  });


  it('should parse populate options', function (done) {
    request(app)
      .get(
        '/mquery?populate=father,mother&filter[father][$ne]=null&limit=1'
      )
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const results = response.body;
        expect(results).to.exist;
        expect(results.docs).to.exist;
        expect(results.docs).to.have.length(1);
        expect(results.docs[0]).to.exist;
        expect(results.docs[0].father).to.exist;
        expect(results.docs[0].mother).to.exist;
        expect(results.total).to.exist;
        expect(results.total).to.be.equal(30);
        expect(results.limit).to.exist;
        expect(results.limit).to.be.equal(1);
        expect(results.skip).to.exist;
        expect(results.skip).to.be.equal(0);
        expect(results.page).to.exist;
        expect(results.page).to.be.equal(1);
        expect(results.pages).to.exist;
        expect(results.pages).to.be.equal(30);
        done(error, response);
      });
  });


  it('should parse populate options', function (done) {
    request(app)
      .get(
        '/mquery?populate=father,mother&fields[mother]=name&filter[father][$ne]=null&limit=1'
      )
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const results = response.body;
        expect(results).to.exist;
        expect(results.docs).to.exist;
        expect(results.docs).to.have.length(1);
        expect(results.docs[0]).to.exist;
        expect(results.docs[0].father).to.exist;
        expect(results.docs[0].mother).to.exist;
        expect(results.docs[0].mother._id).to.exist;
        expect(results.docs[0].mother.name).to.exist;
        expect(results.docs[0].mother.age).to.not.exist;
        expect(results.docs[0].mother.year).to.not.exist;
        expect(results.total).to.exist;
        expect(results.total).to.be.equal(30);
        expect(results.limit).to.exist;
        expect(results.limit).to.be.equal(1);
        expect(results.skip).to.exist;
        expect(results.skip).to.be.equal(0);
        expect(results.page).to.exist;
        expect(results.page).to.be.equal(1);
        expect(results.pages).to.exist;
        expect(results.pages).to.be.equal(30);
        done(error, response);
      });
  });

  it('should parse select options', function (done) {
    request(app)
      .get('/mquery?select=name,age')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const results = response.body;
        expect(results).to.exist;
        expect(results.docs).to.exist;
        expect(results.docs).to.have.length(10);
        expect(_.compact(_.map(results.docs, 'year')))
          .to.have.length(0);
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
        done(error, response);
      });
  });


  it('should parse sort options', function (done) {
    request(app)
      .get('/mquery?sort=age')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const results = response.body;
        expect(results).to.exist;
        expect(results.docs).to.exist;
        expect(results.docs).to.have.length(10);
        expect(results.docs[0].age).to.exist;
        expect(results.docs[0].age).to.be.equal(1);
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
        done(error, response);
      });
  });

  it('should parse sort options', function (done) {
    request(app)
      .get('/mquery?sort=-age')
      .expect(200, function (error, response) {
        expect(error).to.not.exist;
        const results = response.body;
        expect(results).to.exist;
        expect(results.docs).to.exist;
        expect(results.docs).to.have.length(10);
        expect(results.docs[0].age).to.exist;
        expect(results.docs[0].age).to.be.equal(58);
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
        done(error, response);
      });
  });


  after(function (done) {
    User.remove(done);
  });

});