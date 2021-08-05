import chai from 'chai';
import express from 'express';
import request from 'supertest';
import { mquery } from '../../src';

const { expect } = chai;

describe('middleware', () => {
  const app = express();
  app.use(mquery({ limit: 10, maxLimit: 50 }));
  app.use('/mquery', (req, response) => {
    response.json(req.mquery);
  });

  it('should parse search options', (done) => {
    request(app)
      .get('/mquery?q=mquery')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.filter).to.exist;
        expect(body.filter.q).to.exist;
        expect(body.filter.q).to.be.equal('mquery');
        done(error, response);
      });
  });

  it('should parse filter options', (done) => {
    request(app)
      .get('/mquery?filter[age]=10&filter[year]=2018')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.filter).to.exist;
        expect(body.filter.age).to.exist;
        expect(body.filter.age).to.be.equal(10);
        expect(body.filter.year).to.exist;
        expect(body.filter.year).to.be.equal(2018);
        done(error, response);
      });
  });

  it('should parse filter options', (done) => {
    request(app)
      .get('/mquery?filter[age][$gte]=10&filter[year][$eq]=2018')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.filter).to.exist;
        expect(body.filter.age).to.exist;
        expect(body.filter.age).to.be.eql({ $gte: 10 });
        expect(body.filter.year).to.exist;
        expect(body.filter.year).to.be.eql({ $eq: 2018 });
        done(error, response);
      });
  });

  it('should parse page options', (done) => {
    request(app)
      .get('/mquery')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.paginate).to.exist;
        expect(body.paginate.page).to.exist;
        expect(body.paginate.limit).to.exist;
        expect(body.paginate.skip).to.exist;
        done(error, response);
      });
  });

  it('should parse page options', (done) => {
    request(app)
      .get('/mquery?page=1&limit=20&skip=20')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
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

  it('should parse page options', (done) => {
    request(app)
      .get('/mquery?page=1&limit=100&skip=20')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
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

  it('should parse page options', (done) => {
    request(app)
      .get('/mquery?page=-1&limit=-10&skip=-20')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
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

  it('should parse page options', (done) => {
    request(app)
      .get('/mquery?page[number]=2&page[limit]=20&page[skip]=20')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
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

  it('should parse populate options', (done) => {
    const populate = [{ path: 'father' }, { path: 'mother' }];
    request(app)
      .get('/mquery?populate=father,mother')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.populate).to.exist;
        expect(body.populate).to.be.eql(populate);
        done(error, response);
      });
  });

  it('should parse populate options', (done) => {
    const populate = [{ path: 'father' }, { path: 'mother' }];
    request(app)
      .get('/mquery?include=father,mother')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.populate).to.exist;
        expect(body.populate).to.be.eql(populate);
        done(error, response);
      });
  });

  it('should parse populate options', (done) => {
    const populate = [
      { path: 'father' },
      { path: 'mother', select: { name: 1 } },
    ];
    request(app)
      .get('/mquery?include=father,mother&fields[mother]=name')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.populate).to.exist;
        expect(body.populate).to.be.eql(populate);
        done(error, response);
      });
  });

  it('should parse select options', (done) => {
    const select = { name: 1, age: 1, year: 0 };
    request(app)
      .get('/mquery?select=name,age,-year')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.select).to.exist;
        expect(body.select).to.be.eql(select);
        done(error, response);
      });
  });

  it('should parse select options', (done) => {
    const select = { 'name.firstname': 1, age: 1, year: 0 };
    request(app)
      .get('/mquery?select=name.firstname,age,-year')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.select).to.exist;
        expect(body.select).to.be.eql(select);
        done(error, response);
      });
  });

  it('should parse sort options', (done) => {
    const sort = { name: -1, age: 1, year: -1 };
    request(app)
      .get('/mquery?sort=-name,age,-year')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const { body } = response;
        expect(body).to.exist;
        expect(body.sort).to.exist;
        expect(body.sort).to.be.eql(sort);
        done(error, response);
      });
  });
});
