import chai from 'chai';
import express from 'express';
import request from 'supertest';
import * as parser from '../../src';

const { expect } = chai;

describe('sort', () => {
  it('should be a function', () => {
    expect(parser.sort).to.exist;
    expect(parser.sort).to.be.a('function');
    expect(parser.sort.name).to.be.equal('sort');
    expect(parser.sort.length).to.be.equal(2);
  });

  it('should parse json based sort', (done) => {
    const _sort = { name: 1, email: 1 };
    const query = { sort: _sort };

    parser.sort(JSON.stringify(query), (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse json based sort', (done) => {
    const _sort = { name: 'desc', email: 'asc' };
    const query = { sort: _sort };

    parser.sort(JSON.stringify(query), (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse json based sort', (done) => {
    const _sort = { name: 'descending', email: 'ascending' };
    const query = { sort: _sort };

    parser.sort(JSON.stringify(query), (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse object based sort', (done) => {
    const _sort = { name: 1, email: 1 };
    const query = { sort: _sort };

    parser.sort(query, (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse object based sort', (done) => {
    const _sort = { name: 'desc', email: 'asc' };
    const query = { sort: _sort };

    parser.sort(query, (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse object based sort', (done) => {
    const _sort = { name: 'descending', email: 'ascending' };
    const query = { sort: _sort };

    parser.sort(query, (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse string based sort', (done) => {
    const _sort = { name: 1, email: 1 };
    const query = { sort: 'name,email' };

    parser.sort(JSON.stringify(query), (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse string based sort', (done) => {
    const _sort = { name: -1, email: -1 };
    const query = { sort: '-name,-email' };

    parser.sort(query, (error, projection) => {
      expect(error).to.not.exist;
      expect(projection).to.exist;
      expect(projection).to.eql(_sort);
      done(error, projection);
    });
  });

  describe('http', () => {
    const app = express();
    app.use('/sort', (req, response) => {
      parser.sort(req.query, (error, sorts) => {
        if (error) {
          throw error;
        } else {
          response.json(sorts);
        }
      });
    });

    it('should parse json based sort', (done) => {
      const _sort = { name: 1, email: 1 };
      const query = { sort: _sort };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse json based sort', (done) => {
      const _sort = { name: 'desc', email: 'asc' };
      const query = { sort: _sort };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse json based sort', (done) => {
      const _sort = { name: 'descending', email: 'ascending' };
      const query = { sort: _sort };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse string based sort', (done) => {
      const _sort = { name: 1, email: 1 };
      const query = { sort: 'name,email' };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse string based sort', (done) => {
      const _sort = { name: -1, email: -1 };
      const query = { sort: '-name,-email' };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse string based sort', (done) => {
      const _sort = { name: -1, email: 1 };
      const query = { sort: '-name,email' };

      request(app)
        .get('/sort')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse string based sort', (done) => {
      const _sort = { name: -1, email: 1 };

      request(app)
        .get('/sort?sort[name]=-1&sort[email]=1')
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse string based sort', (done) => {
      const _sort = { name: -1, email: 1 };

      request(app)
        .get('/sort?sort=-name,email')
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });

    it('should parse json based sort', (done) => {
      const _sort = { name: 1, email: 1 };

      request(app)
        .get('/sort?sort={"name": "1", "email": "1"}')
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const sort = response.body;
          expect(sort).to.exist;
          expect(sort).to.eql(_sort);
          done(error, response);
        });
    });
  });
});
