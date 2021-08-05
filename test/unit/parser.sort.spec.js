import chai from 'chai';
import express from 'express';
import request from 'supertest';
import { sort as parseSorts } from '../../src/internals';

const { expect } = chai;

describe('sort', () => {
  it('should be a function', () => {
    expect(parseSorts).to.exist;
    expect(parseSorts).to.be.a('function');
    expect(parseSorts.name).to.be.equal('sort');
    expect(parseSorts.length).to.be.equal(2);
  });

  it('should parse json based sort', (done) => {
    const _sort = { name: 1, email: 1 };
    const query = { sort: _sort };

    parseSorts(JSON.stringify(query), (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse json based sort', (done) => {
    const _sort = { name: 'desc', email: 'asc' };
    const query = { sort: _sort };

    parseSorts(JSON.stringify(query), (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse json based sort', (done) => {
    const _sort = { name: 'descending', email: 'ascending' };
    const query = { sort: _sort };

    parseSorts(JSON.stringify(query), (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse object based sort', (done) => {
    const _sort = { name: 1, email: 1 };
    const query = { sort: _sort };

    parseSorts(query, (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse object based sort', (done) => {
    const _sort = { name: 'desc', email: 'asc' };
    const query = { sort: _sort };

    parseSorts(query, (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse object based sort', (done) => {
    const _sort = { name: 'descending', email: 'ascending' };
    const query = { sort: _sort };

    parseSorts(query, (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse string based sort', (done) => {
    const _sort = { name: 1, email: 1 };
    const query = { sort: 'name,email' };

    parseSorts(JSON.stringify(query), (error, sort) => {
      expect(error).to.not.exist;
      expect(sort).to.exist;
      expect(sort).to.eql(_sort);
      done(error, sort);
    });
  });

  it('should parse string based sort', (done) => {
    const _sort = { name: -1, email: -1 };
    const query = { sort: '-name,-email' };

    parseSorts(query, (error, projection) => {
      expect(error).to.not.exist;
      expect(projection).to.exist;
      expect(projection).to.eql(_sort);
      done(error, projection);
    });
  });

  describe('http', () => {
    const app = express();
    app.use('/sort', (req, response) => {
      parseSorts(req.query, (error, sorts) => {
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
