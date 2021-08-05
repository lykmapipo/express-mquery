import chai from 'chai';
import express from 'express';
import request from 'supertest';
import * as parser from '../../src';

const { expect } = chai;

describe('select', () => {
  it('should be a function', () => {
    expect(parser.select).to.exist;
    expect(parser.select).to.be.a('function');
    expect(parser.select.name).to.be.equal('select');
    expect(parser.select.length).to.be.equal(2);
  });

  describe('fields', () => {
    it('should parse json based projection', (done) => {
      const fields = { name: 1, email: 1 };
      const query = { fields };

      parser.select(JSON.stringify(query), (error, projection) => {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(fields);
        done(error, projection);
      });
    });

    it('should parse object based projection', (done) => {
      const fields = { name: 1, email: 1 };
      const query = { fields };

      parser.select(query, (error, projection) => {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(fields);
        done(error, projection);
      });
    });

    it('should parse string based projection', (done) => {
      const fields = { name: 1, email: 1 };
      const query = { fields: 'name,email' };

      parser.select(JSON.stringify(query), (error, projection) => {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(fields);
        done(error, projection);
      });
    });

    it('should parse string based projection', (done) => {
      const fields = { name: 0, email: 0 };
      const query = { fields: '-name,-email' };

      parser.select(query, (error, projection) => {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(fields);
        done(error, projection);
      });
    });
  });

  describe('select', () => {
    it('should parse json based projection', (done) => {
      const select = { name: 1, email: 1 };
      const query = { select };

      parser.select(JSON.stringify(query), (error, projection) => {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(select);
        done(error, projection);
      });
    });

    it('should parse object based projection', (done) => {
      const select = { name: 1, email: 1 };
      const query = { select };

      parser.select(query, (error, projection) => {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(select);
        done(error, projection);
      });
    });

    it('should parse string based projection', (done) => {
      const select = { name: 1, email: 1 };
      const query = { select: 'name,email' };

      parser.select(JSON.stringify(query), (error, projection) => {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(select);
        done(error, projection);
      });
    });

    it('should parse string based projection', (done) => {
      const select = { name: 0, email: 0 };
      const query = { select: '-name,-email' };

      parser.select(query, (error, projection) => {
        expect(error).to.not.exist;
        expect(projection).to.exist;
        expect(projection).to.eql(select);
        done(error, projection);
      });
    });
  });

  describe('http', () => {
    const app = express();
    app.use('/select', (req, response) => {
      parser.select(req.query, (error, projections) => {
        if (error) {
          throw error;
        } else {
          response.json(projections);
        }
      });
    });

    it('should parse json based projection', (done) => {
      const select = { name: 1, email: 1 };
      const query = { select };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse json based projection', (done) => {
      const select = { name: 0, email: 0 };
      const query = { select };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse json based projection', (done) => {
      const select = { 'location.name': 1, 'location.address': 1 };
      const query = { select };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse string based projection', (done) => {
      const select = { name: 1, email: 1 };
      const query = { select: 'name,email' };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse string based projection', (done) => {
      const select = { 'location.name': 1, 'location.address': 1 };
      const query = { select: 'location.name,location.address' };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse string based projection', (done) => {
      const select = { name: 0, email: 0 };
      const query = { select: '-name,-email' };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse string based projection', (done) => {
      const select = { 'location.name': 0, 'location.address': 0 };
      const query = { select: '-location.name,-location.address' };

      request(app)
        .get('/select')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse string based projection', (done) => {
      const select = { name: 1, email: 1 };

      request(app)
        .get('/select?select[name]=1&select[email]=1')
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should parse string based projection', (done) => {
      const select = { name: 1, email: 1 };

      request(app)
        .get('/select?fields[name]=1&fields[email]=1')
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const projection = response.body;
          expect(projection).to.exist;
          expect(projection).to.eql(select);
          done(error, response);
        });
    });

    it('should check populate & select');
    // ?includes=profile&fields[profile]=name
  });
});
