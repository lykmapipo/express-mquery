import { merge } from 'lodash';
import chai from 'chai';
import express from 'express';
import request from 'supertest';
import { headers as parseHeaders } from '../../src/internals';

const { expect } = chai;

describe('headers', () => {
  it('should be a function', () => {
    expect(parseHeaders).to.exist;
    expect(parseHeaders).to.be.a('function');
    expect(parseHeaders.name).to.be.equal('headers');
    expect(parseHeaders.length).to.be.equal(2);
  });

  it('should parse json based headers', (done) => {
    const query = {
      headers: {
        'if-modified-since': new Date().toISOString(),
      },
    };
    const expected = {
      ifModifiedSince: new Date(query.headers['if-modified-since']),
    };

    parseHeaders(JSON.stringify(query), (error, headers) => {
      expect(error).to.not.exist;
      expect(headers).to.exist;
      expect(headers).to.eql(expected);
      done(error, headers);
    });
  });

  it('should parse object based headers', (done) => {
    const query = {
      headers: {
        'if-modified-since': new Date().toISOString(),
      },
    };
    const expected = {
      ifModifiedSince: new Date(query.headers['if-modified-since']),
    };

    parseHeaders(query, (error, headers) => {
      expect(error).to.not.exist;
      expect(headers).to.exist;
      expect(headers).to.eql(expected);
      done(error, headers);
    });
  });

  describe('http', () => {
    const app = express();
    app.use('/headers', (req, response) => {
      const query = merge({}, req.query, { headers: req.headers });
      parseHeaders(query, (error, headers) => {
        if (error) {
          throw error;
        } else {
          response.json(headers);
        }
      });
    });

    it('should parse json based headers', (done) => {
      const query = {
        headers: {
          'if-modified-since': new Date().toISOString(),
        },
      };
      const expected = {
        ifModifiedSince: query.headers['if-modified-since'],
      };

      request(app)
        .get('/headers')
        .query(query)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const headers = response.body;
          expect(headers).to.exist;
          expect(headers).to.eql(expected);
          done(error, response);
        });
    });

    it('should parse http based headers', (done) => {
      const date = new Date().toISOString();
      const expected = {
        ifModifiedSince: date,
      };

      request(app)
        .get('/headers')
        .set('If-Modified-Since', date)
        .expect(200, (error, response) => {
          expect(error).to.not.exist;
          const headers = response.body;
          expect(headers).to.exist;
          expect(headers).to.eql(expected);
          done(error, response);
        });
    });
  });
});
