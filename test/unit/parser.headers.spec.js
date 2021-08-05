import { _ } from 'lodash';
import chai from 'chai';
import express from 'express';
import request from 'supertest';
import * as parser from '../../src';

const { expect } = chai;

describe('headers', () => {
  it('should be a function', () => {
    expect(parser.headers).to.exist;
    expect(parser.headers).to.be.a('function');
    expect(parser.headers.name).to.be.equal('headers');
    expect(parser.headers.length).to.be.equal(2);
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

    parser.headers(JSON.stringify(query), (error, headers) => {
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

    parser.headers(query, (error, headers) => {
      expect(error).to.not.exist;
      expect(headers).to.exist;
      expect(headers).to.eql(expected);
      done(error, headers);
    });
  });

  describe('http', () => {
    const app = express();
    app.use('/headers', (req, response) => {
      const query = _.merge({}, req.query, { headers: req.headers });
      parser.headers(query, (error, headers) => {
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
