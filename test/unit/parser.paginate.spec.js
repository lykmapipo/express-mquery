import { get } from 'lodash';
import chai from 'chai';
import express from 'express';
import request from 'supertest';
import { paginate as parsePaginations } from '../../src/internals';

const { expect } = chai;

describe('paginate', () => {
  it('should be a function', () => {
    expect(parsePaginations).to.exist;
    expect(parsePaginations).to.be.a('function');
    expect(parsePaginations.name).to.be.equal('paginate');
    expect(parsePaginations.length).to.be.equal(2);
  });

  describe('limit', () => {
    it('should parse limit when not specified', (done) => {
      const query = {};

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.equal(10);
        done(error, paginate);
      });
    });

    it('should parse limit', (done) => {
      const query = { limit: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.equal(query.limit);
        done(error, paginate);
      });
    });

    it('should parse limit from max', (done) => {
      const query = { max: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.equal(query.max);
        done(error, paginate);
      });
    });

    it('should parse limit from size', (done) => {
      const query = { size: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.equal(query.size);
        done(error, paginate);
      });
    });

    it('should parse limit from size', (done) => {
      const query = { page: { size: 10 } };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.equal(query.page.size);
        done(error, paginate);
      });
    });

    it('should parse limit from rpp', (done) => {
      const query = { rpp: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.equal(query.rpp);
        done(error, paginate);
      });
    });

    it('should parse limit from count', (done) => {
      const query = { count: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.equal(query.count);
        done(error, paginate);
      });
    });

    it('should parse limit from perPage', (done) => {
      const query = { perPage: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.equal(query.perPage);
        done(error, paginate);
      });
    });

    it('should parse limit from per_page', (done) => {
      const query = {
        per_page: 10,
      };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.eql(get(query, 'per_page'));
        done(error, paginate);
      });
    });

    it('should parse limit from cursor', (done) => {
      const query = {
        cursor: 10,
      };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.limit).to.be.equal(query.cursor);
        done(error, paginate);
      });
    });
  });

  describe('skip', () => {
    it('should parse skip when not specified', (done) => {
      const query = {};

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.skip).to.exist;
        expect(paginate.skip).to.be.eql(0);
        done(error, paginate);
      });
    });

    it('should parse skip', (done) => {
      const query = { skip: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.skip).to.exist;
        expect(paginate.skip).to.be.eql(query.skip);
        done(error, paginate);
      });
    });

    it('should parse skip from offset', (done) => {
      const query = { offset: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.skip).to.exist;
        expect(paginate.skip).to.be.eql(query.offset);
        done(error, paginate);
      });
    });

    it('should parse skip from start', (done) => {
      const query = { start: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.skip).to.exist;
        expect(paginate.skip).to.be.eql(query.start);
        done(error, paginate);
      });
    });

    it('should parse skip from page', (done) => {
      const query = { page: 5 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.skip).to.exist;
        expect(paginate.page).to.be.eql(query.page);
        expect(paginate.skip).to.be.eql(40);
        done(error, paginate);
      });
    });

    it('should parse skip from page offset', (done) => {
      const query = { page: { offset: 5 } };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.skip).to.exist;
        expect(paginate.skip).to.be.eql(query.page.offset);
        done(error, paginate);
      });
    });
  });

  describe('page', () => {
    it('should parse page when not specified', (done) => {
      const query = {};

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.page).to.exist;
        expect(paginate.page).to.be.eql(1);
        done(error, paginate);
      });
    });

    it('should parse page', (done) => {
      const query = { page: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.page).to.exist;
        expect(paginate.page).to.be.eql(query.page);
        done(error, paginate);
      });
    });

    it('should parse page number and page size', (done) => {
      const query = { number: 10, size: 10 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
        expect(error).to.not.exist;
        expect(paginate).to.exist;
        expect(paginate.page).to.exist;
        expect(paginate.limit).to.exist;
        expect(paginate.page).to.be.eql(query.number);
        expect(paginate.limit).to.be.equal(query.size);
        done(error, paginate);
      });
    });

    it('should parse page and skip', (done) => {
      const query = { page: 1, skip: 1000 };

      parsePaginations(JSON.stringify(query), (error, paginate) => {
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

  describe('http', () => {
    const app = express();
    app.use('/paginations', (req, response) => {
      parsePaginations(req.query, (error, paginate) => {
        if (error) {
          throw error;
        } else {
          response.json(paginate);
        }
      });
    });

    describe('limit', () => {
      it('should parse limit when not specified', (done) => {
        const query = {};

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(10);
            done(error, response);
          });
      });

      it('should parse limit', (done) => {
        const query = { limit: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.limit);
            done(error, response);
          });
      });

      it('should parse limit from max', (done) => {
        const query = { max: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.max);
            done(error, response);
          });
      });

      it('should parse limit from size', (done) => {
        const query = { size: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.size);
            done(error, response);
          });
      });

      it('should parse limit from size', (done) => {
        const query = { page: { size: 10 } };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.page.size);
            done(error, response);
          });
      });

      it('should parse limit from rpp', (done) => {
        const query = { rpp: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.rpp);
            done(error, response);
          });
      });

      it('should parse limit from count', (done) => {
        const query = { count: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.count);
            done(error, response);
          });
      });

      it('should parse limit from perPage', (done) => {
        const query = { perPage: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.perPage);
            done(error, response);
          });
      });

      it('should parse limit from per_page', (done) => {
        const query = {
          per_page: 10,
        };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.eql(get(query, 'per_page'));
            done(error, response);
          });
      });

      it('should parse limit from cursor', (done) => {
        const query = {
          cursor: 10,
        };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.limit).to.exist;
            expect(paginate.limit).to.be.equal(query.cursor);
            done(error, response);
          });
      });
    });

    describe('skip', () => {
      it('should parse skip when not specified', (done) => {
        const query = {};

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(0);
            done(error, response);
          });
      });

      it('should parse skip', (done) => {
        const query = { skip: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(query.skip);
            done(error, response);
          });
      });

      it('should parse skip from offset', (done) => {
        const query = { offset: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(query.offset);
            done(error, response);
          });
      });

      it('should parse skip from start', (done) => {
        const query = { start: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(query.start);
            done(error, response);
          });
      });

      it('should parse skip from page', (done) => {
        const query = { page: 5 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(40);
            done(error, response);
          });
      });

      it('should parse skip from page offset', (done) => {
        const query = { page: { offset: 10 } };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.skip).to.exist;
            expect(paginate.skip).to.be.equal(query.page.offset);
            done(error, response);
          });
      });
    });

    describe('page', () => {
      it('should parse page when not specified', (done) => {
        const query = {};

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(1);
            done(error, response);
          });
      });

      it('should parse page', (done) => {
        const query = { page: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(query.page);
            done(error, response);
          });
      });

      it('should parse page number and page size', (done) => {
        const query = { number: 10, size: 10 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(query.number);
            expect(paginate.limit).to.be.equal(query.size);
            done(error, response);
          });
      });

      it('should parse page number and page size', (done) => {
        const query = { number: 10, size: 10 };

        request(app)
          .get('/paginations?page[number]=10&page[size]=10')
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(query.number);
            expect(paginate.limit).to.be.equal(query.size);
            done(error, response);
          });
      });

      it('should parse page and skip', (done) => {
        const query = { page: 1, skip: 1000 };

        request(app)
          .get('/paginations')
          .query(query)
          .expect(200, (error, response) => {
            expect(error).to.not.exist;
            const paginate = response.body;
            expect(paginate).to.exist;
            expect(paginate.page).to.exist;
            expect(paginate.page).to.be.equal(query.page);
            expect(paginate.skip).to.be.equal(query.skip);
            done(error, response);
          });
      });

      it('should parse page and skip', (done) => {
        const query = { page: 1, skip: 1000 };

        request(app)
          .get('/paginations?page=1&skip=1000')
          .expect(200, (error, response) => {
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
