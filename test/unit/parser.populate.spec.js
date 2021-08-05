import chai from 'chai';
import express from 'express';
import request from 'supertest';
import { populate as parsePopulations } from '../../src/internals';

const { expect } = chai;

describe('populate', () => {
  const app = express();
  app.use('/populate', (req, response) => {
    parsePopulations(req.query, (error, projections) => {
      if (error) {
        throw error;
      } else {
        response.json(projections);
      }
    });
  });

  it('should be a function', () => {
    expect(parsePopulations).to.exist;
    expect(parsePopulations).to.be.a('function');
    expect(parsePopulations.name).to.be.equal('populate');
    expect(parsePopulations.length).to.be.equal(2);
  });

  it('should parse string based path population', (done) => {
    const _populate = { path: 'customer' };
    const query = { populate: 'customer' };

    parsePopulations(JSON.stringify(query), (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate).to.have.length(1);
      expect(populate[0]).to.eql(_populate);
      done(error, populate);
    });
  });

  it('should parse string based path population', (done) => {
    const _populate = { path: 'customer' };

    request(app)
      .get('/populate?includes=customer')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const populate = response.body;
        expect(populate).to.exist;
        expect(populate[0]).to.be.eql(_populate);
        done(error, response);
      });
  });

  it('should parse string based paths population', (done) => {
    const _populate = [{ path: 'customer' }, { path: 'items' }];
    const query = { populate: 'customer,items' };

    parsePopulations(JSON.stringify(query), (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate).to.have.length(2);
      expect(populate).to.eql(_populate);
      done(error, populate);
    });
  });

  it('should parse string based paths population', (done) => {
    const _populate = [{ path: 'customer' }, { path: 'items' }];

    request(app)
      .get('/populate?includes=customer, items')
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const populate = response.body;
        expect(populate).to.exist;
        expect(populate).to.be.eql(_populate);
        done(error, response);
      });
  });

  it('should parse string based path with select population', (done) => {
    const _populate = { path: 'customer', select: { name: 1 } };
    const query = { populate: 'customer', fields: { customer: 'name' } };

    parsePopulations(JSON.stringify(query), (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate).to.have.length(1);
      expect(populate[0]).to.eql(_populate);
      done(error, populate);
    });
  });

  it('should parse string based path with select population', (done) => {
    const _populate = { path: 'customer', select: { name: 1 } };
    const query = { populate: 'customer', fields: { customer: 'name' } };

    request(app)
      .get('/populate')
      .query(query)
      .expect(200, (error, response) => {
        expect(error).to.not.exist;
        const populate = response.body;
        expect(populate).to.exist;
        expect(populate[0]).to.be.eql(_populate);
        done(error, response);
      });
  });

  it('should parse string based paths with select population', (done) => {
    const _populate = [
      { path: 'customer', select: { name: 1 } },
      { path: 'items', select: { name: 1, price: 1 } },
    ];
    const query = {
      populate: 'customer,items',
      fields: {
        customer: 'name',
        items: 'name,price',
      },
    };

    parsePopulations(JSON.stringify(query), (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate).to.have.length(2);
      expect(populate).to.eql(_populate);
      done(error, populate);
    });
  });

  it('should parse string based paths with exclude select population', (done) => {
    const _populate = [
      { path: 'customer', select: { name: 1 } },
      { path: 'items', select: { price: 0 } },
    ];
    const query = {
      populate: 'customer,items',
      fields: {
        customer: 'name',
        items: '-price',
      },
    };

    parsePopulations(JSON.stringify(query), (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate).to.have.length(2);
      expect(populate).to.eql(_populate);
      done(error, populate);
    });
  });

  it('should parse object based population', (done) => {
    const _populate = { path: 'customer' };
    const query = { populate: _populate };

    parsePopulations(query, (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate[0]).to.eql(_populate);
      done(error, populate);
    });
  });

  it('should parse object based population with string select', (done) => {
    const _populate = { path: 'customer', select: { name: 1 } };
    const query = { populate: { path: 'customer', select: 'name' } };

    parsePopulations(query, (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate[0]).to.eql(_populate);
      done(error, populate);
    });
  });

  it('should parse object based population with string select', (done) => {
    const _populate = {
      path: 'customer',
      select: {
        name: 1,
        price: 0,
      },
    };
    const query = { populate: { path: 'customer', select: 'name,-price' } };

    parsePopulations(query, (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate[0]).to.eql(_populate);
      done(error, populate);
    });
  });

  it('should parse array based population', (done) => {
    const _populate = [{ path: 'customer' }, { path: 'items' }];
    const query = { populate: _populate };

    parsePopulations(query, (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate).to.eql(_populate);
      done(error, populate);
    });
  });

  it('should parse array based population with selection', (done) => {
    const _populate = [
      { path: 'customer', select: { name: 1 } },
      { path: 'items', select: { name: 1, price: 0 } },
    ];
    const query = {
      populate: [
        { path: 'customer', select: 'name' },
        { path: 'items', select: 'name,-price' },
      ],
    };

    parsePopulations(query, (error, populate) => {
      expect(error).to.not.exist;
      expect(populate).to.exist;
      expect(populate).to.eql(_populate);
      done(error, populate);
    });
  });
});
