'use strict';

//dependencies
const path = require('path');
const _ = require('lodash');
const chai = require('chai');
const sinon = require('sinon');
const sinonChai = require('sinon-chai');
const expect = chai.expect;
chai.use(sinonChai);
const buildQuery = require(path.join(__dirname, '..', '..', 'lib', 'buildQuery'));

describe('buildQuery', function() {
  let query;

  beforeEach(function() {

    query = {
      where: sinon.spy(),
      skip: sinon.spy(),
      limit: sinon.spy(),
      sort: sinon.spy(),
      select: sinon.spy(),
      populate: sinon.spy(),
      distinct: sinon.spy()
    };

  });

  afterEach(function() {
    for (const key in query) {
      const ret = query[key];
      if (ret && ret.restore && _.isFunction(ret.restore)) {
        ret.restore();
      }
    }
  });

  it('does not call any methods and returns a query object', function() {
    const result = buildQuery({})(query);

    for (const key in query) {
      expect(query[key]).to.have.not.been.called;
    }

    expect(result).to.be.eql(query);
  });

  describe('distinct', function() {
    it('calls distinct and returns a query object', function() {
      const queryOptions = {
        distinct: 'foo'
      };

      const result = buildQuery({})(query, queryOptions);

      expect(query.distinct).to.have.been.calledOnce;
      expect(query.distinct).to.have.been.calledWithExactly(
        queryOptions.distinct);
      expect(query.where).to.have.not.been.called;
      expect(query.skip).to.have.not.been.called;
      expect(query.limit).to.have.not.been.called;
      expect(query.sort).to.have.not.been.called;
      expect(query.populate).to.have.not.been.called;
      expect(query.select).to.have.not.been.called;

      expect(result).to.be.eql(query);
    });
  });

  describe('limit', function() {
    it('calls limit and returns a query object', function() {
      const queryOptions = {
        paginate: { limit: '1' }
      };

      const result = buildQuery({})(query, queryOptions);

      expect(query.limit).to.have.been.calledOnce;
      expect(query.limit).to.have.been.calledWithExactly(
        queryOptions.paginate.limit);

      expect(query.where).to.have.not.been.called;
      expect(query.skip).to.have.not.been.called;
      expect(query.sort).to.have.not.been.called;
      expect(query.select).to.have.not.been.called;
      expect(query.populate).to.have.not.been.called;
      expect(query.distinct).to.have.not.been.called;

      expect(result).to.be.eql(query);

    });

    it('calls limit and returns a query object', function() {
      const options = {
        limit: 1
      };

      const queryOptions = {
        paginate: { limit: '2' }
      };

      const result = buildQuery(options)(query, queryOptions);

      expect(query.limit).to.have.been.calledOnce;
      expect(query.limit).to.have.been.calledWithExactly(options.limit);

      expect(query.where).to.have.not.been.called;
      expect(query.skip).to.have.not.been.called;
      expect(query.sort).to.have.not.been.called;
      expect(query.select).to.have.not.been.called;
      expect(query.populate).to.have.not.been.called;
      expect(query.distinct).to.have.not.been.called;

      expect(result).to.be.eql(query);
    });

    it(
      'does not call limit on `count()` query and returns a query object',
      function() {
        const queryOptions = {
          paginate: { limit: '2' }
        };

        query.op = 'count';
        const result = buildQuery({})(query, queryOptions);
        delete query.op;

        for (const key in query) {
          expect(query[key]).to.have.not.been.called;
        }

        expect(result).to.be.eql(query);
      });

    it(
      'does not call limit on `count()` query and returns a query object',
      function() {
        const options = {
          limit: 1
        };

        const queryOptions = {
          paginate: { limit: '2' }
        };

        query.op = 'count';
        const result = buildQuery(options)(query, queryOptions);
        delete query.op;

        for (const key in query) {
          expect(query[key]).to.have.not.been.called;
        }

        expect(result).to.be.eql(query);
      });
  });

  describe('populate', function() {
    it('accepts an object wrapped in an array to populate a path',
      function() {
        const queryOptions = {
          populate: [{
            path: 'foo.bar',
            select: 'baz',
            match: {
              'qux': 'quux'
            },
            options: {
              sort: 'baz'
            }
          }]
        };

        const result = buildQuery({})(query, queryOptions);

        expect(query.populate).to.have.been.calledOnce;
        expect(query.populate).to.have.been.calledWithExactly(
          queryOptions.populate);
        expect(query.where).to.have.not.been.called;
        expect(query.skip).to.have.not.been.called;
        expect(query.limit).to.have.not.been.called;
        expect(query.select).to.have.not.been.called;
        expect(query.sort).to.have.not.been.called;
        expect(query.distinct).to.have.not.been.called;

        expect(result).to.be.eql(query);
      });
  });

  describe('select', function() {
    it('accepts an object', function() {
      const queryOptions = {
        select: {
          foo: 1,
          bar: 0
        }
      };

      const result = buildQuery({})(query, queryOptions);

      expect(query.select).to.have.been.calledOnce;
      expect(query.select).to.have.been.calledWithExactly(
        queryOptions.select);
      expect(query.where).to.have.not.been.called;
      expect(query.limit).to.have.not.been.called;
      expect(query.skip).to.have.not.been.called;
      expect(query.sort).to.have.not.been.called;
      expect(query.populate).to.have.not.been.called;
      expect(query.distinct).to.have.not.been.called;

      expect(result).to.be.eql(query);
    });
  });

  describe('skip', function() {
    it('calls skip and returns a query object', function() {
      const queryOptions = {
        paginate: { skip: '1' }
      };

      const result = buildQuery({})(query, queryOptions);

      expect(query.skip).to.have.been.calledOnce;
      expect(query.skip).to.have.been.calledWithExactly(
        queryOptions.paginate.skip);
      expect(query.where).to.have.not.been.called;
      expect(query.limit).to.have.not.been.called;
      expect(query.sort).to.have.not.been.called;
      expect(query.select).to.have.not.been.called;
      expect(query.populate).to.have.not.been.called;
      expect(query.distinct).to.have.not.been.called;

      expect(result).to.be.eql(query);
    });
  });

  describe('sort', function() {
    it('calls sort and returns a query object', function() {
      const queryOptions = {
        sort: 'foo'
      };

      const result = buildQuery({})(query, queryOptions);

      expect(query.sort).to.have.been.calledOnce;
      expect(query.sort).to.have.been.calledWithExactly(
        queryOptions.sort);
      expect(query.where).to.have.not.been.called;
      expect(query.limit).to.have.not.been.called;
      expect(query.skip).to.have.not.been.called;
      expect(query.select).to.have.not.been.called;
      expect(query.populate).to.have.not.been.called;
      expect(query.distinct).to.have.not.been.called;

      expect(result).to.be.eql(query);
    });
  });

  describe('where', function() {
    it('calls where and returns a query object', function() {
      const queryOptions = {
        filter: { foo: 'bar' }
      };

      const result = buildQuery({})(query, queryOptions);

      expect(query.where).to.have.been.calledOnce;
      expect(query.where).to.have.been.calledWithExactly(
        queryOptions.filter);
      expect(query.skip).to.have.not.been.called;
      expect(query.limit).to.have.not.been.called;
      expect(query.sort).to.have.not.been.called;
      expect(query.select).to.have.not.been.called;
      expect(query.populate).to.have.not.been.called;
      expect(query.distinct).to.have.not.been.called;

      expect(result).to.be.eql(query);

    });
  });

});