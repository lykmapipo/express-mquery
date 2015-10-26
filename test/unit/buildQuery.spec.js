'use strict';

//dependencies
var path = require('path');
var chai = require('chai');
var sinon = require('sinon');
var sinonChai = require('sinon-chai');
var expect = chai.expect;
chai.use(sinonChai);
var buildQuery = require(path.join(__dirname, '..', '..', 'lib', 'buildQuery'));

describe('buildQuery', function() {
    var query = {
        where: sinon.spy(),
        skip: sinon.spy(),
        limit: sinon.spy(),
        sort: sinon.spy(),
        select: sinon.spy(),
        populate: sinon.spy(),
        distinct: sinon.spy()
    };

    afterEach(function() {
        for (var key in query) {
            query[key].reset();
        }
    });

    it('does not call any methods and returns a query object', function() {
        var result = buildQuery({})(query);

        for (var key in query) {
            expect(query[key]).to.have.not.been.called;
        }

        expect(result).to.be.eql(query);
    });

    describe('query', function() {
        it('calls where and returns a query object', function() {
            var queryOptions = {
                query: 'foo'
            };

            var result = buildQuery({})(query, queryOptions);

            expect(query.where).to.have.been.calledOnce;
            expect(query.where).to.have.been.calledWithExactly(queryOptions.query);
            expect(query.skip).to.have.not.been.called;
            expect(query.limit).to.have.not.been.called;
            expect(query.sort).to.have.not.been.called;
            expect(query.select).to.have.not.been.called;
            expect(query.populate).to.have.not.been.called;
            expect(query.distinct).to.have.not.been.called;

            expect(result).to.be.eql(query);

        });
    });

    describe('skip', function() {
        it('calls skip and returns a query object', function() {
            var queryOptions = {
                skip: '1'
            };

            var result = buildQuery({})(query, queryOptions);

            expect(query.skip).to.have.been.calledOnce;
            expect(query.skip).to.have.been.calledWithExactly(queryOptions.skip);
            expect(query.where).to.have.not.been.called;
            expect(query.limit).to.have.not.been.called;
            expect(query.sort).to.have.not.been.called;
            expect(query.select).to.have.not.been.called;
            expect(query.populate).to.have.not.been.called;
            expect(query.distinct).to.have.not.been.called;

            expect(result).to.be.eql(query);
        });
    });

    describe('limit', function() {
        it('calls limit and returns a query object', function() {
            var queryOptions = {
                limit: '1'
            };

            var result = buildQuery({})(query, queryOptions);

            expect(query.limit).to.have.been.calledOnce;
            expect(query.limit).to.have.been.calledWithExactly(queryOptions.limit);

            expect(query.where).to.have.not.been.called;
            expect(query.skip).to.have.not.been.called;
            expect(query.sort).to.have.not.been.called;
            expect(query.select).to.have.not.been.called;
            expect(query.populate).to.have.not.been.called;
            expect(query.distinct).to.have.not.been.called;

            expect(result).to.be.eql(query);

        });

        it('calls limit and returns a query object', function() {
            var options = {
                limit: 1
            };

            var queryOptions = {
                limit: '2'
            };

            var result = buildQuery(options)(query, queryOptions);

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

        it('does not call limit on `count()` query and returns a query object', function() {
            var queryOptions = {
                limit: '2'
            };

            query.op = 'count';
            var result = buildQuery({})(query, queryOptions);
            delete query.op;

            for (var key in query) {
                expect(query[key]).to.have.not.been.called;
            }

            expect(result).to.be.eql(query);
        });

        it('does not call limit on `count()` query and returns a query object', function() {
            var options = {
                limit: 1
            };

            var queryOptions = {
                limit: '2'
            };

            query.op = 'count';
            var result = buildQuery(options)(query, queryOptions);
            delete query.op;

            for (var key in query) {
                expect(query[key]).to.have.not.been.called;
            }

            expect(result).to.be.eql(query);
        });
    });

    describe('sort', function() {
        it('calls sort and returns a query object', function() {
            var queryOptions = {
                sort: 'foo'
            };

            var result = buildQuery({})(query, queryOptions);

            expect(query.sort).to.have.been.calledOnce;
            expect(query.sort).to.have.been.calledWithExactly(queryOptions.sort);
            expect(query.where).to.have.not.been.called;
            expect(query.limit).to.have.not.been.called;
            expect(query.skip).to.have.not.been.called;
            expect(query.select).to.have.not.been.called;
            expect(query.populate).to.have.not.been.called;
            expect(query.distinct).to.have.not.been.called;

            expect(result).to.be.eql(query);
        });
    });

    describe('select', function() {
        it('accepts an object', function() {
            var queryOptions = {
                select: {
                    foo: 1,
                    bar: 0
                }
            };

            var result = buildQuery({})(query, queryOptions);

            expect(query.select).to.have.been.calledOnce;
            expect(query.select).to.have.been.calledWithExactly(queryOptions.select);
            expect(query.where).to.have.not.been.called;
            expect(query.limit).to.have.not.been.called;
            expect(query.skip).to.have.not.been.called;
            expect(query.sort).to.have.not.been.called;
            expect(query.populate).to.have.not.been.called;
            expect(query.distinct).to.have.not.been.called;

            expect(result).to.be.eql(query);
        });
    });

    describe('populate', function() {
        it('accepts an object wrapped in an array to populate a path', function() {
            var queryOptions = {
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

            var result = buildQuery({})(query, queryOptions);

            expect(query.populate).to.have.been.calledOnce;
            expect(query.populate).to.have.been.calledWithExactly(queryOptions.populate);
            expect(query.where).to.have.not.been.called;
            expect(query.skip).to.have.not.been.called;
            expect(query.limit).to.have.not.been.called;
            expect(query.select).to.have.not.been.called;
            expect(query.sort).to.have.not.been.called;
            expect(query.distinct).to.have.not.been.called;

            expect(result).to.be.eql(query);
        });
    });

    describe('distinct', function() {
        it('calls distinct and returns a query object', function() {
            var queryOptions = {
                distinct: 'foo'
            };

            var result = buildQuery({})(query, queryOptions);

            expect(query.distinct).to.have.been.calledOnce;
            expect(query.distinct).to.have.been.calledWithExactly(queryOptions.distinct);
            expect(query.where).to.have.not.been.Called;
            expect(query.skip).to.have.not.been.Called;
            expect(query.limit).to.have.not.been.called;
            expect(query.sort).to.have.not.been.called;
            expect(query.populate).to.have.not.been.called;
            expect(query.select).to.have.not.been.called;

            expect(result).to.be.eql(query);
        });
    });

});