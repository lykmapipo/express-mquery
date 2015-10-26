'use strict';

//dependencies
var path = require('path');
var chai = require('chai');
var sinon = require('sinon');
var sinonChai = require('sinon-chai');
var expect = chai.expect;
chai.use(sinonChai);
var prepareQuery = require(path.join(__dirname, '..', '..', 'lib', 'prepareQuery'));

describe('prepareQuery', function() {

    var next = sinon.spy();

    afterEach(function() {
        next.reset();
    });

    describe('jsonQueryParser', function() {
        it('converts ~ to a case insensitive regex', function() {
            var req = {
                query: {
                    query: '{"foo":"~bar"}'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                query: {
                    foo: new RegExp('bar', 'i')
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('converts >= to $gte', function() {
            var req = {
                query: {
                    query: '{"foo":">=bar"}'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                query: {
                    foo: {
                        $gte: 'bar'
                    }
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('converts > to $gt', function() {
            var req = {
                query: {
                    query: '{"foo":">bar"}'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                query: {
                    foo: {
                        $gt: 'bar'
                    }
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('converts <= to $lte', function() {
            var req = {
                query: {
                    query: '{"foo":"<=bar"}'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                query: {
                    foo: {
                        $lte: 'bar'
                    }
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('converts < to $lt', function() {
            var req = {
                query: {
                    query: '{"foo":"<bar"}'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                query: {
                    foo: {
                        $lt: 'bar'
                    }
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('converts != to $ne', function() {
            var req = {
                query: {
                    query: '{"foo":"!=bar"}'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                query: {
                    foo: {
                        $ne: 'bar'
                    }
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        // This feature was disabled because it requires MongoDB 3
        it.skip('converts = to $eq', function() {
            var req = {
                query: {
                    query: '{"foo":"=bar"}'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                query: {
                    foo: {
                        $eq: 'bar'
                    }
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('converts [] to $in', function() {
            var req = {
                query: {
                    query: '{"foo":["bar"]}'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                query: {
                    foo: {
                        $in: ['bar']
                    }
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });
    });

    it('calls next when query is empty', function() {
        prepareQuery()({}, {}, next);

        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly;
    });

    it('ignores keys that are not whitelisted and calls next', function() {
        var req = {
            query: {
                foo: 'bar'
            }
        };

        prepareQuery()(req, {}, next);

        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly;
    });

    it('calls next when query key is valid json', function() {
        var req = {
            query: {
                query: '{"foo":"bar"}'
            }
        };

        prepareQuery()(req, {}, next);

        expect(req.mquery).to.be.eql({
            query: JSON.parse(req.query.query)
        });
        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly;
    });

    it('calls next with error when query key is invalid json', function() {
        var req = {
            query: {
                query: 'not json'
            }
        };

        var err = new Error('query must be a valid JSON string');
        err.description = 'invalid_json';
        err.statusCode = 400;

        prepareQuery()(req, {}, next);

        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly(err);
    });

    it('calls next when sort key is valid json', function() {
        var req = {
            query: {
                sort: '{"foo":"bar"}'
            }
        };

        prepareQuery()(req, {}, next);

        expect(req.mquery).to.be.eql({
            sort: JSON.parse(req.query.sort)
        });
        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly;
    });

    it('calls next when sort key is a string', function() {
        var req = {
            query: {
                sort: 'foo'
            }
        };

        prepareQuery()(req, {}, next);

        expect(req.mquery).to.be.eql(req.query);
        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly;
    });

    it('calls next when skip key is a string', function() {
        var req = {
            query: {
                skip: '1'
            }
        };

        prepareQuery()(req, {}, next);

        expect(req.mquery).to.be.eql(req.query);
        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly;
    });

    it('calls next when limit key is a string', function() {
        var req = {
            query: {
                limit: '1'
            }
        };

        prepareQuery()(req, {}, next);

        expect(req.mquery).to.be.eql(req.query);
        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly;
    });

    it('calls next when distinct key is a string', function() {
        var req = {
            query: {
                distinct: 'foo'
            }
        };

        prepareQuery()(req, {}, next);

        expect(req.mquery).to.be.eql(req.query);
        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly;
    });

    it('calls next when populate key is a string', function() {
        var req = {
            query: {
                populate: 'foo'
            }
        };

        prepareQuery()(req, {}, next);

        expect(req.mquery).to.be.eql({
            populate: [{
                path: 'foo'
            }]
        });
        expect(next).to.have.been.calledOnce;
        expect(next).to.have.been.calledWithExactly;
    });

    describe('select', function() {
        it('parses a string to include fields', function() {
            var req = {
                query: {
                    select: 'foo'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                select: {
                    foo: 1
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('parses a string to exclude fields', function() {
            var req = {
                query: {
                    select: '-foo'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                select: {
                    foo: 0
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('parses a comma separated list of fields to include', function() {
            var req = {
                query: {
                    select: 'foo,bar'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                select: {
                    foo: 1,
                    bar: 1
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('parses a comma separated list of fields to exclude', function() {
            var req = {
                query: {
                    select: '-foo,-bar'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                select: {
                    foo: 0,
                    bar: 0
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('parses a comma separated list of nested fields', function() {
            var req = {
                query: {
                    select: 'foo.bar,baz.qux.quux'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                select: {
                    'foo.bar': 1,
                    'baz.qux.quux': 1
                }
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });
    });

    describe('populate', function() {
        it('parses a string to populate a path', function() {
            var req = {
                query: {
                    populate: 'foo'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                populate: [{
                    path: 'foo'
                }]
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('parses a string to populate multiple paths', function() {
            var req = {
                query: {
                    populate: 'foo,bar'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                populate: [{
                    path: 'foo'
                }, {
                    path: 'bar'
                }]
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('accepts an object to populate a path', function() {
            var req = {
                query: {
                    populate: {
                        path: 'foo.bar',
                        select: 'baz',
                        match: {
                            'qux': 'quux'
                        },
                        options: {
                            sort: 'baz'
                        }
                    }
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
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
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });

        it('parses a string to populate and select fields', function() {
            var req = {
                query: {
                    populate: 'foo',
                    select: 'foo.bar,foo.baz'
                }
            };

            prepareQuery()(req, {}, next);

            expect(req.mquery).to.be.eql({
                populate: [{
                    path: 'foo',
                    select: 'bar baz'
                }]
            });
            expect(next).to.have.been.calledOnce;
            expect(next).to.have.been.calledWithExactly;
        });
    });
});