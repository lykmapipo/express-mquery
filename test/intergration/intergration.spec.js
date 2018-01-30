'use strict';

//dependencies
var path = require('path');
var expect = require('chai').expect;
var request = require('supertest');
var express = require('express');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var mquery = require(path.join(__dirname, '..', '..'));
var init = require(path.join(__dirname, 'setup'))();

//setup express app
var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(mquery.middleware());

describe('express-mquery', function() {

  before(function(done) {
    init.initialize();
    init.seed(done);
  });

  before(function() {
    app.get('/customers', function(request, response) {
      var Customer = mongoose.model('Customer');

      Customer
        .mquery(request)
        .exec(function(error, users) {
          if (error) {
            response.status(500).json({
              error: error.message
            });
          } else {
            response.json(users);
          }
        });
    });

    app.get('/paginates', function(request, response) {
      var Customer = mongoose.model('Customer');

      Customer
        .paginate(request, function(error, users, pages, total) {
          if (error) {
            response.status(500).json({
              error: error.message
            });
          } else {
            response.json({
              users: users,
              pages: pages,
              total: total
            });
          }
        });
    });

    app.get('/invoices', function(request, response) {
      var Invoice = mongoose.model('Invoice');

      Invoice
        .mquery(request)
        .exec(function(error, invoices) {
          if (error) {
            response.status(500).json({
              error: error.message
            });
          } else {
            response.json(invoices);
          }
        });
    });
  });

  after(function(done) {
    init.reset(done);
  });

  it('should export express middleware', function() {
    expect(mquery.middleware).to.be.a('function');
  });

  it(
    'should export mongoose plugin that add `mquery` and `paginate` static functions',
    function() {
      var Customer = mongoose.model('Customer');
      expect(mquery.plugin).to.be.a('function');
      expect(Customer.mquery).to.be.a('function');
      expect(Customer.paginate).to.be.a('function');
    });

  describe('distinct', function() {
    it('GET /customers?distinct=name 200 - array of unique names',
      function(done) {
        request(app)
          .get('/customers')
          .query({
            distinct: 'name'
          })
          .expect('Content-Type', /json/)
          .expect(200)
          .end(function(error, response) {
            expect(error).to.not.exist;

            var body = response.body;

            expect(body.length).to.be.equal(3);
            expect(body[0]).to.be.equal('Bob');
            expect(body[1]).to.be.equal('John');
            expect(body[2]).to.be.equal('Mike');

            done(error, response);
          });
      });
  });

  describe('limit', function() {
    it('GET /customers?limit=1 200', function(done) {
      request(app)
        .get('/customers')
        .query({
          limit: 1
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;
          expect(response.body.length).to.be.equal(1);
          done(error, response);
        });
    });
  });

  describe('populate', function() {
    it('GET /invoices?populate=customer 200', function(done) {
      request(app)
        .get('/invoices')
        .query({
          populate: 'customer'
        }).expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;

          expect(body.length).to.be.equal(3);

          body.forEach(function(invoice) {
            expect(invoice.customer).to.be.ok;
            expect(invoice.customer._id).to.be.ok;
            expect(invoice.customer.name).to.be.ok;
            expect(invoice.customer.age).to.be.ok;
          });

          done(error, body);
        });
    });

    it('GET /invoices?populate={path:"customer"} 200', function(done) {
      request(app)
        .get('/invoices')
        .query({
          populate: JSON.stringify({
            path: 'customer'
          })
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;

          expect(body.length).to.be.equal(3);

          body.forEach(function(invoice) {
            expect(invoice.customer).to.be.ok;
            expect(invoice.customer._id).to.be.ok;
            expect(invoice.customer.name).to.be.ok;
            expect(invoice.customer.age).to.be.ok;
          });

          done(error, response);
        });
    });

    it('GET /invoices?populate=[{path:"customer"}] 200', function(done) {
      request(app)
        .get('/invoices')
        .query({
          populate: JSON.stringify([{
            path: 'customer'
          }])
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;

          expect(body.length).to.be.equal(3);

          body.forEach(function(invoice) {
            expect(invoice.customer).to.be.ok;
            expect(invoice.customer._id).to.be.ok;
            expect(invoice.customer.name).to.be.ok;
            expect(invoice.customer.age).to.be.ok;
          });

          done(error, response);
        });
    });

    it(
      'GET /customers?populate=favorites.purchase.item 200 - nested field',
      function(done) {
        request(app)
          .get('/customers')
          .query({
            populate: 'favorites.purchase.item'
          })
          .expect('Content-Type', /json/)
          .expect(200)
          .end(function(error, response) {
            expect(error).to.not.exist;

            var body = response.body;

            expect(body.length).to.be.equal(3);

            body.forEach(function(customer) {
              expect(customer.favorites.purchase).to.be.ok;
              expect(customer.favorites.purchase.item).to.be.ok;
              expect(customer.favorites.purchase.item._id).to.be
                .ok;
              expect(customer.favorites.purchase.item.name).to.be
                .ok;
              expect(customer.favorites.purchase.number).to.be.ok;
            });

            done(error, response);
          });
      });

    it(
      'GET /invoices?populate=customer.account 200 - ignore deep populate',
      function(done) {
        request(app)
          .get('/invoices')
          .query({
            populate: 'customer.account'
          })
          .expect('Content-Type', /json/)
          .expect(200)
          .end(function(error, response) {
            expect(error).to.not.exist;

            var body = response.body;

            expect(body.length).to.be.equal(3);
            body.forEach(function(invoice) {
              expect(invoice.customer).to.be.ok;
              expect(typeof invoice.customer).to.be.equal(
                'string');
            });

            done(error, response);
          });
      });

    it('GET /invoices?populate=evilCustomer 200 - ignore unknown field',
      function(done) {
        request(app)
          .get('/invoices')
          .query({
            populate: 'evilCustomer'
          })
          .expect('Content-Type', /json/)
          .expect(200)
          .end(function(error, response) {
            expect(error).to.not.exist;

            var body = response.body;

            expect(body.length).to.be.equal(3);

            done(error, response);
          });
      });

    describe('with select', function() {
      it(
        'GET invoices?populate=customer&select=amount 200 - only include amount and customer document',
        function(done) {
          request(app)
            .get('/invoices')
            .query({
              populate: 'customer',
              select: 'amount'
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(3);

              body.forEach(function(invoice) {
                expect(invoice.amount).to.be.ok;
                expect(invoice.customer).to.be.ok;
                expect(invoice.customer._id).to.be.ok;
                expect(invoice.customer.name).to.be.ok;
                expect(invoice.customer.age).to.be.ok;
                expect(invoice.receipt).to.be.undefined;
              });

              done(error, response);
            });
        });

      it(
        'GET invoices?populate=customer&select=amount,customer.name 200 - only include amount and customer name',
        function(done) {
          request(app)
            .get('/invoices')
            .query({
              populate: 'customer',
              select: 'amount,customer.name'
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(3);
              body.forEach(function(invoice) {
                expect(invoice.amount).to.be.ok;
                expect(invoice.customer).to.be.ok;
                expect(invoice.customer._id).to.be.ok;
                expect(invoice.customer.name).to.be.ok;
                expect(invoice.customer.age).to.be.undefined;
                expect(invoice.receipt).to.be.undefined;
              });

              done(error, response);
            });
        });

      it(
        'GET invoices?populate=customer&select=customer.name 200 - include all invoice fields, but only include customer name',
        function(done) {
          request(app)
            .get('/invoices')
            .query({
              populate: 'customer',
              select: 'customer.name'
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(3);

              body.forEach(function(invoice) {
                expect(invoice.amount).to.be.ok;
                expect(invoice.receipt).to.be.ok;
                expect(invoice.customer).to.be.ok;
                expect(invoice.customer._id).to.be.ok;
                expect(invoice.customer.name).to.be.ok;
                expect(invoice.customer.age).to.be.undefined;
              });

              done(error, response);
            });
        });

      it(
        'GET invoices?populate=customer&select=-customer.name 200 - include all invoice and fields, but exclude customer name',
        function(done) {
          request(app)
            .get('/invoices')
            .query({
              populate: 'customer',
              select: '-customer.name'
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(3);

              body.forEach(function(invoice) {
                expect(invoice.amount).to.be.ok;
                expect(invoice.receipt).to.be.ok;
                expect(invoice.customer).to.be.ok;
                expect(invoice.customer._id).to.be.ok;
                expect(invoice.customer.age).to.be.ok;
                expect(invoice.customer.name).to.be.undefined;
              });

              done(error, response);
            });
        });

      it(
        'GET invoices?populate=customer&select=amount,-customer._id,customer.name 200 - only include amount and customer name and exclude customer _id',
        function(done) {
          request(app)
            .get('/invoices')
            .query({
              populate: 'customer',
              select: 'amount,-customer._id,customer.name'
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(3);

              body.forEach(function(invoice) {
                expect(invoice.amount).to.be.ok;
                expect(invoice.customer).to.be.ok;
                expect(invoice.customer.name).to.be.ok;
                expect(invoice.receipt).to.be.undefined;
                expect(invoice.customer._id).to.be.undefined;
                expect(invoice.customer.age).to.be.undefined;
              });

              done(error, response);
            });
        });

      it(
        'GET invoices?populate=customer&select=customer.name,customer.age 200 - only include customer name and age',
        function(done) {
          request(app)
            .get('/invoices')
            .query({
              populate: 'customer',
              select: 'customer.name,customer.age'
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(3);

              body.forEach(function(invoice) {
                expect(invoice.amount).to.be.ok;
                expect(invoice.receipt).to.be.ok;
                expect(invoice.customer).to.be.ok;
                expect(invoice.customer._id).to.be.ok;
                expect(invoice.customer.name).to.ok;
                expect(invoice.customer.age).to.be.ok;
              });

              done(error, response);
            });
        });
    });
  });

  describe('paginate', function() {
    it('GET /paginates', function(done) {
      request(app)
        .get('/paginates')
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;

          expect(body.total).to.exist;
          expect(body.pages).to.exist;

          expect(body.users.length).to.be.equal(3);
          expect(body.users[0].name).to.be.equal('Bob');
          expect(body.users[1].name).to.be.equal('John');
          expect(body.users[2].name).to.be.equal('Mike');

          done(error, response);
        });
    });
  });

  describe('select', function() {
    it('GET /customers?select=name 200 - only include', function(done) {
      request(app)
        .get('/customers')
        .query({
          select: 'name'
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;
          expect(body.length).to.be.equal(3);

          body.forEach(function(item) {
            expect(Object.keys(item).length).to.be.equal(4);
            expect(item._id).to.be.ok;
            expect(item.name).to.be.ok;
          });

          done(error, response);
        });
    });

    it(
      'GET /customers?select=favorites.animal 200 - only include (nested field)',
      function(done) {
        request(app)
          .get('/customers')
          .query({
            select: 'favorites.animal'
          })
          .expect('Content-Type', /json/)
          .expect(200)
          .end(function(error, response) {
            expect(error).to.not.exist;

            var body = response.body;
            expect(body.length).to.be.equal(3);

            body.forEach(function(item) {
              expect(Object.keys(item).length).to.be.equal(4);
              expect(item._id).to.be.ok;
              expect(item.favorites).to.be.ok;
              expect(item.favorites.animal).to.be.ok;
              expect(item.favorites.color === undefined).to.be.ok;
            });

            done(error, response);
          });
      });

    it('GET /customers?select=-name 200 - exclude name', function(done) {
      request(app)
        .get('/customers')
        .query({
          select: '-name'
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;
          expect(body.length).to.be.equal(3);

          body.forEach(function(item) {
            expect(item.name === undefined).to.be.ok;
          });

          done(error, response);
        });
    });

    it('GET /customers?select={"name":1} 200 - only include name',
      function(done) {
        request(app)
          .get('/customers')
          .query({
            select: JSON.stringify({
              name: 1
            })
          })
          .expect('Content-Type', /json/)
          .expect(200)
          .end(function(error, response) {
            expect(error).to.not.exist;

            var body = response.body;
            expect(body.length).to.be.equal(3);

            body.forEach(function(item) {
              expect(Object.keys(item).length).to.be.equal(4);
              expect(item._id).to.be.ok;
              expect(item.name).to.be.ok;
            });

            done(error, response);
          });
      });

    it('GET /customers?select={"name":0} 200 - exclude name', function(
      done) {
      request(app)
        .get('/customers')
        .query({
          select: JSON.stringify({
            name: 0
          })
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;
          expect(body.length).to.be.equal(3);

          body.forEach(function(item) {
            expect(item.name === undefined).to.be.ok;
          });

          done(error, response);
        });
    });
  });

  describe('skip', function() {
    it('GET /customers?skip=1 200', function(done) {
      request(app)
        .get('/customers')
        .query({
          skip: 1
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;
          expect(response.body.length).to.be.equal(2);
          done(error, response);
        });
    });
  });

  describe('sort', function() {
    it('GET /customers?sort=name 200', function(done) {
      request(app)
        .get('/customers')
        .query({
          sort: 'name'
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;
          expect(body.length).to.be.equal(3);

          expect(body[0].name).to.be.equal('Bob');
          expect(body[1].name).to.be.equal('John');
          expect(body[2].name).to.be.equal('Mike');

          done(error, response);
        });
    });

    it('GET /customers?sort=-name 200', function(done) {
      request(app)
        .get('/customers')
        .query({
          sort: '-name'
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;
          expect(body.length).to.be.equal(3);

          expect(body[0].name).to.be.equal('Mike');
          expect(body[1].name).to.be.equal('John');
          expect(body[2].name).to.be.equal('Bob');

          done(error, response);
        });
    });

    it('GET /customers?sort={"name":1} 200', function(done) {
      request(app)
        .get('/customers')
        .query({
          sort: {
            name: 1
          }
        })
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;
          expect(body.length).to.be.equal(3);

          expect(body[0].name).to.be.equal('Bob');
          expect(body[1].name).to.be.equal('John');
          expect(body[2].name).to.be.equal('Mike');

          done(error, response);
        });
    });

    it('GET /customers?sort={"name":-1} 200', function(done) {
      request(app)
        .get('/customers')
        .query({
          sort: {
            name: -1
          }
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;
          expect(body.length).to.be.equal(3);

          expect(body[0].name).to.be.equal('Mike');
          expect(body[1].name).to.be.equal('John');
          expect(body[2].name).to.be.equal('Bob');

          done(error, response);
        });
    });
  });

  describe('where', function() {
    it('GET /customers?query={} 200 - empty object', function(done) {
      request(app)
        .get('/customers')
        .query({
          query: JSON.stringify({})
        })
        .expect('Content-Type', /json/)
        .expect(200)
        .end(function(error, response) {
          expect(error).to.not.exist;

          var body = response.body;
          expect(body.length).to.be.equal(3);

          done(error, response);
        });
    });


    describe('string', function() {
      it('GET /customers?query={"name":"John"} 200 - exact match',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                name: 'John'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;
              expect(body.length).to.be.equal(1);
              expect(body[0].name).to.be.equal('John');

              done(error, response);
            });
        });

      it(
        'GET /customers?query={"name":"~^J"} 200 - name starting with',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                name: '~^J'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(1);
              expect(body[0].name[0]).to.be.equal('J');

              done(error, response);
            });
        });

      it(
        'GET /customers?query={"name":">=John"} 200 - greater than or equal',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                name: '>=John'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body[0].name >= 'John').to.be.ok;
              expect(body[1].name >= 'John').to.be.ok;

              done(error, response);
            });
        });

      it('GET /customers?query={"name":">John"} 200 - greater than',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                name: '>John'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;
              expect(body.length).to.be.equal(1);
              expect(body[0].name > 'John').to.be.ok;

              done(error, response);
            });
        });

      it(
        'GET /customers?query={"name":"<=John"} 200 - lower than or equal',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                name: '<=John'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(2);
              expect(body[0].name[0] <= 'John').to.be.ok;
              expect(body[1].name[0] <= 'John').to.be.ok;

              done(error, response);
            });
        });

      it('GET /customers?query={"name":"<John"} 200 - lower than',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                name: '<John'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(1);
              expect(body[0].name[0] < 'John').to.be.ok;

              done(error, response);
            });
        });

      it('GET /customers?query={"name":"!=John"} 200 - not equal',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                name: '!=John'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(2);
              expect(body[0].name).to.not.equal('John');
              expect(body[1].name).to.not.equal('John');

              done(error, response);
            });
        });

      // This feature was disabled because it requires MongoDB 3
      it.skip('GET /customers?query={"name":"=John"} 200 - equal',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                name: '=John'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(1);
              expect(body[0].name === 'John').to.be.ok;

              done(error, response);
            });
        });

      it(
        'GET /customers?query={"name":["Bob","John"]}&sort=name 200 - in',
        function(done) {
          request(app)
            .get('/customers').query({
              query: JSON.stringify({
                name: ['Bob', 'John']
              }),
              sort: 'name'
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(2);
              expect(body[0].name).to.be.equal('Bob');
              expect(body[1].name).to.be.equal('John');

              done(error, response);
            });
        });
    });

    describe('number', function() {
      it('GET /customers?query={"age":"24"} 200 - exact match',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                age: 24
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(1);
              expect(body[0].age).to.be.equal(24);

              done(error, response);
            });
        });

      it(
        'GET /customers?query={"age":">=24"} 200 - greater than or equal',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                age: '>=24'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(2);

              expect(body[0].age >= 24).to.be.ok;
              expect(body[1].age >= 24).to.be.ok;

              done(error, response);
            });
        });

      it('GET /customers?query={"age":">24"} 200 - greater than',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                age: '>24'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(1);
              expect(body[0].age > 24).to.be.ok;

              done(error, response);
            });
        });

      it(
        'GET /customers?query={"age":"<=24"} 200 - lower than or equal',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                age: '<=24'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(2);
              expect(body[0].age <= 24).to.be.ok;
              expect(body[1].age <= 24).to.be.ok;

              done(error, response);
            });
        });

      it('GET /customers?query={"age":"<24"} 200 - lower than',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                age: '<24'
              })
            }).expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(1);
              expect(body[0].age).to.be.equal(12);

              done(error, response);
            });
        });

      it('GET /customers?query={"age":"!=24"} 200 - not equal',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                age: '!=24'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(2);
              expect(body[0].age).to.not.be.equal(24);
              expect(body[1].age).to.not.be.equal(24);

              done(error, response);
            });
        });

      // This feature was disabled because it requires MongoDB 3
      it.skip('GET /customers?query={"age":"=24"} 200 - equal',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                age: '=24'
              })
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(1);
              expect(body[0].age).to.be.equal(24);

              done(error, response);
            });
        });

      it(
        'GET /customers?query={"age":["12","24"]}&sort=age 200 - in',
        function(done) {
          request(app)
            .get('/customers')
            .query({
              query: JSON.stringify({
                age: ['12', '24']
              }),
              sort: 'age'
            })
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function(error, response) {
              expect(error).to.not.exist;

              var body = response.body;

              expect(body.length).to.be.equal(2);
              expect(body[0].age).to.be.equal(12);
              expect(body[1].age).to.be.equal(24);

              done(error, response);
            });
        });
    });
  });

});