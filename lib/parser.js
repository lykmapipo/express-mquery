'use strict';



/**
 * @module parser
 * @name parser
 * @description http query params parser to valid mongoose(mongodb) query methods 
 *              and options
 * @see  {@link https://docs.mongodb.com/manual/reference/operator/query/}
 * @see  {@link http://mongoosejs.com/docs/api.html#Query}
 * @see  {@link http://jsonapi.org/recommendations/}
 * @see  {@link http://mgmco.github.io/api-query-spec/}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */


/*** global imports */
const _ = require('lodash');
const async = require('async');
const autoParse = require('auto-parse');



/**
 * @name filter
 * @function filter
 * @description parse filters from http query object into valid mongoose query 
 *              conditions
 * @param {Object} options valid query params options to parse for sorting
 *                         conditions
 * @param {Function} done a callback to invoke on success or failure
 * @return {Object} valid mongoose(mongodb) query conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-filtering}
 * @see {@link http://mongoosejs.com/docs/api.html#where_where}
 * @see  {@link https://docs.mongodb.com/manual/reference/operator/query/}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 * @example
 * 
 * comparison
 * GET /customers?query={"name":"Bob"}
 * GET /customers?filter[name]=Bob
 * GET /customers?filter[name]={"$regex":"/Bo$/"}
 * GET /customers?filter[name][$regex]="/Bo$/"
 * GET /customers?filter[age]={"$gt":12}
 * GET /customers?filter[age][$gt]=12
 * 
 * 
 */
exports.filter = function filter(options, done) {

  //try parsing filters
  try {

    //ensure query
    const query = _.merge({}, autoParse(options));

    //obtain filters field
    let filters =
      (query.filter || query.filters || query.query || query.q);

    //check if is search query
    filters = _.isString(filters) ? { q: filters } : filters;

    //TODO ignore ['$jsonSchema', '$where']

    done(null, filters);

  }

  //catch all errors
  catch (error) {
    error.message = error.message || 'Bad Request';
    error.status = 400;
    done(error);
  }

};



/**
 * @name headers
 * @function headers
 * @description parse headers to obtain request pre-conditions
 * @param {Object} options valid http headers to parse for pre-conditions
 * @param {Function} done a callback to invoke on success or failure
 * @return {Object} valid parsed pre-conditions headers
 * @see  {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since}
 * @author lally elias <lallyelias87@mail.com>
 * @since 1.0.1
 * @version 0.1.0
 * @public
 * @example
 * 
 * GET /customers?header['if-modified-since']=Mon Apr 16 2018 11:28:06 GMT+0300 (EAT)
 *
 * or
 * 
 * curl -i -H 'If-Modified-Since: Wed, 12 Nov 2014 15:44:46 GMT' http://localhost:3000/invoices
 * 
 */
exports.headers = function headers(options, done) {

  //try parsing headers
  try {

    //ensure query
    const query = autoParse(options);
    let headers = _.merge({}, query.header, query.headers);

    //normalize headers

    //... pick allowed headers
    const ALLOWED_HEADERS = ['if-modified-since'];
    headers = _.pick(headers, ALLOWED_HEADERS);


    //... camelize header names
    headers = _.mapKeys(headers, function (value, key) {
      return _.camelCase(key);
    });

    //... normalize date headers
    const DATE_HEADERS = ['ifModifiedSince'];
    headers = _.mapValues(headers, function (value, key) {
      return _.includes(DATE_HEADERS, key) ? new Date(value) : value;
    });

    done(null, headers);

  }

  //catch all errors
  catch (error) {
    error.message = error.message || 'Bad Request';
    error.status = 400;
    done(error);
  }

};



/**
 * @name paginate
 * @function paginate
 * @description parse paginations(i.e limit, offset, skip, page etc) from 
 *              http query object into valid mongoose pagination conditions
 * * @param {Object} options valid query params options to parse for sorting
 *                         conditions
 * @param {Function} done a callback to invoke on success or failure
 * @return {Object} valid mongoose(mongodb) pagination query conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-pagination}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-skip}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-limit}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 * @example
 * 
 * GET /customers?skip=10&limit=10
 * GET /customers?limit=10
 * GET /customers?page=1
 * GET /customers?page[number]=1
 * GET /customers?page[number]=1&page[offset]=10
 * GET /customers?page[number]=1&page[limit]=10
 * GET /customers?page[number]=1&page[size]=10
 * 
 */
exports.paginate = function paginate(options, done) {

  //try parsing paginations
  try {

    //ensure query
    let query = _.merge({ maxLimit: 50 }, autoParse(options));

    //normalize json-api page params
    if (query.page && _.isPlainObject(query.page)) {
      query = _.merge({}, query, query.page);
      query.page = query.number;
    }


    //initialize pagination
    let paginations = { limit: 10, skip: 0, page: 1 };

    //parse limit
    //see https://apigee.com/about/tags/restful-api-design
    let limit =
      (query.limit || query.max || query.size || query.rpp ||
        query.count || query.perPage || _.get(query, 'per_page') ||
        query.cursor || 10);
    limit = limit > query.maxLimit ? query.maxLimit : limit;
    limit = limit < 0 ? 10 : limit;
    paginations = _.merge({}, paginations, { limit: limit });


    //parse page
    //see https://apigee.com/about/tags/restful-api-design
    let page = (query.page || query.number || 1);
    page = page < 0 ? 1 : page;
    paginations = _.merge({}, paginations, { page: page });

    //parse skip
    //see https://apigee.com/about/tags/restful-api-design
    const hasSkip =
      _.has(query, 'skip') || _.has(query, 'offset') || _.has(query, 'start');
    let skip = (query.skip || query.offset || query.start || 0);
    skip = skip < 0 ? 0 : skip;
    //correct skip base on page number
    skip = (!hasSkip && page > 0) ? ((page - 1) * limit) : skip;
    paginations = _.merge({}, paginations, { skip: skip });

    done(null, paginations);

  }

  //catch all errors
  catch (error) {
    error.message = error.message || 'Bad Request';
    error.status = 400;
    done(error);
  }

};



/**
 * @name populate
 * @function populate
 * @description parse includes(or population) from http query object into 
 *              valid mongoose query population conditions
 * @param {Object} options valid query params options to parse for population
 *                         or includes
 * @param {Function} done a callback to invoke on success or failure
 * @return {Object} valid mongoose(mongodb) query population conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-includes}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-populate}
 * @see  {@link http://mongoosejs.com/docs/populate.html#deep-populate}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 * @example
 * /invoice?populate=customer
 * /invoice?populate=customer,items
 * /invoice?populate=customer.name,items.name,items.price
 * /invoice?populate={"path":"customer", "select":"name,price" }
 * /invoice?populate={"path":"customer", "select":{"name":1, "price":1} }
 * /invoice?populate=[{"path":"customer"}, {"path":"items"}]
 * /invoice?populate=[{"path":"customer", "select":"name"}, {"path":"items", "select":{"name": 1, "price": 1}}]
 *
 * or
 *
 * /invoice?includes=customer
 * /invoice?includes=customer,items
 * /invoice?includes=customer.name,items.name,items.price
 * /invoice?includes={"path":"customer", "select":"name,price" }
 * /invoice?includes={"path":"customer", "select":{"name":1, "price":1} }
 * /invoice?includes=[{"path":"customer"}, {"path":"items"}]
 * /invoice?includes=[{"path":"customer", "select":"name"}, {"path":"items", "select":{"name": 1, "price": 1}}]
 *
 * or
 * 
 * /invoice?includes[customer]=name,number&includes[items]=name,price
 * /invoice?includes=customer,items&fields[customer]=name,number&fields[items]=name,price
 * 
 */
exports.populate = function populate(options, done) {
  // try parsing population
  // TODO support population on related object fields selection
  // TODO support nested population
  try {

    //ensure query
    const query = _.merge({}, autoParse(options));
    let populations =
      (query.populate || query.include || query.includes);

    //handle string populations(or includes)
    //i.e includes=customer,items or
    //includes=customer.name,items.name,items.price
    if (populations && _.isString(populations)) {

      //ensure unique populations
      populations = [].concat(populations.split(','));
      populations = _.compact(populations);
      populations = _.map(populations, function (population) {
        return population.trim();
      });
      populations = _.uniq(populations);

      //normalize populations to object based
      //and
      //map to array of populations
      populations = _.map(populations, function (population) {
        return _.merge({}, { path: population });
      });

    }

    //handle object population
    //i.e {"path":"customer", "select":"name,price" }
    //or {"path":"customer", "select":{"name":1, "price":1} }
    // or
    //handle array populations
    //i.e [{"path":"customer", "select":"name,price" }]
    //or [{"path":"customer", "select":{"name":1, "price":1} }]

    //ensure array
    populations = _.compact([].concat(populations));

    //build populations
    async.waterfall([

      //parse field selections
      function parseSelect(next) {
        exports.select(query, next);
      },

      //normalize populations
      function normalize(selections, next) {

        populations = _.map(populations, function (population) {

          return function (cb) {

            //obtain population selected fields
            const fields =
              (selections ? selections[population.path] : undefined);
            if (fields) {
              population = _.merge({}, population, { select: fields });
            }

            //parse path specific select
            if (population.select) {
              exports.select(population, function (error, select) {
                cb(error, _.merge({}, population, { select: select }));
              });
            }

            //continue
            else {
              cb(null, population);
            }

          };

        });

        async.parallel(populations, next);

      }
    ], done);

  }

  //catch all errors
  catch (error) {
    error.message = error.message || 'Bad Request';
    error.status = 400;
    done(error);
  }

};



/**
 * @name select
 * @function select
 * @description parse fields from http query object into valid mongoose query 
 *              select conditions
 * @param {Object} options valid query params options to parse for select fields
 * @param {Function} done a callback to invoke on success or failure
 * @return {Object} valid mongoose(mongodb) query select conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-sparse-fieldsets}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-select}
 * @see  {@link https://docs.mongodb.com/manual/tutorial/project-fields-from-query-results/}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.2.0
 * @public
 * @example
 * GET /users?select=name
 * GET /users?select=name,email
 * GET /users?select=-name
 * GET /users?select=-name,-email
 * GET /users?select={"name":1}
 * GET /users?select={"name":1, "email":1}
 * GET /users?select={"name":0}
 * GET /users?select={"name":0, "email": 0}
 *
 * or
 *
 * GET /users?fields=name
 * GET /users?fields=name,email
 * GET /users?fields=-name
 * GET /users?fields=-name,-email
 *
 * or
 * 
 * GET /users?select={"location.name":0, "location.address": 0}
 * GET /users?fields[location]=-name,-address
 * 
 */
exports.select = function select(options, done) {

  //try parsing projections
  try {

    //ensure query
    const query = _.merge({}, autoParse(options));
    let projections =
      (query.select || query.fields || query.projections);

    if (_.isString(projections)) {
      projections = [].concat(projections);
    }

    if (_.isPlainObject(projections)) {
      projections = _.map(projections, function (proj, key) {
        if (!_.isNaN(Number(key))) {
          return proj;
        } else {
          return {
            [key]: proj
          };
        }
      });
    }

    //parse comma separated fields into mongodb
    //awase projections
    const fieldify = function (projection = '') {

      //prepare projections
      let fields = _.compact(projection.split(','));
      fields = _.map(fields, _.trim);
      fields = _.uniq(fields);
      const accumulator = {};

      _.forEach(fields, function (field) {

        //if exclude e.g -name
        if (field[0] === '-') {
          accumulator[field.substring(1)] = 0;
        }

        //if include i.e name
        else {
          accumulator[field] = 1;
        }

      });

      return accumulator;
    };


    //normalize projections to object based
    projections =
      _.reduce(projections, function (accumulator, projection) {

        //handle string projection i.e select=name,email
        if (projection && _.isString(projection)) {
          const fields = fieldify(projection);
          accumulator = _.merge({}, accumulator, fields);
        }

        if (_.isPlainObject(projection)) {
          _.forEach(projection, function (value, key) {
            if (!_.isNaN(Number(value))) {
              accumulator = _.merge({}, accumulator, {
                [key]: value
              });
            } else {
              const fields = fieldify(value);
              accumulator = _.merge({}, accumulator, {
                [key]: fields
              });
            }
          });
        }

        return accumulator;

      }, {});

    done(null, projections);

  }

  //catch all errors
  catch (error) {
    error.message = error.message || 'Bad Request';
    error.status = 400;
    done(error);
  }

};



/**
 * @name sort
 * @function sort
 * @description parse sorts from http query object into valid mongoose sorting 
 *              conditions
 * @param {Object} options valid query params options to parse for sorting
 *                         conditions
 * @param {Function} done a callback to invoke on success or failure
 * @return {Object} valid mongoose(mongodb) sorting conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-sorting}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-sort}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 * @example
 * GET /users?sort=name
 * GET /users?sort=name,email
 * GET /users?sort=-name
 * GET /users?sort=-name,-email
 * GET /users?sort={"name":1}
 * GET /users?sort={"name":1, "email":1}
 * GET /users?sort={"name":0}
 * GET /users?sort={"name":0, "email": 0}
 * GET /users?sort={"name":"asc", "email": "desc"}
 * GET /users?sort={"name":"ascending", "email": "descending"}
 */
exports.sort = function sort(options, done) {

  //try parsing sorts
  try {

    //ensure query
    const query = _.merge({}, autoParse(options));
    let sorts = (query.order || query.sort);

    //handle string sort i.e sort=name,email
    if (sorts && _.isString(sorts)) {

      //ensure unique sorts
      sorts = _.compact(sorts.split(','));
      sorts = _.uniq(sorts);

      //normalize sorts to object based
      sorts = _.reduce(sorts, function (accumulator, sort) {

        sort.trim();

        //if exclude i.e sort=-name
        if (sort[0] === '-') {
          accumulator[sort.substring(1)] = -1;
        }

        //if include i.e sort=name
        else {
          accumulator[sort] = 1;
        }

        return accumulator;

      }, {});

    }

    done(null, sorts);

  }

  //catch all errors
  catch (error) {
    error.message = error.message || 'Bad Request';
    error.status = 400;
    done(error);
  }
};




/**
 * @name parse
 * @function parse
 * @param {String} string valid json string
 * @description parse specified JSON string into Javascript value or object
 * @return {Object} constructed JavaScript value or object from JSON key value
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */
exports.parse = function parse(string, done) {

  //TODO navigate paths and change them to valid mongodb query

  //try to parse json string
  try {

    const json = autoParse(string);

    //parse query parameters in parallel
    async.parallel({

      filter: function parseFilters(next) {
        exports.filter(json, next);
      },

      headers: function parseHeaders(next) {
        exports.headers(json, next);
      },

      paginate: function parsePaginations(next) {
        exports.paginate(json, next);
      },

      populate: function parsePopulations(next) {
        exports.populate(json, next);
      },

      select: function parseProjections(next) {
        exports.select(json, next);
      },

      sort: function parseSorts(next) {
        exports.sort(json, next);
      }

    }, function (error, mquery) {

      if (mquery) {
        //remove unused
        delete mquery.maxLimit;

        //remove populations in selects
        if (mquery.populate && mquery.select) {
          const populations = _.map(mquery.populate, 'path');
          mquery.select = _.omit(mquery.select, populations);
        }

        //compact
        mquery = _.omitBy(mquery, _.isEmpty);

      }

      done(error, mquery);

    });

  }

  //handle all error
  catch (error) {
    error.message = error.message || 'Bad Request';
    error.status = 400;
    done(error);
  }

};