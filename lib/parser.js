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


//global imports
const _ = require('lodash');
const async = require('async');
const parse = require('auto-parse');


//TODO use model this.where(criteria).cast(this); to cast query per model



/**
 * @name filter
 * @description parse filters from http query object into valid mongoose query 
 *              conditions
 * @param {Object} options valid query params options to parse for sorting
 *                         conditions
 * @param {Function} done a callback to invoke on success or failure
 * @return {Object} valid mongoose(mongodb) query conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-filtering}
 * @see {@link http://mongoosejs.com/docs/api.html#where_where}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 * @example
 * GET /customers?query={"name":"Bob"}
 * GET /customers?query={"name":{"$regex":"/Bo$/"}}
 * GET /customers?query={"age":{"$gt":12}}
 * GET /customers?query={"age":{"$gte":12}}
 * GET /customers?query={"age":{"$lt":12}}
 * GET /customers?query={"age":{"$lte":12}}
 * GET /customers?query={"age":{"$ne":12}}
 *
 * or
 *
 * GET /customers?filter[name]=Bob
 * GET /customers?filter[name]={"$regex":"/Bo$/"}
 * GET /customers?filter[age]={"$gt":12}
 * GET /customers?filter[age]={"$gte":12}
 * GET /customers?filter[age]={"$lt":12}
 * GET /customers?filter[age]={"$lte":12}
 * GET /customers?filter[age]={"$ne":12}
 */
exports.filter = function filter(options, done) {

  //try parsing filters
  try {

    //ensure query
    const query = _.merge({}, parse(options));

    //obtain filters field
    let filters =
      (query.filter || query.filters || query.query || query.q);

    //check if is search query
    filters = _.isString(filters) ? { q: filters } : filters;

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
 * @name paginate
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
 */
exports.paginate = function paginate(options, done) {

  //try parsing paginations
  try {

    //ensure query
    let query = _.merge({}, parse(options));

    //normalize json-api page params
    if (query.page && _.isPlainObject(query.page)) {
      query = _.merge({}, query, query.page);
      query.page = query.number;
    }

    //initialize pagination
    let paginations = { limit: 10, skip: 0, page: 1 };

    //parse limit
    //see https://apigee.com/about/tags/restful-api-design
    const limit =
      (query.limit || query.max || query.size || query.rpp ||
        query.count || query.perPage || _.get(query, 'per_page') ||
        query.cursor || 10);
    paginations = _.merge({}, paginations, { limit: limit });


    //parse page
    //see https://apigee.com/about/tags/restful-api-design
    const page = (query.page || query.number || 1);
    paginations = _.merge({}, paginations, { page: page });

    //parse skip
    //see https://apigee.com/about/tags/restful-api-design
    const hasSkip =
      _.has(query, 'skip') || _.has(query, 'offset') || _.has(query, 'start');
    let skip = (query.skip || query.offset || query.start || 0);
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
 * @description parse includes(or population) from http query object into 
 *              valid mongoose query population conditions
 * @param {Object} options valid query params options to parse for population
 *                         or includes
 * @param {Function} done a callback to invoke on success or failure
 * @return {Object} valid mongoose(mongodb) query population conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-includes}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-populate}
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
 */
exports.populate = function populate(options, done) {
  // try parsing population
  // TODO support population on related object fields selection
  try {

    //ensure query
    const query = _.merge({}, parse(options));
    let populations = (query.populate || query.include);

    //handle string populations(or includes)
    //i.e includes=customer,items or
    //includes=customer.name,items.name,items.price
    if (populations && _.isString(populations)) {

      //ensure unique populations
      populations = _.compact(populations.split(','));
      populations = _.uniq(populations);

      //normalize populations to object based
      let populates = {};
      _.each(populations, function (path) {

        //try obtain selections
        let select = _.compact(path.split('.'));
        select = _.uniq(select);

        //update path
        path = _.first(select);
        const exclude = path[0] === '-';
        path = exclude ? path.substring(1) : path;

        //update selections
        select = _.tail(select);
        select = _.reduce(select, function (accumulator, selected) {
          accumulator[selected] = exclude ? 0 : 1;
          return accumulator;
        }, {});

        //handle select
        let populate = {
          [path]: _.merge({}, { select: select }, populates[path])
        };

        //merge back
        populates = _.merge({}, populates, populate);

      });

      //map to array of populations
      populations = _.map(populates, function (value, key) {
        const populate = _.merge({}, { path: key }, value);
        return _.omitBy(populate, _.isEmpty);
      });

      done(null, populations);

    }

    //handle plain object
    //i.e {"path":"customer", "select":"name,price" }
    //or {"path":"customer", "select":{"name":1, "price":1} }
    else if (populations && _.isPlainObject(populations)) {
      //throw if no select
      if (!populations.path) {
        let error = new Error('Missing Population Path');
        error.status = 400;
        done(error);
      }

      //parse select
      else if (populations.select) {
        exports.select(populations, function (error, select) {
          done(error, [_.merge({}, populations, { select: select })]);
        });
      }

      //continue
      else {
        done(null, [populations]);
      }

    }

    //handle plain object
    //i.e [{"path":"customer", "select":"name,price" }]
    //or [{"path":"customer", "select":{"name":1, "price":1} }]
    else if (populations && _.isArray(populations)) {

      populations = _.map(populations, function (population) {

        return function (next) {

          //throw if no select
          if (!population.path) {
            let error = new Error('Missing Population Path');
            error.status = 400;
            next(error);
          }

          //parse select
          else if (population.select) {
            exports.select(population, function (error, select) {
              next(error, _.merge({}, population, { select: select }));
            });
          }

          //continue
          else {
            next(null, population);
          }
        };

      });

      async.parallel(populations, done);

    }

    //do nothing
    else {
      done(null, undefined);
    }

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
 * @version 0.1.0
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
    const query = _.merge({}, parse(options));
    let projections = (query.select || query.fields || query.projections);

    //handle string projection i.e select=name,email
    if (projections && _.isString(projections)) {

      //ensure unique projections
      projections = _.compact(projections.split(','));
      projections = _.uniq(projections);

      //normalize projections to object based
      projections = _.reduce(projections, function (accumulator, projection) {

        projection.trim();

        //if exclude i.e select=-name
        if (projection[0] === '-') {
          accumulator[projection.substring(1)] = 0;
        }

        //if include i.e select=name
        else {
          accumulator[projection] = 1;
        }

        return accumulator;

      }, {});

    }

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
    const query = _.merge({}, parse(options));
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
          accumulator[sort.substring(1)] = 0;
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

    const json = parse(string);

    //parse query parameters in parallel
    async.parallel({

      filter: function parseFilters(next) {
        exports.filter(json, next);
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

    }, done);

  }

  //handle all error
  catch (error) {
    error.message = error.message || 'Bad Request';
    error.status = 400;
    done(error);
  }

};