'use strict';


//dependencies
const path = require('path');
const _ = require('lodash');
const async = require('async');
const parser = require(path.join(__dirname, 'lib', 'parser'));
const mongooseSearch = require('mongoose-regex-search');


/**
 * @name middleware
 * @function middleware
 * @param  {Object} [optns] valid middleware options
 * @param  {Object} [optns.limit] default limit
 * @param  {Object} [optns.maxLimit] default max limit
 * @return {Function[]} valid express middleware stack
 * @example
 * 
 * const expess = require('express');
 * const middleware = require('express-mquery').middleware;
 *
 * 
 * const app = express();
 * app.use(middleware({limit: 10, maxLimit: 50}));
 * 
 */
exports.middleware = function middleware(optns) {

  //normalize options
  const options = _.merge({}, {
    limit: 10,
    maxLimit: 50
  }, optns);

  //pack & return middlewares stack
  return [
    function prepareMquery(request, response, next) {
      const query = _.merge({}, options, request.query);
      parser
        .parse(query, function (error, mquery) {

          if (mquery && !_.isEmpty(mquery)) {
            request.mquery = mquery;
          }

          next(error, mquery);

        });
    }
  ];

};



/**
 * @name plugin
 * @function plugin
 * @param  {Object} [optns] valid mongoose schema options
 * @example
 * 
 * const mongoose = require('mongoose');
 * const plugin = require('express-mquery').plugin;
 * mongoose.plugin(plugin());
 *
 * const expess = require('express');
 * const middleware = require('express-mquery').middleware;
 *
 * 
 * const app = express();
 * app.use(middleware({limit: 10, maxLimit: 50}));
 *
 * ....
 * app.get('/users', function(request, response, next){
 *   User
 *     .countAndPaginate(request.mquery, function(error, results){
 *       if(error){
 *         next(error);
 *       }
 *       else{
 *         response.status(200);
 *         response.json(results);
 *       }
 *     });
 * });
 * 
 */
exports.plugin = function plugin(schema, schemaOptns) {

  //normalize options
  const schemaOptions = _.merge({}, schemaOptns);

  //default countAndPaginate options
  const defaults = {
    filter: {},
    paginate: { limit: 10, skip: 0, page: 1 },
    populate: [],
    select: {},
    sort: {}
  };


  //ensure search
  if (!schema.statics.search) {
    mongooseSearch(schema, schemaOptions);
  }


  /**
   * @package mongoose-paginate
   * @param {Object} [optns={}]
   * @param {Object|String} [optns.filter] valid mongoose query criteria
   * @param {Object|String} [optns.select] valid mongoose query projections
   * @param {Object|String} [optns.sort] valid mongoose query sort criteria
   * @param {Array} [optns.populate] valid mongoose query population options
   * @param {Number} [optns.paginate.skip=0] valid query skip option
   * @param {Number} [optns.paginate.page=1] 
   * @param {Number} [optns.paginate.limit=10] valid query limit option
   * @param {Function} [done] callback to invoke on success or failure
   * @returns {Promise}
   */
  schema.statics.countAndPaginate = function countAndPaginate(optns, done) {

    //normalize options
    const cb = _.isFunction(optns) ? optns : done;

    let options = _.isObject(optns) ? optns : {};
    options = _.merge({}, defaults, options);
    options = _.merge({}, options.paginate, options);
    delete options.paginate;

    //obtain query criteria
    let filter = (options.query || options.criteria || options.filter);

    //obtain limit
    let limit = (options.limit || options.limit || 10);
    limit = limit > 0 ? limit : 10;

    //obtain skip
    let skip = (options.skip || options.skip || options.offset || 0);
    skip = skip > 0 ? skip : 0;

    //obtain page
    let page = (options.page || options.page);

    let populate = _.compact([].concat(options.populate));
    let select = (options.select || {});
    let sort = (options.sort || {});


    //initialize query
    let query = this.find();

    //try build search query
    const canSearch = (_.isFunction(this.search) && _.isString(filter.q));
    if (canSearch) {
      query = this.search(filter.q);
    }
    delete filter.q;

    //add criteria
    filter = this.where(filter).cast(this);
    query.where(filter);

    if (page && page > 0) {
      skip = (page - 1) * limit;
    }

    if (select) {
      query.select(select);
    }

    if (sort) {
      query.sort(sort);
    }

    if (skip) {
      query.skip(skip);
    }

    if (limit) {
      query.limit(limit);
    }

    if (populate) {
      _.forEach(populate, function (populateOption) {
        query.populate(populateOption);
      });
    }

    async.parallel({

      count: function countQuery(next) {
        this.count(filter).exec(next);
      }.bind(this),

      docs: function paginateQuery(next) {
        query.exec(next);
      }

    }, function (error, results) {

      if (results) {
        results = _.merge({}, {
          docs: results.docs,
          total: results.count,
          limit: limit,
          skip: skip,
          page: page,
          pages: Math.ceil(results.count / limit) || 1
        });
      }

      cb(error, results);

    });

  };

};