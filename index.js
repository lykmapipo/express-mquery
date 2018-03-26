'use strict';

//dependencies
const path = require('path');
const _ = require('lodash');
const buildQuery = require(path.join(__dirname, 'lib', 'buildQuery'));
const parser = require(path.join(__dirname, 'lib', 'parser'));
const mongoosePaginate = require(path.join(__dirname, 'lib', 'mongoosePaginate'));


//export express middleware
exports.middleware = function (optns) {
  const options = optns || {
    limit: 10,
    maxLimit: 50
  };

  //return middleware stack
  return [function (request, response, next) {
    const query = _.merge({}, options, request.query);
    parser
      .parse(query, function (error, mquery) {
        if (error) {
          next(error);
        } else {
          request.mquery = mquery;
          next();
        }
      });
  }];

};

//export mongoose plugin
exports.plugin = function (schema, options) {
  //normalize options
  options = options || {};

  /**
   * @description build mongoose query from request.mquery object
   * @param  {Request} request valid express HTTP request
   * @return {Query}         valid mongoose query instance
   */
  schema.statics.mquery = function (request) {
    const query = options.query || this.find();
    if (request.mquery) {
      return buildQuery(options)(query, request.mquery);
    } else {
      return query;
    }
  };


  /**
   * @description build mongoose paginate query from request.mquery object
   * @param  {Request|Object}   request valid express HTTP request or valid
   *                                    mongodb query object
   * @param  {Function} [done]   callback to invoke on success or error, if not
   *                             provided a promise will be returned
   */
  schema.statics.paginate = function (request, done) {

    //obtain mongoose query object
    let query = request.mquery ? request.mquery : request;

    //extend mquery if exist
    if (request.mquery) {
      //pick page and limit from request query params
      const pageAndLimit = _.pick(request.query, ['page', 'limit']);

      //extend query with page and limit request params
      query =
        _.merge({}, query, pageAndLimit);
    }

    //execute query
    if (_.isFunction(done)) {
      return mongoosePaginate.call(this, query, done);
    } else {
      return mongoosePaginate.call(this, query);
    }

  };

};