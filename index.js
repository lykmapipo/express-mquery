'use strict';


//dependencies
const path = require('path');
const _ = require('lodash');
const parser = require(path.join(__dirname, 'lib', 'parser'));

/**
 * @name mquery
 * @function mquery
 * @description parse http query parameters into valid mongoose query options
 * @param  {Object} [optns] valid mquery options
 * @param  {Object} [optns.limit] default limit
 * @param  {Object} [optns.maxLimit] default max limit
 * @return {Function[]} valid express middleware stack
 * @example
 * 
 * const expess = require('express');
 * const mquery = require('express-mquery');
 *
 * 
 * const app = express();
 * app.use(mquery({limit: 10, maxLimit: 50}));
 * 
 */
module.exports = exports = function mquery(optns) {

  //normalize options
  const options = _.merge({}, {
    limit: 10,
    maxLimit: 50
  }, optns);

  //pack & return middlewares stack
  return [
    function prepareMquery(request, response, next) {

      const query =
        _.merge({}, options, { headers: request.headers }, request.query);

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