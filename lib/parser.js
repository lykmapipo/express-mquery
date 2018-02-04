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

// const WHITE_LIST = [
//   'populate', 'includes',
//   'select', 'fields',
//   'distinct',
//   'q', 'filters',
//   'sort',
//   'skip', 'limit', 'offset', 
//   'page', 'perPage'
// ];



/**
 * @name reviver
 * @description transform a value of specified key when JSON.parse
 * @return {Object} constructed JavaScript value or object from JSON key value
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */
exports.reviver = function(key, value) {
  return value;
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
exports.parse = function(string, done) {

  //TODO navigate paths and change them to valid mongodb query

  //try to parse json string
  try {
    const json = parse(string);

    //parse query parameters in parallel
    async.parallel({
      select: function parseSelect(next) {
        exports.select(json, next);
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


/**
 * @name select
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
 */

exports.select = function select(options, done) {

  //try parsing projectionsh
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
      projections = _.reduce(projections, function(accumulator, projection) {

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
 * @name distinct
 * @description parse distinct from http query object into valid mongoose query 
 *              distinct conditions
 * @return {Object} valid mongoose(mongodb) query distinct conditions(or criteria)
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-distinct}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */
exports.distinct = function distinct() {
  // body...
};



/**
 * @name filter
 * @description parse filters from http query object into valid mongoose query 
 *              conditions
 * @return {Object} valid mongoose(mongodb) query conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-filtering}
 * @see {@link http://mongoosejs.com/docs/api.html#where_where}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */
exports.filter = function() {
  // body...
  // TODO support JSON api filter plus mongodb query
};



/**
 * @name filter
 * @description parse sorts from http query object into valid mongoose sorting 
 *              conditions
 * @return {Object} valid mongoose(mongodb) sorting conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-sorting}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-sort}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */
exports.sort = function() {
  // body...
};



/**
 * @name paginate
 * @description parse paginations from http query object into valid mongoose 
 *              pagination conditions
 * @return {Object} valid mongoose(mongodb) pagination query conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-pagination}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-skip}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-limit}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */
exports.paginate = function() {
  // body...
  //TODO navigate paths and change them to valid mongodb query
};


/**
 * @name populate
 * @description parse includes(or population) from http query object into 
 *              valid mongoose query population conditions
 * @return {Object} valid mongoose(mongodb) query population conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-includes}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-populate}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */
exports.populate = function() {
  // body...
  // TODO support population on related object fields selection
};