'use strict';



/**
 * @module parser
 * @name parser
 * @description http query params parser to valid mongoose query methods and 
 *              options
 * @see  {@link https://en.wikipedia.org/wiki/Customer}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */



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



/**
 * @name select
 * @description parse fields from http query object into valid mongoose query 
 *              select conditions
 * @return {Object} valid mongoose(mongodb) query select conditions(or criteria)
 * @see  {@link http://jsonapi.org/format/#fetching-sparse-fieldsets}
 * @see {@link http://mongoosejs.com/docs/api.html#query_Query-select}
 * @author lally elias <lallyelias87@mail.com>
 * @since 0.2.2
 * @version 0.1.0
 * @public
 */
exports.select = function() {
  // body...
  // TODO support population on related object fields selection
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
};