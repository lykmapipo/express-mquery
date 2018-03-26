'use strict';

//dependencies
const _ = require('lodash');


module.exports = function (options) {
  /**
   * @description build mongoose query from query option object
   * @param  {Query} query        valid mongoose query object
   * @param  {Object} queryOptions query object
   * @return {Query}              valid mongoose query
   */
  function buildQuery(query, queryOptions) {
    if (!queryOptions) {
      return query;
    }

    queryOptions = _.merge({}, queryOptions);

    // declares or executes a distict() operation
    if (queryOptions.distinct) {
      query.distinct(queryOptions.distinct);
    }

    // sets the lean option
    if (!!queryOptions.lean) {
      query.lean(true);
    }

    // specifies the maximum number of documents the query will return
    if (options.limit && (!queryOptions.paginate.limit || queryOptions.paginate
        .limit === '0' || queryOptions.paginate.limit > options.limit)) {
      queryOptions.paginate.limit = options.limit;
    }

    if (queryOptions.paginate.limit && query.op !== 'count' && !queryOptions.distinct) {
      query.limit(queryOptions.paginate.limit);
    }

    // specifies paths which should be populated with other documents
    if (queryOptions.populate) {
      _.forEach(queryOptions.populate, function (populate) {
        query.populate(populate);
      });
    }

    // specifies which document fields to include or exclude 
    // (also known as the query "projection")
    if (queryOptions.select) {
      query.select(queryOptions.select);
    }

    // specifies the number of documents to skip
    if (queryOptions.paginate.skip && !queryOptions.distinct) {
      query.skip(queryOptions.paginate.skip);
    }

    // sets the sort order
    if (queryOptions.sort) {
      query.sort(queryOptions.sort);
    }

    // Specifies a path or query condition for use
    if (queryOptions.filter) {
      query.where(queryOptions.filter);
    }

    return query;
  }

  return buildQuery;
};