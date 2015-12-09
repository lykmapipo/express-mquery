'use strict';

//dependencies


module.exports = function(options) {
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

        // declares or executes a distict() operation
        if (queryOptions.distinct) {
            query.distinct(queryOptions.distinct);
        }

        // sets the lean option
        if (!!queryOptions.lean) {
            query.lean(true);
        }

        // specifies the maximum number of documents the query will return
        if (options.limit && (!queryOptions.limit || queryOptions.limit === '0' || queryOptions.limit > options.limit)) {
            queryOptions.limit = options.limit;
        }

        if (queryOptions.limit && query.op !== 'count' && !queryOptions.distinct) {
            query.limit(queryOptions.limit);
        }

        // specifies paths which should be populated with other documents
        if (queryOptions.populate) {
            query.populate(queryOptions.populate);
        }

        // specifies which document fields to include or exclude 
        // (also known as the query "projection")
        if (queryOptions.select) {
            query.select(queryOptions.select);
        }

        // specifies the number of documents to skip
        if (queryOptions.skip && !queryOptions.distinct) {
            query.skip(queryOptions.skip);
        }

        // sets the sort order
        if (queryOptions.sort) {
            query.sort(queryOptions.sort);
        }

        // Specifies a path or query condition for use
        if (queryOptions.query) {
            query.where(queryOptions.query);
        }

        return query;
    }

    return buildQuery;
};