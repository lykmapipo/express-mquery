'use strict';

//dependencies
var path = require('path');
var buildQuery = require(path.join(__dirname, 'lib', 'buildQuery'));
var prepareQuery = require(path.join(__dirname, 'lib', 'prepareQuery'));

//export express middleware
exports.middleware = prepareQuery;

//export mongoose plugin
exports.plugin = function(schema, options) {
    options = options || {};

    /**
     * @description build mongoose query from request.mquery object
     * @param  {Request} request valid express HTTP request
     * @return {Query}         valid mongoose query instance
     */
    schema.statics.mquery = function(request) {
        var query = options.query || this.find();
        if (request.mquery) {
            return buildQuery(options)(query, request.mquery);
        } else {
            return query;
        }
    };
};