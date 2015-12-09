'use strict';

//code borrowed from https://github.com/edwardhotchkiss/mongoose-paginate
//and customized to fit express-mquery requirements

// dependencies
var _ = require('lodash');
var async = require('async');
var promise = require('bluebird');

/**
 * Return a promise with results
 *
 * @method handlePromise
 * @param {Object} query - mongoose query object
 * @param {Object} q - query
 * @param {Object} model - mongoose model
 * @param {Number} resultsPerPage
 * @returns {Promise}
 */

function handlePromise(query, q, model, resultsPerPage) {
    return promise.all([
        query.exec(),
        model.count(q).exec()
    ]).spread(function(results, count) {
        return [
            results,
            Math.ceil(count / resultsPerPage) || 1,
            count
        ];
    });
}

/**
 * Call callback function passed with results
 *
 * @method handleCallback
 * @param {Object} query - mongoose query object
 * @param {Object} q - query
 * @param {Object} model - mongoose model
 * @param {Number} resultsPerPage
 * @param {Function} callback
 * @returns {void}
 */

function handleCallback(query, q, model, resultsPerPage, callback) {
    return async.parallel({
        results: function(callback) {
            query.exec(callback);
        },
        count: function(callback) {
            model.count(q, function(err, count) {
                callback(err, count);
            });
        }
    }, function(error, data) {
        if (error) {
            return callback(error);
        }
        callback(null, data.results, Math.ceil(data.count / resultsPerPage) || 1, data.count);
    });
}


/*
 * @method paginate
 * @param {Object} query and pagination options
 * @param {Function} [callback]
 * Extend Mongoose Models to paginate queries
 */

function paginate(q, callback) {
    /*jshint validthis:true */
    var model = this;

    var select = q.select || null;
    var sort = q.sort || null;
    var populate = q.populate || null;
    var distinct = q.distinct || null;

    //prepare limit and skip
    var pageNumber = q.page || 1;
    var resultsPerPage = q.limit || 10;
    var skipFrom = (pageNumber * resultsPerPage) - resultsPerPage;

    //obtain query object
    q = _.omit(q, ['select', 'sort', 'populate', 'skip', 'limit', 'distinct', 'page']);
    q = q.query ? q.query : q;

    //prepare query
    var query = distinct ? model.distinct(distinct) : model.find(q);

    //set select 
    if (select !== null) {
        query = query.select(select);
    }

    //set skip and limit
    if (distinct === null) {
        query = query.skip(skipFrom).limit(resultsPerPage);
    }

    //set sorting
    if (sort !== null) {
        query.sort(sort);
    }

    //populate paths
    if (populate) {
        if (Array.isArray(populate)) {
            populate.forEach(function(field) {
                query = query.populate(field);
            });
        } else {
            query = query.populate(populate);
        }
    }

    //query and prepare results
    if (typeof callback === 'function') {
        return handleCallback(query, q, model, resultsPerPage, callback);
    } else {
        return handlePromise(query, q, model, resultsPerPage);
    }
}

//export mongoose-paginate
module.exports = exports = paginate;