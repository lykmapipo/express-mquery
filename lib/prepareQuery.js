'use strict';

//dependencies
var _ = require('lodash');

module.exports = function( /*options*/ ) {
    function jsonQueryParser(key, value) {
        if (_.isString(value)) {
            if (value[0] === '~') { // parse RegExp
                return new RegExp(value.substr(1), 'i');
            } else if (value[0] === '>') {
                if (value[1] === '=') {
                    return {
                        $gte: value.substr(2)
                    };
                } else {
                    return {
                        $gt: value.substr(1)
                    };
                }
            } else if (value[0] === '<') {
                if (value[1] === '=') {
                    return {
                        $lte: value.substr(2)
                    };
                } else {
                    return {
                        $lt: value.substr(1)
                    };
                }
            } else if (value[0] === '!' && value[1] === '=') {
                return {
                    $ne: value.substr(2)
                };
                /* This feature was disabled because it requiresponse MongoDB 3
                } else if (value[0] === '=') {
                  return { $eq: value.substr(1) }*/
            }
        } else if (_.isArray(value) && key[0] !== '$') {
            return {
                $in: value
            };
        }

        return value;
    }

    function parseQueryOptions(queryOptions) {
        var i;
        var length;
        var populate;
        var select;

        //parse select options
        if (queryOptions.select) {

            if (_.isString(queryOptions.select)) {

                select = queryOptions.select.split(',');

                queryOptions.select =
                    _.reduce(select, function(accumulator, value) {
                        if (value[0] === '-') {
                            accumulator[value.substring(1)] = 0;
                        } else {
                            accumulator[value] = 1;
                        }
                        return accumulator;
                    }, {});
            }

        }

        if (queryOptions.populate) {
            if (_.isString(queryOptions.populate)) {
                populate = queryOptions.populate.split(',');
                queryOptions.populate = [];

                for (i = 0, length = populate.length; i < length; i++) {
                    queryOptions.populate.push({
                        path: populate[i]
                    });

                    for (var key in queryOptions.select) {
                        if (key.indexOf(populate[i] + '.') === 0) {
                            if (queryOptions.populate[i].select) {
                                queryOptions.populate[i].select += ' ';
                            } else {
                                queryOptions.populate[i].select = '';
                            }

                            if (queryOptions.select[key] === 0) {
                                queryOptions.populate[i].select += '-';
                            }

                            queryOptions.populate[i].select += key.substring(populate[i].length + 1);
                            delete queryOptions.select[key];
                        }
                    }

                    // If other specific fields are selected, add the populated field
                    if (queryOptions.select) {
                        if (Object.keys(queryOptions.select).length > 0 && !queryOptions.select[populate[i]]) {
                            queryOptions.select[populate[i]] = 1;
                        }

                        if (Object.keys(queryOptions.select).length === 0) {
                            delete queryOptions.select;
                        }
                    }
                }
            } else if (!_.isArray(queryOptions.populate)) {
                queryOptions.populate = [queryOptions.populate];
            }
        }

        return queryOptions;
    }

    return function(request, response, next) {
        var whitelist = [
            'distinct', 'limit', 'populate',
            'query', 'select', 'skip', 'sort'
        ];

        request.mquery = {};

        for (var key in request.query) {

            //continue if query key is not whitelisted
            if (whitelist.indexOf(key) === -1) {
                continue;
            }

            //parse query to build where
            if (key === 'query') {
                try {
                    request.mquery[key] = JSON.parse(request.query[key], jsonQueryParser);
                } catch (e) {
                    var err = new Error('%s must be a valid JSON string', key);
                    err.description = 'invalid_json';
                    err.statusCode = 400;
                    return next(err);
                }
            }

            //parse populate, select , sort
            else if (key === 'populate' || key === 'select' || key === 'sort') {
                try {
                    request.mquery[key] = JSON.parse(request.query[key]);
                } catch (e) {
                    request.mquery[key] = request.query[key];
                }
            }

            //parse any key value
            else {
                request.mquery[key] = request.query[key];
            }
        }

        request.mquery = parseQueryOptions(request.mquery);

        next();
    };
};