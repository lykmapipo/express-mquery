'use strict';

//set environment to test
process.env.NODE_ENV = 'test';

//dependencies
var async = require('async');
var mongoose = require('mongoose');


/**
 * @description wipe all mongoose model data and drop all indexes
 */
function wipe(done) {
    var cleanups = mongoose.modelNames()
        .map(function(modelName) {
            //grab mongoose model
            return mongoose.model(modelName);
        })
        .map(function(Model) {
            return async.series.bind(null, [
                //clean up all model data
                Model.remove.bind(Model),
                //drop all indexes
                Model.collection.dropAllIndexes.bind(Model.collection)
            ]);
        });

    //run all clean ups parallel
    async.parallel(cleanups, function(error) {
        if (error && error.message !== 'ns not found') {
            done(error);
        } else {
            //drop database
            mongoose.connection.db.dropDatabase();

            done(null);
        }
    });
}

//establish mongoose connection
before(function() {
    mongoose.connect('mongodb://localhost/express-mquery');
});

//restore initial environment
after(function(done) {
    wipe(done);
});