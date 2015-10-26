'use strict';

//set environment to test
process.env.NODE_ENV = 'test';

//dependencies
var faker = require('faker');
var async = require('async');
var mongoose = require('mongoose');

//additional faker helpers
faker.lorem.word = function() {
    var words = faker.lorem.words(20);
    var r1 = faker.random.number(15);
    var r2 = faker.random.number(15);
    return words[r1] + words[r2];
};


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