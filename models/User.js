'use strict';

//dependencies
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var UserSchema = new Schema({
    username: {
        type: String
    },
    email: {
        type: String
    }
});

//export model
module.exports = mongoose.model('User', UserSchema);