'use strict';

//dependencies
var path = require('path');
var async = require('async');
var mquery = require(path.join(__dirname, '..', '..'));
var mongoose = require('mongoose');
mongoose.plugin(mquery.plugin);
var Schema = mongoose.Schema;
var util = require('util');

module.exports = function() {
    var ProductSchema = new Schema({
        name: {
            type: String,
            required: true
        },
        department: {
            name: {
                type: String
            },
            code: {
                type: Number
            }
        },
        price: {
            type: Number
        }
    });

    var BaseCustomerSchema = function() {
        Schema.apply(this, arguments);

        this.add({
            account: {
                type: Schema.Types.ObjectId,
                ref: 'Account'
            },
            name: {
                type: String,
                required: true,
                unique: true
            },
            comment: {
                type: String
            },
            address: {
                type: String
            },
            age: {
                type: Number
            },
            favorites: {
                animal: {
                    type: String
                },
                color: {
                    type: String
                },
                purchase: {
                    item: {
                        type: Schema.Types.ObjectId,
                        ref: 'Product'
                    },
                    number: {
                        type: Number
                    }
                }
            },
            purchases: [{
                item: {
                    type: Schema.Types.ObjectId,
                    ref: 'Product'
                },
                number: {
                    type: Number
                }
            }],
            returns: [{
                type: Schema.Types.ObjectId,
                ref: 'Product'
            }],
            creditCard: {
                type: String,
                access: 'protected'
            },
            ssn: {
                type: String,
                access: 'private'
            }
        });
    };

    util.inherits(BaseCustomerSchema, Schema);

    var CustomerSchema = new BaseCustomerSchema({}, {
        toObject: {
            virtuals: true
        },
        toJSON: {
            virtuals: true
        }
    });

    CustomerSchema.virtual('info').get(function() {
        return this.name + ' is awesome';
    });

    var InvoiceSchema = new Schema({
        customer: {
            type: Schema.Types.ObjectId,
            ref: 'Customer'
        },
        amount: {
            type: Number
        },
        receipt: {
            type: String
        },
        products: [{
            type: Schema.Types.ObjectId,
            ref: 'Product'
        }]
    }, {
        toObject: {
            virtuals: true
        },
        toJSON: {
            virtuals: true
        },
        versionKey: '__version'
    });

    var RepeatCustomerSchema = new BaseCustomerSchema({
        account: {
            type: Schema.Types.ObjectId,
            ref: 'Account'
        },
        visits: {
            type: Number
        },
        status: {
            type: String
        },
        job: {
            type: String
        }
    });

    var AccountSchema = new Schema({
        accountNumber: String,
        points: Number
    });

    function initialize() {
        if (!mongoose.models.Customer) {
            mongoose.model('Customer', CustomerSchema);
        }

        if (!mongoose.models.Invoice) {
            mongoose.model('Invoice', InvoiceSchema);
        }

        if (!mongoose.models.Product) {
            mongoose.model('Product', ProductSchema);
        }

        if (!mongoose.models.RepeatCustomer) {
            mongoose.models.Customer.discriminator('RepeatCustomer', RepeatCustomerSchema);
        }

        if (!mongoose.models.Account) {
            mongoose.model('Account', AccountSchema);
        }

    }

    function reset(callback) {
        async.series([
            function(cb) {
                mongoose.models.Customer.remove(cb);
            },
            function(cb) {
                mongoose.models.Invoice.remove(cb);
            },
            function(cb) {
                mongoose.models.Product.remove(cb);
            },
            function(cb) {
                mongoose.models.RepeatCustomer.remove(cb);
            },
            function(cb) {
                mongoose.models.Account.remove(cb);
            }
        ], callback);
    }

    function seed(callback) {
        async.waterfall([
            function(next) {
                mongoose.models.Product.create({
                    name: 'Bobsleigh'
                }, next);
            },
            function(product, next) {
                mongoose.models.Customer.create([{
                    name: 'Bob',
                    age: 12,
                    favorites: {
                        animal: 'Boar',
                        color: 'Black',
                        purchase: {
                            item: product._id,
                            number: 1
                        }
                    }
                }, {
                    name: 'John',
                    age: 24,
                    favorites: {
                        animal: 'Jaguar',
                        color: 'Jade',
                        purchase: {
                            item: product._id,
                            number: 2
                        }
                    }
                }, {
                    name: 'Mike',
                    age: 36,
                    favorites: {
                        animal: 'Medusa',
                        color: 'Maroon',
                        purchase: {
                            item: product._id,
                            number: 3
                        }
                    }
                }], next);
            },
            function(customers, next) {
                mongoose.models.Invoice.create([{
                    customer: customers[0]._id,
                    amount: 100,
                    receipt: 'A'
                }, {
                    customer: customers[1]._id,
                    amount: 200,
                    receipt: 'B'
                }, {
                    customer: customers[2]._id,
                    amount: 300,
                    receipt: 'C'
                }], next);
            }
        ], callback);
    }

    return {
        initialize: initialize,
        reset: reset,
        seed: seed
    };
};