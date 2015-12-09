express-mquery
====================

[![Build Status](https://travis-ci.org/lykmapipo/express-mquery.svg?branch=master)](https://travis-ci.org/lykmapipo/express-mquery)

Expose [mongoose](https://github.com/Automattic/mongoose) query API through HTTP request.

## Installation
```js
$ npm install --save express-mquery
```

## Usage
- plugin `express-mquery` to mongoose
```js
var mquery = require('express-mquery');
mongoose.plugin(mquery.plugin, {limit:10});
```

- add `express-mquery` middleware to expess
```js
var mquery = require('express-mquery');
var app = require('express');
...
//somewhere before your routes definition add
app.use(mquery.middleware({limit:10, maxLimit:50}));
...

```

- parse http query string using `express-mquery` to mongoose `Query`
```js
var User = mongoose.model('User');
app.get('/',function(request, response, next){
   User
    .mquery(request);//return valid mongoose query
    .exec(function(error, models){
        if(error){
            next(error);
        }
        else{
            respose.json(models;
        }
    }); 
});
```
or

- parse http query string and paginate documents
```js
User
    .paginate(request, function(error, users, pages, total) {
        if (error) {
            response.status(500).json({
                error: error.message
            });
        } else {
            response.json({
                users: users,
                pages: pages,
                total: total
            });
        }
    });
```

### Usage with request
```js
var request = require('request')

request({
  url: '/customers',
  qs: {
    query: JSON.stringify({
      $or: [{
        name: '~Another'
      }, {
        $and: [{
          name: '~Product'
        }, {
          price: '<=10'
        }]
      }],
      price: 20
    })
  }
});
```

## Querying
All the following parameters `(sort, skip, limit, query, populate, select and distinct)` support the entire mongoose feature set.

>When passing values as objects or arrays in URLs, they must be valid JSON

### Sort
```js
GET /customers?sort=name
GET /customers?sort=-name
GET /customers?sort={"name":1}
GET /customers?sort={"name":0}
```

### Skip
```js
GET /customers?skip=10
```

### Limit
Only overrides `maximum limit option set by the plugin` if the queried limit is lower
```js
GET /customers?limit=10
```

### Query
Supports all operators `($regex, $gt, $gte, $lt, $lte, $ne, etc.) as well as shorthands: ~, >, >=, <, <=, !=`

```js
GET /customers?query={"name":"Bob"}
GET /customers?query={"name":{"$regex":"^(Bob)"}}
GET /customers?query={"name":"~^(Bob)"}
GET /customers?query={"age":{"$gt":12}}
GET /customers?query={"age":">12"}
GET /customers?query={"age":{"$gte":12}}
GET /customers?query={"age":">=12"}
GET /customers?query={"age":{"$lt":12}}
GET /customers?query={"age":"<12"}
GET /customers?query={"age":{"$lte":12}}
GET /customers?query={"age":"<=12"}
GET /customers?query={"age":{"$ne":12}}
GET /customers?query={"age":"!=12"}
```

### Populate
Works with create, read and update operations

```js
GET/POST/PUT /invoices?populate=customer
GET/POST/PUT /invoices?populate={"path":"customer"}
GET/POST/PUT /invoices?populate=[{"path":"customer"},{"path":"products"}]
```

### Select
`_id` is always returned unless explicitely excluded

```js
GET /customers?select=name
GET /customers?select=-name
GET /customers?select={"name":1}
GET /customers?select={"name":0}
```

### Distinct
```js
GET /customers?distinct=name
```

## TODOS
- [ ] support geo queries

## Testing

* Clone this repository

* Install `grunt-cli` global

```sh
$ npm install -g grunt-cli
```

* Install all development dependencies

```sh
$ npm install
```

* Then run test

```sh
$ npm test
```

## Contribute

Fork this repo and push in your ideas. Do not forget to add a bit of test(s) of what value you adding.

## Licence

Copyright (c) 2015 lykmapipo & Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
