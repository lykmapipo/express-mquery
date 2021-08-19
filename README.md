express-mquery
====================

[![Build Status](https://travis-ci.com/lykmapipo/express-mquery.svg?branch=master)](https://travis-ci.com/lykmapipo/express-mquery)
[![Dependencies Status](https://david-dm.org/lykmapipo/express-mquery.svg)](https://david-dm.org/lykmapipo/express-mquery)
[![Coverage Status](https://coveralls.io/repos/github/lykmapipo/express-mquery/badge.svg?branch=master)](https://coveralls.io/github/lykmapipo/express-mquery?branch=master)
[![GitHub License](https://img.shields.io/github/license/lykmapipo/express-mquery)](https://github.com/lykmapipo/express-mquery/blob/master/LICENSE)

[![Commitizen Friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![Code Style](https://badgen.net/badge/code%20style/airbnb/ff5a5f?icon=airbnb)](https://github.com/airbnb/javascript)
[![npm version](https://img.shields.io/npm/v/express-mquery)](https://www.npmjs.com/package/express-mquery)

Expose [mongoose](https://github.com/Automattic/mongoose) query API through HTTP request with partial support of [json-api](http://jsonapi.org/): 
 - [sparse-fieldsets](http://jsonapi.org/format/#fetching-sparse-fieldsets)
 - [sorting](http://jsonapi.org/format/#fetching-sorting)
 - [pagination](http://jsonapi.org/format/#fetching-pagination)
 - [filtering](http://jsonapi.org/format/#fetching-filtering)
 - [includes](http://jsonapi.org/format/#fetching-includes)

*Note: Checkout the current [specification](https://github.com/lykmapipo/express-mquery/blob/master/SPECIFICATION.md) for more information.*

## Installation
```js
$ npm install --save express-mquery
```

## Usage
```js
import expess from 'express';
import mquery from 'express-mquery';

const app = express();
app.use(mquery({ limit: 10, maxLimit: 50 }));

...

app.get('/users', (request, response, next) => {
  
  // obtain request.mquery
  console.log(request.mquery);

});
```

## Structure
Once parse, `express-mquery` will extend `http request` with `mquery` field

Example:

```js
GET /invoices?fields=number,amount&filter[name]=Bob
&filter[amount][$gte]=1200&include=customer,items
&fields[customer]=name,number&fields[items]=name,price
&page[number]=1&page[size]=10&sort[number]=1&sort[amount]=-1
```

Will be parsed into:
```js
{
  filter: { name: "Bob", amount: { $gte: 1200 } },
  paginate: { limit: 10, skip: 0, page: 1 },
  populate: [
  	{ path: "customer", select: { name: 1, number: 1 } },
  	{ path: "items", select: { name: 1, price: 1 } }
  ],
  select: { number: 1, amount: 1 },
  sort: { number: 1, amount: -1 }
}
```

Where:
- `filter` : Is valid `mongoose` criteria and can be passed to `find()`
- `paginate` : Contains paging details that can be passed to `limit()`, `skip()`
- `populate` : Is valid `mongoose` populate option and can be passed to `populate()`
- `select` : Is valid `mongoose` project options and can be passed to `select()`
- `sort` : Is valid `mongoose` sort options and can be passed to `sort()`


## Querying

>When passing values as objects or arrays in URLs, they must be valid JSON

### Sort
```js
GET /customers?sort=name
GET /customers?sort=-name
GET /customers?sort={"name":1}
GET /customers?sort={"name":1, "email":-1}

or

GET /customers?sort=name
GET /customers?sort=-name
GET /customers?sort[name]=1&sort[email]=-1
```

### Page
```js
GET /customers?page=1
GET /customers?page=1&limit=10
GET /customers?page[number]=1&page[size]=10
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

### Query or Filters
Supports all [mongodb operators](https://docs.mongodb.com/manual/reference/operator/query/) `($regex, $gt, $gte, $lt, $lte, $ne, etc.)`

```js
GET /customers?query={"name":"Bob"}
GET /customers?query={"name":{"$regex":"/Bo$/"}}
GET /customers?query={"age":{"$gt":12}}
GET /customers?query={"age":{"$gte":12}}

or

GET /customers?filter[name]=Bob
GET /customers?filter[name][$regex]="/Bo$/"
GET /customers?filter[age][$gt]=12
GET /customers?filter[age][$gte]=12
```

### Populate or Include
Works with create, read and update operations

```js
GET /invoices?populate=customer
GET /invoices?populate={"path":"customer"}
GET /invoices?populate=[{"path":"customer"},{"path":"products"}]

or

GET /invoices?include=customer
GET /invoices?include[customer]=name,number&includes[items]=name,price
GET /invoices?include=customer,items&fields[customer]=name,number&fields[items]=name,price
```

### Select or Fields
`_id` is always returned unless explicitely excluded

```js
GET /customers?select=name
GET /customers?select=-name
GET /customers?select={"name":1}
GET /customers?select={"name":0}

or

GET /customers?fields=name
GET /customers?fields=-name
GET /customers?fields=name,email
GET /invoices?include=customer&fields[customer]=name
```

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

Copyright (c) lykmapipo & Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
