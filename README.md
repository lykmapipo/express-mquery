express-mquery
====================

[![Build Status](https://travis-ci.org/lykmapipo/express-mquery.svg?branch=master)](https://travis-ci.org/lykmapipo/express-mquery)

Expose [mongoose](https://github.com/Automattic/mongoose) query API through HTTP request.

Most of codes extracted from [express-restify-mongoose](https://github.com/florianholzapfel/express-restify-mongoose).

## Installation
```js
$ npm install --save express-mquery
```

## Usage
```js
var mquery = require('express-mquery');
var app = require('express');
...
//somwhere before your router definition add
app.use(mquery.middleware());

...

//somewhere in your controller/route use mquery object
app.get('/',function(request, response, next){
   Model
    .find(query, function(error, models){
        if(error){
            next(error);
        }
        else{
            respose.json(models;
        }
    }); 
});

//parse mquery using plugin
var UserSchema = new Schema({
    ...
});
UserSchema.plugin({limit:20});
...

//then exec query
var User = mongoose.model('User');
app.get('/',function(request, response, next){
   User
    .mquery(request);
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

## TODO
- [ ] Use express-paginate
- [ ] allow pagination
- [ ] pass max limit options on the plugin
- [ ] testing geo queries

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
