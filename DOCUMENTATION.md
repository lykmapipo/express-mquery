#### filter(options, done) 

parse filters from http query object into valid mongoose query conditions




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| options | `object`  | valid query params options to parse for sorting conditions | &nbsp; |
| done | `Function`  | a callback to invoke on success or failure | &nbsp; |




##### Examples

```javascript

GET /customers?query={"name":"Bob"}
GET /customers?filter[name]=Bob
GET /customers?filter[name]={"$regex":"/Bo$/"}
GET /customers?filter[name][$regex]="/Bo$/"
GET /customers?filter[age]={"$gt":12}
GET /customers?filter[age][$gt]=12
```


##### Returns


- `object`  valid mongoose(mongodb) query conditions(or criteria)



#### headers(options, done) 

parse headers to obtain request pre-conditions




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| options | `object`  | valid http headers to parse for pre-conditions | &nbsp; |
| done | `Function`  | a callback to invoke on success or failure | &nbsp; |




##### Examples

```javascript

GET /customers?header['if-modified-since']=Mon Apr 16 2018 11:28:06 GMT+0300 (EAT)

or

curl -i -H 'If-Modified-Since: Wed, 12 Nov 2014 15:44:46 GMT' http://localhost:3000/invoices
```


##### Returns


- `object`  valid parsed pre-conditions headers



#### paginate(options, done) 

parse paginations(i.e limit, offset, skip, page etc) from http query object into valid mongoose pagination conditions




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| options | `object`  | valid query params options to parse for sorting conditions | &nbsp; |
| done | `Function`  | a callback to invoke on success or failure | &nbsp; |




##### Examples

```javascript

GET /customers?skip=10&limit=10
GET /customers?limit=10
GET /customers?page=1
GET /customers?page[number]=1
GET /customers?page[number]=1&page[offset]=10
GET /customers?page[number]=1&page[limit]=10
GET /customers?page[number]=1&page[size]=10
```


##### Returns


- `object`  valid mongoose(mongodb) pagination query conditions(or criteria)



#### select(options, done) 

parse fields from http query object into valid mongoose query select conditions




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| options | `object`  | valid query params options to parse for select fields | &nbsp; |
| done | `Function`  | a callback to invoke on success or failure | &nbsp; |




##### Examples

```javascript

GET /users?select=name
GET /users?select=name,email
GET /users?select=-name
GET /users?select=-name,-email
GET /users?select={"name":1}
GET /users?select={"name":1, "email":1}
GET /users?select={"name":0}
GET /users?select={"name":0, "email": 0}

or

GET /users?fields=name
GET /users?fields=name,email
GET /users?fields=-name
GET /users?fields=-name,-email

or

GET /users?select={"location.name":0, "location.address": 0}
GET /users?fields[location]=-name,-address
```


##### Returns


- `object`  valid mongoose(mongodb) query select conditions(or criteria)



#### populate(options, done) 

parse includes(or population) from http query object into valid mongoose query population conditions




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| options | `object`  | valid query params options to parse for population or includes | &nbsp; |
| done | `Function`  | a callback to invoke on success or failure | &nbsp; |




##### Examples

```javascript

/invoice?populate=customer
/invoice?populate=customer,items
/invoice?populate=customer.name,items.name,items.price
/invoice?populate={"path":"customer", "select":"name,price" }
/invoice?populate={"path":"customer", "select":{"name":1, "price":1} }
/invoice?populate=[{"path":"customer"}, {"path":"items"}]
/invoice?populate=[{"path":"customer", "select":"name"}, {"path":"items", "select":{"name": 1, "price": 1}}]

or

/invoice?includes=customer
/invoice?includes=customer,items
/invoice?includes=customer.name,items.name,items.price
/invoice?includes={"path":"customer", "select":"name,price" }
/invoice?includes={"path":"customer", "select":{"name":1, "price":1} }
/invoice?includes=[{"path":"customer"}, {"path":"items"}]
/invoice?includes=[{"path":"customer", "select":"name"}, {"path":"items", "select":{"name": 1, "price": 1}}]

or

/invoice?includes[customer]=name,number&includes[items]=name,price
/invoice?includes=customer,items&fields[customer]=name,number&fields[items]=name,price
```


##### Returns


- `object`  valid mongoose(mongodb) query population conditions(or criteria)



#### sort(options, done) 

parse sorts from http query object into valid mongoose sorting conditions




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| options | `object`  | valid query params options to parse for sorting conditions | &nbsp; |
| done | `Function`  | a callback to invoke on success or failure | &nbsp; |




##### Examples

```javascript
GET /users?sort=name
GET /users?sort=name,email
GET /users?sort=-name
GET /users?sort=-name,-email
GET /users?sort={"name":1}
GET /users?sort={"name":1, "email":1}
GET /users?sort={"name":0}
GET /users?sort={"name":0, "email": 0}
GET /users?sort={"name":"asc", "email": "desc"}
GET /users?sort={"name":"ascending", "email": "descending"}
```


##### Returns


- `object`  valid mongoose(mongodb) sorting conditions(or criteria)



#### parse(string, done) 

parse specified JSON string into Javascript value or object




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| string | `string`  | valid json string | &nbsp; |
| done | `Function`  | a callback to invoke on success or failure | &nbsp; |




##### Returns


- `object`  constructed JavaScript value or object from JSON key value



#### mquery([optns]) 

parse http query parameters into valid mongoose query options




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| optns | `object`  | valid mquery options | *Optional* |
| optns.limit | `object`  | default limit | *Optional* |
| optns.maxLimit | `object`  | default max limit | *Optional* |




##### Examples

```javascript

import express from 'express';
import mquery from 'express-mquery';


const app = express();
app.use(mquery({limit: 10, maxLimit: 50}));
```


##### Returns


- `Array.&lt;Function&gt;`  valid express middleware stack


*Documentation generated with [doxdox](https://github.com/neogeek/doxdox).*
