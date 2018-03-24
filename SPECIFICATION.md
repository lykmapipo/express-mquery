# Query Parameters Specification

Here we work at merge common recommendation from

- [MongoDB Query](https://docs.mongodb.com/manual/reference/operator/query/)
- [JSON API Recommendations](http://jsonapi.org/recommendations/)
- [JSONAPI Resources Querystring Examples](https://github.com/cerebris/jsonapi-resources/wiki/JSONAPI::Resources-Querystring-Examples)
- [JSON API Examples](http://jsonapi.org/examples/)
- [JSON API propose filtering strategy](http://discuss.jsonapi.org/t/share-propose-a-filtering-strategy/257)
- [wordpress rest-api](https://developer.wordpress.org/rest-api/)
- [apigee](https://docs-apis.apigee.io/files/Web-design-the-missing-link-ebook-2016-11.pdf)
- [JSON API Example](http://jsonapi.org/examples/)
- etc

to have a consistent approach to parse query parameters and transalate them
to actual [query builder](http://mongoosejs.com/docs/api.html#Query) options.

## Projection - Select Specific Fields
Parse projection(`select or fields`) from http query parameters and construct 
[select](http://mongoosejs.com/docs/api.html#query_Query-select) query options 
to satisfy [mongodb projection specification](https://docs.mongodb.com/manual/tutorial/project-fields-from-query-results/)

Example
```
 /users?select=name
 /users?select=name,email
 /users?select=-name
 /users?select=-name,-email
 /users?select={"name":1}
 /users?select={"name":1, "email":1}
 /users?select={"name":0}
 /users?select={"name":0, "email": 0}
 /users?fields=name
 /users?fields=name,email
 /users?fields=-name
 /users?fields=-name,-email
```

*Note:*
- A projection must be either inclusive or exclusive. In other words, you must either list the fields to include (which excludes all others), or list the fields to exclude (which implies all other fields are included). [See](https://docs.mongodb.com/manual/tutorial/project-fields-from-query-results/)
- For projection specified using object ,it must be a valid json



## Sorting - Result Ordering
Parse orders(`sort`) from http query parameters and construct 
[sort](http://mongoosejs.com/docs/api.html#query_Query-sort) query options.

Example
```
 /users?sort=name
 /users?sort=name,email
 /users?sort=-name
 /users?sort=-name,-email
 /users?sort={"name":1}
 /users?sort={"name":1, "email":1}
 /users?sort={"name":0}
 /users?sort={"name":0, "email": 0}
 /users?sort={"name":'asc', "email": 'desc'}
 /users?sort={"name":'ascending', "email": 'descending'}
```

## Populate - Load Relations(or Related Resources)
Parse `populate` or `includes` from http query parameters and construct 
[populate](http://mongoosejs.com/docs/api.html#query_Query-populate) query options.

Example
```
/invoices?populate=customer
/invoices?populate=customer,items
/invoices?populate=customer.name,items.name,items.price
/invoices?populate=customer.name,-items.price
/invoices?populate={"path":"customer", "select":"name,price" }
/invoices?populate={"path":"customer", "select":{"name":1, "price":1} }
/invoices?populate=[{"path":"customer"}, {"path":"items"}]
/invoices?populate=[{"path":"customer", "select":"name"}, {"path":"items", "select":{"name": 1, "price": 1}}]

or

/invoices?include=customer
/invoices?include=customer,items
/invoices?include=customer.name,items.name,items.price
/invoices?include=customer.name,-items.price
/invoices?include={"path":"customer", "select":"name,price" }
/invoices?include={"path":"customer", "select":{"name":1, "price":1} }
/invoices?include=[{"path":"customer"}, {"path":"items"}]
/invoices?include=[{"path":"customer", "select":"name"}, {"path":"items", "select":{"name": 1, "price": 1}}]
```

### Filtering
Supports all [mongodb operators](https://docs.mongodb.com/manual/reference/operator/query/) `($regex, $gt, $gte, $lt, $lte, $ne, etc.)`

```js
GET /customers?query={"name":"Bob"}
GET /customers?query={"name":{"$regex":"/Bo$/"}}
GET /customers?query={"age":{"$gt":12}}
GET /customers?query={"age":{"$gte":12}}
GET /customers?query={"age":{"$lt":12}}
GET /customers?query={"age":{"$lte":12}}
GET /customers?query={"age":{"$ne":12}}

or

GET /customers?filter[name]=Bob
GET /customers?filter[name]={"$regex":"/Bo$/"}
GET /customers?filter[age]={"$gt":12}
GET /customers?filter[age]={"$gte":12}
GET /customers?filter[age]={"$lt":12}
GET /customers?filter[age]={"$lte":12}
GET /customers?filter[age]={"$ne":12}
```

## Pagination

### Offset Pagination
**Limiting Returned Resources:**
 - **`/users?page[limit]={resource_count}`**
 - `{resource_count}` = number of resources you want returned
 - e.g. `/users?page[limit]=5` will return the first 5 `user` resources

**Offsetting Returned Resources:**
 - **`/users?page[offset]={resource_offset}`**
 - `{resource_offset}` = the number of records to offset by prior to returning resources
 - e.g. `/users?page[offset]=10` will skip the first 10 `user` resources in the collection

**Combining Limiting/Offsetting:**
 - **`/users?page[limit]={resource_count}&page[offset]={resource_offset}`**
 - e.g. `/users?page[limit]=5&page[offset]=10` will skip `user` resources 0-10 and return resources 11-15

### Paged Pagination
**Paging Returned Resources:**
 - **`/users?page[number]={page_number}`**
 - `{page_number}` = the page number of the resources to be returned (this is "one-based", i.e. the first page is `1`, not `0`)
 - e.g. `/users?page[number]=7` will skip the first 7 *pages* of `user` resources in the collection, and return the 8th page

**Setting Page Size:**
 - **`/users?page[size]={page_size}`**
 - `{page_size}` = the number of resources to be returned per page
 - e.g. `/users?page[size]=25` will return 25 `user` resources on a single page

**Combining Paging/Page Sizing:**
 - **`/users?page[size]={page_size}&page[number]={page_number}`**
 - e.g. `/users?page[size]=25&page[number]=5` will skip `user` resources 0-100 and return resources 101-125
