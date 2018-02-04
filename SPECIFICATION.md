# Query Parameters Specification

Here we work at merge common recommendation from

- [JSON API Recommendaions](http://jsonapi.org/recommendations/)
- [MongoDB Query](https://docs.mongodb.com/manual/reference/operator/query/)
- etc

to have a consistent approach to parse query parameters and transalate them
to actual [query builder](http://mongoosejs.com/docs/api.html#Query) options.

## Projection - Select Specific Fields
Parse projection(`select or fields`) from http query parameters and construct 
[select](http://mongoosejs.com/docs/api.html#query_Query-select) query options.

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