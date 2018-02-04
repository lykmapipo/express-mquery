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


### A partial string match

```
https://api.example.com/users?username=*steve*
```

### A range of values

```
https://api.example.com/users?age=18...25
```

### Greater than + Lesser than (or equal to)

We use familiar operators - `>`, `<`, `>=`, `<=` (shown URI-encoded)

```
https://api.example.com/users?age=%3E18
https://api.example.com/users?age=%3C25
https://api.example.com/users?age=%3E%3D18
https://api.example.com/users?age=%3C%3D25
```

### Sorting by a value

Default is ascending, negating with a `-` sets to descending.

```
https://api.example.com/users?order=createdAt
https://api.example.com/users?order=-createdAt
```

### Amount of results

A `limit=0` sets no limit.

```
https://api.example.com/users?limit=5
https://api.example.com/users?limit=0
```

### Pagination

```
https://api.example.com/users?page=1&perPage=20
```

### Negation

It should be possible to search for the opposite of a query by adding the `!` operator to it to negate it like so:

```
https://api.example.com/users?status=!deleted