import { merge } from 'lodash';
import express from 'express';
import mquery from '../src';

const PORT = 3000;

// prepare express app
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '2mb' }));
app.use(mquery());

// handle requests
app.get('/', (request, response) => {
  const options = merge({}, request.mquery);
  response.json(options);
});

// run express app
app.listen(PORT, (error) => {
  if (error) {
    throw error;
  } else {
    console.log(`visit http://0.0.0.0:${PORT}`);
  }
});
