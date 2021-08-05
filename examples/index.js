import _ from 'lodash';
import express from 'express';
import { mquery } from '../src';

// prepare express app
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '2mb' }));
app.use(mquery());

// handle requests
app.get('/', (request, response) => {
  const options = _.merge({}, request.mquery);
  response.json(options);
});

const PORT = 3000;
app.listen(PORT, (error) => {
  if (error) {
    throw error;
  } else {
    // eslint-disable-next-line no-console
    console.log(`visit http://0.0.0.0:${PORT}`);
  }
});
