import chai from 'chai';
import {
  filter,
  headers,
  paginate,
  populate,
  select,
  sort,
} from '../../src/internals';

const { expect } = chai;

describe('parser', () => {
  it('should have all required parser', () => {
    expect(filter).to.exist;
    expect(filter).to.be.a('function');

    expect(headers).to.exist;
    expect(headers).to.be.a('function');

    expect(paginate).to.exist;
    expect(paginate).to.be.a('function');

    expect(populate).to.exist;
    expect(populate).to.be.a('function');

    expect(select).to.exist;
    expect(select).to.be.a('function');

    expect(sort).to.exist;
    expect(sort).to.be.a('function');
  });
});
