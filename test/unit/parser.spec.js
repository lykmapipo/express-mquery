import chai from 'chai';
import * as parser from '../../src';

const { expect } = chai;

describe('parser', () => {
  it('should be an object', () => {
    expect(parser).to.exist;
    expect(parser).to.be.an('object');
  });

  it('should have all required parser', () => {
    expect(parser.filter).to.exist;
    expect(parser.filter).to.be.a('function');

    expect(parser.headers).to.exist;
    expect(parser.headers).to.be.a('function');

    expect(parser.paginate).to.exist;
    expect(parser.paginate).to.be.a('function');

    expect(parser.populate).to.exist;
    expect(parser.populate).to.be.a('function');

    expect(parser.select).to.exist;
    expect(parser.select).to.be.a('function');

    expect(parser.sort).to.exist;
    expect(parser.sort).to.be.a('function');
  });
});
