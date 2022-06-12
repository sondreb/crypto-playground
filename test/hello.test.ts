import assert from 'assert';
import { world } from '../src/hello';

describe('hello', () => {
  it('should return a hello world', () => {
    const actual: string = world('Web5');
    const expected: string = 'Hello world, Web5!';

    assert.equal(actual, expected);
  });
});
