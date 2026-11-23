'use strict';

const url = require('url');

// Since Node.js 18 the legacy `url.parse()` throws `ERR_INVALID_URL` for
// malformed values such as an unterminated IPv6 literal (`[::1`), while the
// older Node.js versions the test suite runs on parse them leniently. Make
// `url.parse()` throw for the given inputs, like recent Node.js versions do,
// and call through to the real implementation for everything else.
// Returns the jest spy; call `mockRestore()` on it when done.
function mockThrowingUrlParse(malformedInputs) {
  const originalParse = url.parse;

  return jest.spyOn(url, 'parse').mockImplementation(function parse(...args) {
    const input = args[0];

    if (typeof input === 'string' && malformedInputs.indexOf(input) !== -1) {
      const error = new TypeError(`Invalid URL: ${input}`);

      error.code = 'ERR_INVALID_URL';

      throw error;
    }

    return originalParse.apply(this, args);
  });
}

module.exports = mockThrowingUrlParse;
