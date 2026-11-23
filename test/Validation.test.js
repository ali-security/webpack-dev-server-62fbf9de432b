'use strict';

/* eslint-disable
  no-shadow,
  array-bracket-spacing
*/

const webpack = require('webpack');
const Server = require('../lib/Server');
const schema = require('../lib/options.json');
const config = require('./fixtures/simple-config/webpack.config');
const mockThrowingUrlParse = require('./helpers/throwing-url-parse');

const messages = schema.errorMessage.properties;

describe('Validation', () => {
  let compiler;
  let server;

  beforeAll(() => {
    compiler = webpack(config);
  });

  describe('validation', () => {
    afterEach((done) => {
      // `server` is undefined if a test is good
      if (server) {
        server.close(() => {
          done();
        });
      } else {
        done();
      }
    });

    const tests = [
      {
        name: 'invalid `hot` configuration',
        config: { hot: 'false' },
        message: `options.hot ${messages.hot}`,
      },
      {
        name: 'invalid `logLevel` configuration',
        config: { logLevel: 1 },
        message: `options.logLevel ${messages.logLevel.split('\n\n')[0]}`,
      },
      {
        name: 'invalid `writeToDisk` configuration',
        config: { writeToDisk: 1 },
        message: `options.writeToDisk ${messages.writeToDisk}`,
      },
      {
        name: 'invalid `overlay` configuration',
        config: { overlay: { errors: 1 } },
        message: `options.overlay ${messages.overlay}`,
      },
      {
        name: 'invalid `contentBase` configuration',
        config: { contentBase: [0] },
        message: `options.contentBase ${messages.contentBase}`,
      },
      {
        name: 'no additional properties',
        config: { additional: true },
        message: 'options should NOT have additional properties',
      },
    ];

    tests.forEach((test) => {
      it(`should fail validation for ${test.name}`, () => {
        try {
          server = new Server(compiler, test.config);
        } catch (err) {
          if (err.name !== 'ValidationError') {
            throw err;
          }

          const [title, message] = err.message.split('\n\n');

          expect(title).toEqual('webpack Dev Server Invalid Options');
          expect(message.trim()).toEqual(test.message);

          return;
        }

        throw new Error("Validation didn't fail");
      });
    });
  });

  describe('filename', () => {
    afterEach((done) => {
      server.close(() => {
        done();
      });
    });

    it('should allow filename to be a function', () => {
      try {
        server = new Server(compiler, { filename: () => {} });
      } catch (err) {
        if (err === 'ValidationError') {
          throw err;
        }

        throw new Error("Validation failed and it shouldn't");
      }
    });
  });

  describe('checkHost', () => {
    afterEach((done) => {
      server.close(() => {
        done();
      });
    });

    it('should always allow any host if options.disableHostCheck is set', () => {
      const options = {
        public: 'test.host:80',
        disableHostCheck: true,
      };

      const headers = {
        host: 'bad.host',
      };

      server = new Server(compiler, options);

      if (!server.checkHost(headers)) {
        throw new Error("Validation didn't fail");
      }
    });

    it('should allow any valid options.public when host is localhost', () => {
      const options = {
        public: 'test.host:80',
      };
      const headers = {
        host: 'localhost',
      };
      server = new Server(compiler, options);
      if (!server.checkHost(headers)) {
        throw new Error("Validation didn't fail");
      }
    });

    it('should allow any valid options.public when host is 127.0.0.1', () => {
      const options = {
        public: 'test.host:80',
      };

      const headers = {
        host: '127.0.0.1',
      };

      server = new Server(compiler, options);

      if (!server.checkHost(headers)) {
        throw new Error("Validation didn't fail");
      }
    });

    it('should allow access for every requests using an IP', () => {
      const options = {};

      const tests = [
        '192.168.1.123',
        '192.168.1.2:8080',
        '[::1]',
        '[::1]:8080',
        '[ad42::1de2:54c2:c2fa:1234]',
        '[ad42::1de2:54c2:c2fa:1234]:8080',
      ];

      server = new Server(compiler, options);

      tests.forEach((test) => {
        const headers = { host: test };

        if (!server.checkHost(headers)) {
          throw new Error("Validation didn't pass");
        }
      });
    });

    it("should not allow hostnames that don't match options.public", () => {
      const options = {
        public: 'test.host:80',
      };

      const headers = {
        host: 'test.hostname:80',
      };

      server = new Server(compiler, options);

      if (server.checkHost(headers)) {
        throw new Error("Validation didn't fail");
      }
    });

    it('should allow urls with scheme for checking origin', () => {
      const options = {
        public: 'test.host:80',
      };
      const headers = {
        origin: 'https://test.host',
      };
      server = new Server(compiler, options);
      if (!server.checkOrigin(headers)) {
        throw new Error("Validation didn't fail");
      }
    });

    it('should not allow an IP address in the origin header when it differs from the host header', () => {
      const options = {};

      const tests = [
        { origin: 'http://192.168.1.1', host: 'localhost:8080' },
        { origin: 'http://192.168.1.1/', host: 'localhost' },
        { origin: 'https://192.168.1.1:8080', host: '127.0.0.1:8080' },
        { origin: 'http://192.168.1.1:8080', host: '192.168.1.2:8080' },
        { origin: 'http://[::1]:8080', host: 'localhost:8080' },
        {
          origin: 'http://[ad42::1de2:54c2:c2fa:1234]',
          host: '[::1]:8080',
        },
        { origin: 'http://192.168.1.1' },
      ];

      server = new Server(compiler, options);

      tests.forEach((headers) => {
        expect(server.checkHost({ host: headers.host || 'localhost' })).toBe(
          true
        );
        expect(server.checkOrigin(headers)).toBe(false);
        expect(server.checkHeaders(headers, 'origin')).toBe(false);
      });
    });

    it('should allow an IP address in the origin header when it matches the host header', () => {
      const options = {};

      const tests = [
        { origin: 'http://127.0.0.1:8080', host: '127.0.0.1:8080' },
        { origin: 'http://192.168.1.1', host: '192.168.1.1:8080' },
        { origin: 'https://[::1]:8080', host: '[::1]:8080' },
        {
          origin: 'http://[ad42::1de2:54c2:c2fa:1234]',
          host: '[ad42::1de2:54c2:c2fa:1234]:8080',
        },
      ];

      server = new Server(compiler, options);

      tests.forEach((headers) => {
        expect(server.checkHost(headers)).toBe(true);
        expect(server.checkOrigin(headers)).toBe(true);
      });
    });

    it('should allow an IP address in the origin header if options.disableHostCheck is set', () => {
      const options = {
        disableHostCheck: true,
      };

      const headers = {
        origin: 'http://192.168.1.1',
        host: 'localhost:8080',
      };

      server = new Server(compiler, options);

      expect(server.checkOrigin(headers)).toBe(true);
    });

    it('should still allow non-IP origins that are allowed', () => {
      const options = {
        public: 'test.host:80',
        allowedHosts: ['.example.com'],
      };

      const tests = [
        { origin: 'http://localhost:8080', host: '127.0.0.1:8080' },
        { origin: 'https://test.host', host: '192.168.1.1:8080' },
        { origin: 'http://www.example.com', host: 'localhost:8080' },
      ];

      server = new Server(compiler, options);

      tests.forEach((headers) => {
        expect(server.checkOrigin(headers)).toBe(true);
      });
    });

    describe('malformed Host/Origin headers', () => {
      // an invalid IPv6 literal, which `url.parse()` throws on since Node.js 18
      const malformedHost = '[::1';
      const malformedOrigin = 'http://[::1/';
      // the `url.parse()` inputs built from them
      const malformedInputs = [`//${malformedHost}`, malformedOrigin];
      // a host-less origin, whose hostname `url.parse()` leaves `null`
      const hostlessOrigin = 'javascript://evil.example.com';

      let urlParseSpy = null;

      afterEach(() => {
        if (urlParseSpy) {
          urlParseSpy.mockRestore();
          urlParseSpy = null;
        }
      });

      it('should not throw on malformed Host/Origin headers parsed leniently by url.parse()', () => {
        server = new Server(compiler, {});

        const malformedHostHeaders = {
          origin: 'http://localhost:8080',
          host: malformedHost,
        };
        const malformedOriginHeaders = {
          origin: malformedOrigin,
          host: 'localhost:8080',
        };

        expect(() => server.checkHost(malformedHostHeaders)).not.toThrow();
        expect(() =>
          server.checkHeaders(malformedHostHeaders, 'host', true, false)
        ).not.toThrow();
        expect(server.isSameOrigin(malformedHostHeaders)).toBe(false);
        expect(
          server.isSameOriginRequest({ headers: malformedHostHeaders })
        ).toBe(false);

        expect(server.isSameOrigin(malformedOriginHeaders)).toBe(false);
        expect(server.checkOrigin(malformedOriginHeaders)).toBe(false);
        expect(server.checkHeaders(malformedOriginHeaders, 'origin')).toBe(
          false
        );
        expect(
          server.isSameOriginRequest({ headers: malformedOriginHeaders })
        ).toBe(false);
      });

      it('should reject a malformed Host header when url.parse() throws on it (Node.js >= 18)', () => {
        server = new Server(compiler, {});
        urlParseSpy = mockThrowingUrlParse(malformedInputs);

        const headers = {
          origin: 'http://localhost:8080',
          host: malformedHost,
        };

        expect(server.checkHost(headers)).toBe(false);
        expect(server.checkHeaders(headers, 'host', true, false)).toBe(false);
        expect(server.isSameOrigin(headers)).toBe(false);
        expect(server.isSameOriginRequest({ headers })).toBe(false);
        expect(urlParseSpy).toHaveBeenCalledWith(
          `//${malformedHost}`,
          false,
          true
        );
      });

      it('should reject a malformed Origin header when url.parse() throws on it (Node.js >= 18)', () => {
        server = new Server(compiler, {});
        urlParseSpy = mockThrowingUrlParse(malformedInputs);

        const headers = {
          origin: malformedOrigin,
          host: 'localhost:8080',
        };

        expect(server.checkHost(headers)).toBe(true);
        expect(server.isSameOrigin(headers)).toBe(false);
        expect(server.checkOrigin(headers)).toBe(false);
        expect(server.checkHeaders(headers, 'origin')).toBe(false);
        expect(server.isSameOriginRequest({ headers })).toBe(false);
        expect(urlParseSpy).toHaveBeenCalledWith(malformedOrigin, false, true);
      });

      it('should reject a host-less Origin header matched against a wildcard in allowedHosts', () => {
        server = new Server(compiler, { allowedHosts: ['.example.com'] });

        const headers = {
          origin: hostlessOrigin,
          host: 'localhost:8080',
        };

        expect(server.checkHost(headers)).toBe(true);
        expect(server.checkOrigin(headers)).toBe(false);
        expect(server.checkHeaders(headers, 'origin')).toBe(false);
        // a well-formed origin under the wildcard is still allowed
        expect(
          server.checkOrigin({
            origin: 'http://www.example.com',
            host: 'localhost:8080',
          })
        ).toBe(true);
      });

      it('should reject a host-less Host header matched against a wildcard in allowedHosts', () => {
        server = new Server(compiler, { allowedHosts: ['.example.com'] });

        const headers = { host: hostlessOrigin };

        expect(server.checkHost(headers)).toBe(false);
        expect(server.checkHeaders(headers, 'host', true, false)).toBe(false);
        // a well-formed host under the wildcard is still allowed
        expect(server.checkHost({ host: 'www.example.com:8080' })).toBe(true);
      });
    });

    describe('allowedHosts', () => {
      it('should allow hosts in allowedHosts', () => {
        const tests = ['test.host', 'test2.host', 'test3.host'];
        const options = { allowedHosts: tests };
        server = new Server(compiler, options);
        tests.forEach((test) => {
          const headers = { host: test };
          if (!server.checkHost(headers)) {
            throw new Error("Validation didn't fail");
          }
        });
      });

      it('should allow hosts that pass a wildcard in allowedHosts', () => {
        const options = { allowedHosts: ['.example.com'] };
        server = new Server(compiler, options);
        const tests = [
          'www.example.com',
          'subdomain.example.com',
          'example.com',
          'subsubcomain.subdomain.example.com',
          'example.com:80',
          'subdomain.example.com:80',
        ];
        tests.forEach((test) => {
          const headers = { host: test };
          if (!server.checkHost(headers)) {
            throw new Error("Validation didn't fail");
          }
        });
      });
    });
  });
});
