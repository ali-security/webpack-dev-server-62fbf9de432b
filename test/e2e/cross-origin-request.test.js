'use strict';

const http = require('http');
const net = require('net');
const internalIp = require('internal-ip');
const WebSocket = require('ws');
const testServer = require('../helpers/test-server');
const mockThrowingUrlParse = require('../helpers/throwing-url-parse');
const config = require('../fixtures/client-config/webpack.config');
const runBrowser = require('../helpers/run-browser');
const [port1, port2] = require('../ports-map')['cross-origin-request'];

describe('cross-origin requests', () => {
  const devServerPort = port1;
  const htmlServerPort = port2;
  const htmlServerHost = '127.0.0.1';

  // Loads a page from a separate (cross-site) origin containing `scriptTag`
  // and resolves with the HTTP status the dev server answered the script with.
  // TODO: use async/await when Node.js v6 support is dropped
  function getScriptTagResponseStatus(devServerOptions, scriptTag) {
    let htmlServer;
    let browser;

    const cleanup = () => {
      return Promise.resolve()
        .then(() => (browser ? browser.close() : null))
        .then(
          () =>
            new Promise((resolve) => {
              if (htmlServer) {
                htmlServer.close(() => resolve());
              } else {
                resolve();
              }
            })
        )
        .then(() => new Promise((resolve) => testServer.close(resolve)));
    };

    return new Promise((resolve) => {
      testServer.startAwaitingCompilation(
        config,
        Object.assign({ port: devServerPort }, devServerOptions),
        resolve
      );
    })
      .then(
        () =>
          new Promise((resolve) => {
            // Start a separate server for serving the HTML file
            htmlServer = http.createServer((req, res) => {
              res.writeHead(200, { 'Content-Type': 'text/html' });
              res.end(`
                <html>
                  <head>
                    ${scriptTag}
                  </head>
                  <body></body>
                </html>
              `);
            });
            htmlServer.listen(htmlServerPort, htmlServerHost, () => resolve());
          })
      )
      .then(() => runBrowser())
      .then((result) => {
        browser = result.browser;

        const { page } = result;
        const scriptTagRequest = page.waitForResponse(
          `http://localhost:${devServerPort}/main.js`
        );

        return page
          .goto(`http://${htmlServerHost}:${htmlServerPort}`)
          .then(() => scriptTagRequest);
      })
      .then((response) => response.status())
      .then(
        (status) => cleanup().then(() => status),
        (error) =>
          cleanup().then(() => {
            throw error;
          })
      );
  }

  it('should return 403 for cross-origin no-cors non-module script tag requests', () => {
    return getScriptTagResponseStatus(
      {},
      `<script src="http://localhost:${devServerPort}/main.js"></script>`
    ).then((status) => {
      expect(status).toBe(403);
    });
  });

  it('should return 200 for cross-origin cors non-module script tag requests', () => {
    return getScriptTagResponseStatus(
      {
        headers: {
          'Access-Control-Allow-Origin': '*',
        },
      },
      `<script src="http://localhost:${devServerPort}/main.js" crossorigin></script>`
    ).then((status) => {
      expect(status).toBe(200);
    });
  });

  it("should return 200 for cross-origin no-cors non-module script tag requests with the 'disableHostCheck' option", () => {
    return getScriptTagResponseStatus(
      {
        disableHostCheck: true,
      },
      `<script src="http://localhost:${devServerPort}/main.js"></script>`
    ).then((status) => {
      expect(status).toBe(200);
    });
  });

  it("should return 200 for cross-origin no-cors non-module script tag requests with the 'allowedHosts' option and the 'localhost' value", () => {
    return getScriptTagResponseStatus(
      {
        allowedHosts: ['localhost'],
      },
      `<script src="http://localhost:${devServerPort}/main.js"></script>`
    ).then((status) => {
      expect(status).toBe(200);
    });
  });
});

// Browsers only send the Sec-Fetch-* headers to potentially trustworthy origins,
// so when the dev server is reached over plain HTTP on a non-loopback address
// (e.g. a LAN IP) the cross-site no-cors check above is bypassed. The
// Cross-Origin-Resource-Policy header makes the browser itself refuse to hand
// the bundle to a cross-origin page.
// @see https://github.com/webpack/webpack-dev-server/security/advisories/GHSA-79cf-xcqc-c78w
describe('cross-origin resource policy header', () => {
  const devServerPort = port1;
  const htmlServerPort = port2;
  const htmlServerHost = '127.0.0.1';

  function request(path, headers) {
    return new Promise((resolve, reject) => {
      const req = http.get(
        {
          host: 'localhost',
          port: devServerPort,
          path,
          headers: headers || {},
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => {
            resolve({ status: res.statusCode, headers: res.headers, body });
          });
        }
      );
      req.on('error', reject);
    });
  }

  // Starts the dev server, requests `path` and resolves with the response,
  // closing the dev server afterwards whatever the outcome.
  // TODO: use async/await when Node.js v6 support is dropped
  function getResponse(devServerOptions, path, headers) {
    const close = () => new Promise((resolve) => testServer.close(resolve));

    return new Promise((resolve) => {
      testServer.startAwaitingCompilation(
        config,
        Object.assign({ port: devServerPort }, devServerOptions),
        resolve
      );
    })
      .then(() => request(path, headers))
      .then(
        (res) => close().then(() => res),
        (error) =>
          close().then(() => {
            throw error;
          })
      );
  }

  it('should set Cross-Origin-Resource-Policy: same-origin by default', () => {
    return getResponse({}, '/main.js').then((res) => {
      expect(res.status).toBe(200);
      expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
    });
  });

  it('should set Cross-Origin-Resource-Policy: same-origin for a LAN IP host without Sec-Fetch-* headers', () => {
    // what a browser sends over plain HTTP for <script src="http://192.168.1.10:port/main.js">
    // embedded on an attacker's page: no Sec-Fetch-* headers at all
    return getResponse({}, '/main.js', {
      Host: `192.168.1.10:${devServerPort}`,
      Referer: 'http://attacker.example.com/',
    }).then((res) => {
      expect(res.status).toBe(200);
      expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
    });
  });

  it('should set Cross-Origin-Resource-Policy: same-origin for the client bundles', () => {
    return getResponse({}, '/webpack-dev-server.js', {
      Host: `192.168.1.10:${devServerPort}`,
    }).then((res) => {
      expect(res.status).toBe(200);
      expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
    });
  });

  it("should NOT set CORP header with the 'disableHostCheck' option", () => {
    return getResponse({ disableHostCheck: true }, '/main.js').then((res) => {
      expect(res.status).toBe(200);
      expect(res.headers['cross-origin-resource-policy']).toBeUndefined();
    });
  });

  it('should NOT set CORP header when user configures wildcard CORS', () => {
    return getResponse(
      { headers: { 'Access-Control-Allow-Origin': '*' } },
      '/main.js'
    ).then((res) => {
      expect(res.status).toBe(200);
      expect(res.headers['cross-origin-resource-policy']).toBeUndefined();
    });
  });

  it('should set CORP header when user configures a specific-origin Access-Control-Allow-Origin (no-cors embedding is not governed by CORS)', () => {
    return getResponse(
      { headers: { 'Access-Control-Allow-Origin': 'http://foo.example.com' } },
      '/main.js'
    ).then((res) => {
      expect(res.status).toBe(200);
      expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
    });
  });

  it('should set CORP header when user configures Access-Control-Allow-Origin as an array with a specific origin', () => {
    return getResponse(
      {
        headers: { 'Access-Control-Allow-Origin': ['http://foo.example.com'] },
      },
      '/main.js'
    ).then((res) => {
      expect(res.status).toBe(200);
      expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
    });
  });

  it('should NOT set CORP header when user configures wildcard Access-Control-Allow-Origin as an array', () => {
    return getResponse(
      { headers: { 'access-control-allow-origin': ['*'] } },
      '/main.js'
    ).then((res) => {
      expect(res.status).toBe(200);
      expect(res.headers['cross-origin-resource-policy']).toBeUndefined();
    });
  });

  it('should NOT set CORP header when host is in allowedHosts', () => {
    return getResponse({ allowedHosts: ['localhost'] }, '/main.js').then(
      (res) => {
        expect(res.status).toBe(200);
        expect(res.headers['cross-origin-resource-policy']).toBeUndefined();
      }
    );
  });

  // The attack itself: a page on another origin embeds the bundle with a classic
  // <script> tag while the dev server is reached on a LAN IP over plain HTTP,
  // so the browser sends no Sec-Fetch-* headers and the 403 check never fires.
  const lanAddress = internalIp.v4.sync();

  (lanAddress ? it : it.skip)(
    'should prevent a cross-origin page from running the bundle served over plain HTTP on a LAN IP',
    () => {
      const bundleUrl = `http://${lanAddress}:${devServerPort}/main.js`;
      const consoleMessages = [];
      let bundleRequestHeaders;
      let htmlServer;
      let browser;

      const cleanup = () => {
        return Promise.resolve()
          .then(() => (browser ? browser.close() : null))
          .then(
            () =>
              new Promise((resolve) => {
                if (htmlServer) {
                  htmlServer.close(() => resolve());
                } else {
                  resolve();
                }
              })
          )
          .then(() => new Promise((resolve) => testServer.close(resolve)));
      };

      return new Promise((resolve) => {
        testServer.startAwaitingCompilation(
          config,
          {
            port: devServerPort,
            host: '0.0.0.0',
            // runs after the cross-origin header check, records what the
            // browser actually sent for the bundle
            before(app) {
              app.get('/main.js', (req, res, next) => {
                bundleRequestHeaders = req.headers;
                next();
              });
            },
          },
          resolve
        );
      })
        .then(
          () =>
            new Promise((resolve) => {
              // the attacker's page
              htmlServer = http.createServer((req, res) => {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(`
                  <html>
                    <head>
                      <script
                        src="${bundleUrl}"
                        onload="window.__bundleLoaded = true"
                        onerror="window.__bundleBlocked = true"
                      ></script>
                    </head>
                    <body></body>
                  </html>
                `);
              });
              htmlServer.listen(htmlServerPort, htmlServerHost, () =>
                resolve()
              );
            })
        )
        .then(() => runBrowser())
        .then((result) => {
          browser = result.browser;

          const { page } = result;

          page.on('console', (message) => {
            consoleMessages.push(message.text());
          });

          return page
            .goto(`http://${htmlServerHost}:${htmlServerPort}`, {
              waitUntil: 'load',
            })
            .then(() =>
              page.evaluate(
                '({ loaded: window.__bundleLoaded === true, blocked: window.__bundleBlocked === true })'
              )
            );
        })
        .then(
          (outcome) =>
            cleanup().then(() => {
              // the browser sent no Sec-Fetch-* headers, so the server-side
              // 403 check did not apply and the bundle was served
              expect(bundleRequestHeaders).toBeDefined();
              expect(bundleRequestHeaders['sec-fetch-mode']).toBeUndefined();
              // ...but the browser refused to run it on the attacker's page
              expect(outcome).toEqual({ loaded: false, blocked: true });
              expect(consoleMessages).not.toContain('Hey.');
            }),
          (error) =>
            cleanup().then(() => {
              throw error;
            })
        );
    }
  );
});

// A cross-site page must not be able to trigger the state-changing
// `/webpack-dev-server/invalidate` endpoint (cross-site request forgery).
describe('cross-site request forgery on state-changing endpoints', () => {
  const devServerPort = port1;
  const endpoint = '/webpack-dev-server/invalidate';

  function request(path, headers) {
    return new Promise((resolve, reject) => {
      const req = http.get(
        {
          host: 'localhost',
          port: devServerPort,
          path,
          headers: headers || {},
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => {
            resolve({ status: res.statusCode, body });
          });
        }
      );
      req.on('error', reject);
    });
  }

  // Starts the dev server, requests the invalidate endpoint and resolves with
  // the response plus whether a rebuild was triggered, closing the dev server
  // afterwards whatever the outcome.
  // TODO: use async/await when Node.js v6 support is dropped
  function requestInvalidate(devServerOptions, headers) {
    let invalidateSpy;
    const close = () => new Promise((resolve) => testServer.close(resolve));

    return new Promise((resolve) => {
      const server = testServer.startAwaitingCompilation(
        config,
        Object.assign({ port: devServerPort }, devServerOptions),
        resolve
      );

      invalidateSpy = jest.spyOn(server, 'invalidate');
    })
      .then(() => request(endpoint, headers))
      .then(
        (res) =>
          close().then(() =>
            Object.assign(
              { invalidated: invalidateSpy.mock.calls.length > 0 },
              res
            )
          ),
        (error) =>
          close().then(() => {
            throw error;
          })
      );
  }

  it(`should block cross-site requests to ${endpoint}`, () => {
    // what a browser sends for fetch() from an attacker's page
    return requestInvalidate(
      {},
      {
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
      }
    ).then((res) => {
      expect(res.status).toBe(403);
      expect(res.body).toBe('Cross-Origin request blocked');
      expect(res.invalidated).toBe(false);
    });
  });

  it(`should block cross-site navigations to ${endpoint}`, () => {
    // what a browser sends for a link/form on an attacker's page
    return requestInvalidate(
      {},
      {
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'cross-site',
      }
    ).then((res) => {
      expect(res.status).toBe(403);
      expect(res.invalidated).toBe(false);
    });
  });

  it(`should block same-site (non same-origin) requests to ${endpoint}`, () => {
    return requestInvalidate(
      {},
      {
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
      }
    ).then((res) => {
      expect(res.status).toBe(403);
      expect(res.invalidated).toBe(false);
    });
  });

  it(`should block cross-site requests to ${endpoint} when the host is in 'allowedHosts'`, () => {
    // 'allowedHosts' bypasses the global cross-origin header check
    return requestInvalidate(
      { allowedHosts: ['localhost'] },
      {
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
      }
    ).then((res) => {
      expect(res.status).toBe(403);
      expect(res.invalidated).toBe(false);
    });
  });

  it(`should block requests to ${endpoint} with a cross-origin Origin and no Sec-Fetch metadata`, () => {
    return requestInvalidate({}, { origin: 'http://evil.example' }).then(
      (res) => {
        expect(res.status).toBe(403);
        expect(res.invalidated).toBe(false);
      }
    );
  });

  it(`should block requests to ${endpoint} over a LAN IP with a cross-origin Origin and no Sec-Fetch metadata`, () => {
    // browsers send no Sec-Fetch-* headers over plain HTTP to a LAN IP
    return requestInvalidate(
      {},
      {
        Host: `192.168.1.10:${devServerPort}`,
        origin: 'http://attacker.example.com',
      }
    ).then((res) => {
      expect(res.status).toBe(403);
      expect(res.invalidated).toBe(false);
    });
  });

  it(`should allow same-origin requests to ${endpoint}`, () => {
    return requestInvalidate(
      {},
      {
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
      }
    ).then((res) => {
      expect(res.status).toBe(200);
      expect(res.invalidated).toBe(true);
    });
  });

  it(`should allow user-initiated navigations to ${endpoint}`, () => {
    return requestInvalidate({}, { 'sec-fetch-site': 'none' }).then((res) => {
      expect(res.status).toBe(200);
      expect(res.invalidated).toBe(true);
    });
  });

  it(`should allow requests to ${endpoint} with a same-origin Origin and no Sec-Fetch metadata`, () => {
    return requestInvalidate(
      {},
      { origin: `http://localhost:${devServerPort}` }
    ).then((res) => {
      expect(res.status).toBe(200);
      expect(res.invalidated).toBe(true);
    });
  });

  it(`should allow requests to ${endpoint} without Sec-Fetch metadata or Origin (e.g. curl)`, () => {
    return requestInvalidate({}).then((res) => {
      expect(res.status).toBe(200);
      expect(res.invalidated).toBe(true);
    });
  });
});

// A malformed `Host` or `Origin` header value must be rejected, not throw while
// it is being validated: thrown from the socket server's connection handler,
// the error takes down the whole dev server process.
// See https://github.com/webpack/webpack-dev-server/commit/f21ed0f44aceb6132abb591ee8b60d770b6e489f
describe('malformed Host/Origin headers', () => {
  const devServerPort = port1;
  const invalidHeaderMessage = JSON.stringify({
    type: 'error',
    data: 'Invalid Host/Origin header',
  });
  // an invalid IPv6 literal, which `url.parse()` throws on since Node.js 18
  const malformedHost = '[::1';
  const malformedOrigin = 'http://[::1/';
  // a host-less origin, whose hostname `url.parse()` leaves `null`
  const hostlessOrigin = 'javascript://evil.example.com';

  let urlParseSpy = null;

  afterEach(() => {
    if (urlParseSpy) {
      urlParseSpy.mockRestore();
      urlParseSpy = null;
    }
  });

  // the older Node.js versions under test parse the malformed values
  // leniently, so make `url.parse()` throw on them like Node.js >= 18 does
  function mockUrlParse() {
    urlParseSpy = mockThrowingUrlParse([`//${malformedHost}`, malformedOrigin]);
  }

  function request(path, headers) {
    return new Promise((resolve, reject) => {
      const req = http.get(
        {
          host: 'localhost',
          port: devServerPort,
          path,
          headers: headers || {},
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => {
            resolve({ status: res.statusCode, body });
          });
        }
      );
      req.on('error', reject);
    });
  }

  // connects a websocket client sending the given headers and collects the
  // messages until the dev server closes the connection
  function connectSocket(socketPath, headers) {
    return new Promise((resolve) => {
      const result = { messages: [], closed: false };
      const client = new WebSocket(
        `ws://localhost:${devServerPort}${socketPath}`,
        { headers }
      );
      let finished = false;
      let timer = null;

      const finish = () => {
        if (finished) {
          return;
        }

        finished = true;
        clearTimeout(timer);

        // state of the connection before the client terminates it
        const state = {
          messages: result.messages.slice(),
          closed: result.closed,
        };

        client.terminate();
        resolve(state);
      };

      timer = setTimeout(finish, 5000);

      client.on('message', (message) => {
        result.messages.push(message);
      });

      client.on('close', () => {
        result.closed = true;
        finish();
      });

      client.on('error', () => {});
    });
  }

  // sends a request over a raw socket, so the malformed Host header reaches
  // the dev server as-is, and resolves with the raw response
  function rawRequest(path, host) {
    return new Promise((resolve) => {
      let response = '';
      const socket = net.connect(devServerPort, 'localhost', () => {
        socket.write(
          [
            `GET ${path} HTTP/1.1`,
            `Host: ${host}`,
            'Connection: close',
            '',
            '',
          ].join('\r\n')
        );
      });

      socket.setEncoding('utf8');
      socket.on('data', (chunk) => {
        response += chunk;
      });
      socket.on('close', () => resolve(response));
      socket.on('error', () => resolve(response));
    });
  }

  // Starts the dev server, runs `attack` against it and then checks the dev
  // server is still alive by requesting the bundle. Resolves with the result
  // of the attack and the status of the bundle request, closing the dev
  // server afterwards whatever the outcome.
  // TODO: use async/await when Node.js v6 support is dropped
  function attackDevServer(devServerOptions, attack) {
    let server;
    const close = () => new Promise((resolve) => testServer.close(resolve));

    return new Promise((resolve) => {
      server = testServer.startAwaitingCompilation(
        config,
        Object.assign({ port: devServerPort }, devServerOptions),
        resolve
      );
    })
      .then(() => attack(server))
      .then((result) =>
        request('/main.js').then((res) => {
          return { result, bundleStatus: res.status };
        })
      )
      .then(
        (outcome) => close().then(() => outcome),
        (error) =>
          close().then(() => {
            throw error;
          })
      );
  }

  [
    {
      title: 'ws',
      transportMode: 'ws',
      socketPath: '/sockjs-node',
    },
    {
      title: 'sockjs',
      transportMode: 'sockjs',
      // raw websocket endpoint of sockjs
      socketPath: '/sockjs-node/websocket',
    },
  ].forEach((transport) => {
    describe(`websocket connections ("${transport.title}")`, () => {
      [
        {
          title: 'a malformed Origin header',
          headers: {
            host: `localhost:${devServerPort}`,
            origin: malformedOrigin,
          },
          mockUrlParse: true,
        },
        {
          title: 'a malformed Host header',
          headers: { host: malformedHost },
          mockUrlParse: true,
        },
        {
          title: "a host-less Origin header and a wildcard in 'allowedHosts'",
          options: { allowedHosts: ['.example.com'] },
          headers: {
            host: `localhost:${devServerPort}`,
            origin: hostlessOrigin,
          },
        },
        {
          title: "a host-less Host header and a wildcard in 'allowedHosts'",
          options: { allowedHosts: ['.example.com'] },
          headers: { host: hostlessOrigin },
        },
      ].forEach((data) => {
        it(`should reject a connection with ${data.title} without crashing`, () => {
          return attackDevServer(
            Object.assign(
              { transportMode: transport.transportMode },
              data.options
            ),
            () => {
              if (data.mockUrlParse) {
                mockUrlParse();
              }

              return connectSocket(transport.socketPath, data.headers);
            }
          ).then((outcome) => {
            expect(outcome.result.messages).toContain(invalidHeaderMessage);
            expect(outcome.result.closed).toBe(true);
            // the dev server is still alive
            expect(outcome.bundleStatus).toBe(200);
          });
        });
      });
    });
  });

  [
    {
      title: 'a malformed Host header',
      host: malformedHost,
      mockUrlParse: true,
    },
    {
      title: "a host-less Host header and a wildcard in 'allowedHosts'",
      options: { allowedHosts: ['.example.com'] },
      host: hostlessOrigin,
    },
  ].forEach((data) => {
    it(`should reject a request with ${data.title} without crashing`, () => {
      return attackDevServer(data.options, () => {
        if (data.mockUrlParse) {
          mockUrlParse();
        }

        return rawRequest('/main.js', data.host);
      }).then((outcome) => {
        expect(outcome.result).toMatch(/^HTTP\/1\.1 200 /);
        expect(outcome.result).toContain('Invalid Host header');
        // the dev server is still alive
        expect(outcome.bundleStatus).toBe(200);
      });
    });
  });

  it('should reject a request to /webpack-dev-server/invalidate with a malformed Origin header', () => {
    let invalidateSpy;

    return attackDevServer({}, (server) => {
      invalidateSpy = jest.spyOn(server, 'invalidate');
      mockUrlParse();

      return request('/webpack-dev-server/invalidate', {
        origin: malformedOrigin,
      });
    }).then((outcome) => {
      expect(outcome.result.status).toBe(403);
      expect(outcome.result.body).toBe('Cross-Origin request blocked');
      expect(invalidateSpy).not.toHaveBeenCalled();
      // the dev server is still alive
      expect(outcome.bundleStatus).toBe(200);
    });
  });
});
