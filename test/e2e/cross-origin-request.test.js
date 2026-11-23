'use strict';

const http = require('http');
const internalIp = require('internal-ip');
const testServer = require('../helpers/test-server');
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
