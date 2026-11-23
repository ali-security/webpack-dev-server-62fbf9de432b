'use strict';

const http = require('http');
const WebSocket = require('ws');
const testServer = require('../helpers/test-server');
const config = require('../fixtures/proxy-config/webpack.config');
const [devServerPort, backendPort] = require('../ports-map')[
  'proxy-web-socket-origin'
];

const WebSocketServer = WebSocket.Server;
const devServerOrigin = `http://localhost:${devServerPort}`;

const wait = (ms) =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

// Upgrade requests bypass the express middleware chain, so a proxy with
// `ws: true` must apply the same Host/Origin validation as the dev server's own
// socket before forwarding the upgrade to the proxy target.
// See https://github.com/webpack/webpack-dev-server/commit/3e9b60494963e155ff68958ef82686aa141b4c74
describe('proxied WebSocket upgrade origin validation', () => {
  let backend;
  let backendWss;
  let backendSockets;
  let backendConnections;
  let backendPaths;

  const startBackend = () =>
    new Promise((resolve) => {
      backendSockets = [];
      backendConnections = 0;
      backendPaths = [];

      // A stand-in for a service the developer proxies over WebSocket.
      backend = http.createServer((req, res) => {
        res.end('backend response');
      });
      backend.on('connection', (socket) => {
        backendSockets.push(socket);
      });
      backendWss = new WebSocketServer({ server: backend });
      backendWss.on('connection', (client, req) => {
        backendConnections += 1;
        backendPaths.push(req.url);
        client.send('INTERNAL-SERVICE-SECRET');
      });
      backend.listen(backendPort, '127.0.0.1', resolve);
    });

  const stopBackend = () =>
    new Promise((resolve) => {
      backendWss.clients.forEach((client) => {
        client.terminate();
      });
      backendWss.close();
      backendSockets.forEach((socket) => {
        socket.destroy();
      });
      backend.close(() => resolve());
    });

  const startServer = (devServerOptions) =>
    // the test server helper is a singleton: close a previous one first
    new Promise((resolve) => {
      testServer.close(resolve);
    }).then(
      () =>
        new Promise((resolve, reject) => {
          testServer.start(
            config,
            Object.assign(
              {
                port: devServerPort,
                proxy: [
                  {
                    context: ['/api'],
                    target: `http://127.0.0.1:${backendPort}`,
                    ws: true,
                  },
                ],
              },
              devServerOptions
            ),
            (err) => (err ? reject(err) : resolve())
          );
        })
    );

  const stopServer = () =>
    new Promise((resolve) => {
      testServer.close(resolve);
    });

  // Sends a raw WebSocket upgrade request to the dev server and reports
  // whether it was upgraded and the HTTP status the dev server answered with.
  const upgrade = (origin, headers) =>
    new Promise((resolve) => {
      const requestHeaders = {
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
        'Sec-WebSocket-Version': '13',
      };

      if (typeof origin === 'string') {
        requestHeaders.Origin = origin;
      }

      const req = http.request({
        host: 'localhost',
        port: devServerPort,
        path: '/api/socket',
        headers: Object.assign(requestHeaders, headers),
      });

      req.setTimeout(8000, () => {
        req.abort();
        resolve({ upgraded: false });
      });
      req.on('upgrade', (res, socket) => {
        socket.destroy();
        resolve({ upgraded: true, status: res.statusCode });
      });
      req.on('response', (res) => {
        res.resume();
        resolve({ upgraded: false, status: res.statusCode });
      });
      req.on('error', () => {
        resolve({ upgraded: false });
      });
      req.end();
    });

  // A regular (non-upgrade) HTTP request through the proxy.
  const get = (urlPath) =>
    new Promise((resolve, reject) => {
      http
        .get(`http://localhost:${devServerPort}${urlPath}`, (res) => {
          let body = '';

          res.setEncoding('utf8');
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body });
          });
        })
        .on('error', reject);
    });

  // A rejected upgrade could still be forwarded by a separate `upgrade`
  // listener after the client got the rejection, so give it time to happen.
  const expectRejected = (result) => {
    expect(result.upgraded).toBe(false);
    expect(result.status).toBe(403);

    return wait(200).then(() => {
      expect(backendConnections).toBe(0);
    });
  };

  const expectAllowed = (result) => {
    expect(result.upgraded).toBe(true);
    expect(result.status).toBe(101);
    expect(backendConnections).toBe(1);
  };

  beforeEach(() => startBackend());

  afterEach(() => stopServer().then(() => stopBackend()));

  describe('with the default host check', () => {
    beforeEach(() => startServer());

    it('should reject a cross-origin proxied WebSocket upgrade', () =>
      upgrade('http://evil.example.com').then(expectRejected));

    it('should allow a same-origin proxied WebSocket upgrade', () =>
      upgrade(devServerOrigin).then(expectAllowed));

    it('should allow a same-origin proxied WebSocket upgrade over an IP address', () =>
      upgrade(`http://127.0.0.1:${devServerPort}`, {
        Host: `127.0.0.1:${devServerPort}`,
      }).then(expectAllowed));

    it('should reject an upgrade with an invalid Host header', () =>
      upgrade(devServerOrigin, { Host: 'evil.example.com' }).then(
        expectRejected
      ));

    it('should reject a DNS rebinding upgrade (attacker Host and Origin)', () =>
      upgrade('http://evil.example.com', {
        Host: `evil.example.com:${devServerPort}`,
      }).then(expectRejected));

    it('should reject an upgrade without an Origin header', () =>
      upgrade().then(expectRejected));

    it('should reject an upgrade with an opaque (null) Origin header', () =>
      upgrade('null').then(expectRejected));

    it('should reject an upgrade from a remote IP address Origin', () =>
      upgrade('http://203.0.113.7').then(expectRejected));

    it('should not forward a rejected upgrade after an HTTP proxy request', () =>
      get('/api/hello')
        .then(({ statusCode, body }) => {
          expect(statusCode).toBe(200);
          expect(body).toBe('backend response');

          return upgrade('http://evil.example.com');
        })
        .then(expectRejected));

    it('should allow a same-origin upgrade after an HTTP proxy request', () =>
      get('/api/hello')
        .then(({ statusCode }) => {
          expect(statusCode).toBe(200);

          return upgrade(devServerOrigin);
        })
        .then(expectAllowed));
  });

  describe('with a proxy callback', () => {
    let proxyConfig;

    beforeEach(() => {
      proxyConfig = {
        context: ['/api'],
        target: `http://127.0.0.1:${backendPort}`,
        ws: false,
        pathRewrite: { '^/api': '/initial' },
      };

      return startServer({
        proxy: [() => Object.assign({}, proxyConfig)],
      });
    });

    it('should validate upgrades using the current proxy callback configuration', () =>
      get('/api/hello')
        .then(({ statusCode }) => {
          expect(statusCode).toBe(200);

          proxyConfig = Object.assign({}, proxyConfig, {
            ws: true,
            pathRewrite: { '^/api': '/updated' },
          });

          return get('/api/hello');
        })
        .then(({ statusCode }) => {
          expect(statusCode).toBe(200);

          return upgrade('http://evil.example.com');
        })
        .then(expectRejected)
        .then(() => upgrade(devServerOrigin))
        .then((result) => {
          expectAllowed(result);
          expect(backendPaths).toEqual(['/updated/socket']);
        }));
  });

  describe('with allowedHosts', () => {
    beforeEach(() => startServer({ allowedHosts: ['.trusted.test'] }));

    it('should allow an upgrade from an allowed Origin', () =>
      upgrade('http://app.trusted.test').then(expectAllowed));

    it('should allow an upgrade to an allowed Host', () =>
      upgrade('http://app.trusted.test', {
        Host: `app.trusted.test:${devServerPort}`,
      }).then(expectAllowed));

    it('should still reject a cross-origin upgrade', () =>
      upgrade('http://evil.example.com').then(expectRejected));
  });

  describe('with disableHostCheck', () => {
    beforeEach(() => startServer({ disableHostCheck: true }));

    it('should forward any upgrade (opt-out of the security check)', () =>
      upgrade('http://evil.example.com').then(expectAllowed));
  });
});
