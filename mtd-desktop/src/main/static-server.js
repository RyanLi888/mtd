'use strict'

const fs = require('fs')
const http = require('http')
const path = require('path')

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
}

function startStaticServer(uiRoot, port = 3090, backendPort = 8080) {
  const root = path.resolve(uiRoot)
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`)
    if (url.pathname === '/prod-api' || url.pathname.startsWith('/prod-api/')) {
      return proxyRequest(request, response, url, backendPort)
    }

    let relative
    try {
      relative = decodeURIComponent(url.pathname).replace(/^\/+/, '')
    } catch (_) {
      response.writeHead(400)
      return response.end('Bad Request')
    }
    let filePath = path.resolve(root, relative || 'index.html')
    if (!filePath.startsWith(root + path.sep) && filePath !== path.join(root, 'index.html')) {
      response.writeHead(403)
      return response.end('Forbidden')
    }
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) filePath = path.join(root, 'index.html')
    fs.readFile(filePath, (error, data) => {
      if (error) {
        response.writeHead(404)
        return response.end('Not Found')
      }
      response.writeHead(200, {
        'Content-Type': CONTENT_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
        'Cache-Control': filePath.endsWith('index.html') ? 'no-cache' : 'public, max-age=31536000, immutable',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'"
      })
      response.end(data)
    })
  })

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => resolve(server))
  })
}

function proxyRequest(request, response, url, backendPort) {
  const backendPath = (url.pathname.replace(/^\/prod-api/, '') || '/') + url.search
  const headers = { ...request.headers, host: `127.0.0.1:${backendPort}` }
  const proxy = http.request({
    hostname: '127.0.0.1',
    port: backendPort,
    method: request.method,
    path: backendPath,
    headers
  }, backendResponse => {
    response.writeHead(backendResponse.statusCode || 502, backendResponse.headers)
    backendResponse.pipe(response)
  })
  proxy.on('error', error => {
    response.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' })
    response.end(JSON.stringify({ code: 502, msg: `本地服务不可用：${error.message}` }))
  })
  request.pipe(proxy)
}

module.exports = { startStaticServer }
