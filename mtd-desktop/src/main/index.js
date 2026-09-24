'use strict'

const { app, BrowserWindow, dialog, ipcMain, safeStorage } = require('electron')
const { spawn } = require('child_process')
const fs = require('fs')
const net = require('net')
const path = require('path')
const { ConfigStore } = require('./config-store')
const { SshManager } = require('./ssh-manager')
const { DetectionService } = require('./detection-service')
const { startStaticServer } = require('./static-server')

let mainWindow
let backendProcess
let webServer
let configStore
let sshManager
let detectionService
const BACKEND_PORT = 18080
const UI_PORT = 3090

const gotLock = app.requestSingleInstanceLock()
if (!gotLock) app.quit()

app.on('second-instance', () => {
  if (!mainWindow) return
  if (mainWindow.isMinimized()) mainWindow.restore()
  mainWindow.focus()
})

function broadcast(channel, payload) {
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed()) window.webContents.send(channel, payload)
  }
}

function appIconPath() {
  return app.isPackaged
    ? path.join(process.resourcesPath, 'app.asar', 'build', 'icon.ico')
    : path.join(__dirname, '..', '..', 'build', 'icon.ico')
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    show: false,
    backgroundColor: '#f1f5f8',
    autoHideMenuBar: true,
    icon: appIconPath(),
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  })
  mainWindow.once('ready-to-show', () => mainWindow.show())

  await mainWindow.loadURL(`data:text/html;charset=UTF-8,${encodeURIComponent(`
    <!doctype html><html><head><meta charset="utf-8"><title>MTD 挖矿检测系统</title>
    <style>html,body{height:100%;margin:0;font-family:"Microsoft YaHei",sans-serif;background:#10243d;color:#fff}
    body{display:flex;align-items:center;justify-content:center}.box{text-align:center}.mark{font-size:42px;color:#5fd8cf}
    h2{font-weight:500;margin:18px 0 8px}.hint{color:#a9bdcb;font-size:14px}</style></head>
    <body><div class="box"><div class="mark">◌</div><h2>正在启动 MTD 本地服务</h2><div class="hint">首次运行将自动创建本地数据库，请稍候…</div></div></body></html>
  `)}`)
}

async function loadApplication() {
  const developmentUrl = process.env.MTD_UI_URL
  if (developmentUrl) {
    await mainWindow.loadURL(developmentUrl)
  } else {
    const uiRoot = path.join(process.resourcesPath, 'ui')
    webServer = await startStaticServer(uiRoot, UI_PORT, BACKEND_PORT)
    await mainWindow.loadURL(`http://127.0.0.1:${UI_PORT}`)
  }
}

async function startBackend() {
  if (process.env.MTD_SKIP_BACKEND === 'true') return
  if (await isPortOpen(BACKEND_PORT)) throw new Error(`本地服务端口 ${BACKEND_PORT} 已被占用`)

  const repositoryRoot = path.resolve(__dirname, '..', '..', '..')
  const jarPath = app.isPackaged
    ? path.join(process.resourcesPath, 'backend', 'mtd-admin.jar')
    : path.join(repositoryRoot, 'mtd-admin', 'target', 'mtd-admin.jar')
  if (!fs.existsSync(jarPath)) {
    console.warn(`未找到本地后端：${jarPath}，请先执行资源准备脚本`)
    return
  }

  const bundledJava = path.join(process.resourcesPath, 'runtime', 'bin', 'java.exe')
  const javaExecutable = app.isPackaged && fs.existsSync(bundledJava)
    ? bundledJava
    : process.env.JAVA_HOME
      ? path.join(process.env.JAVA_HOME, 'bin', process.platform === 'win32' ? 'java.exe' : 'java')
      : 'java'
  const dataRoot = app.getPath('userData')
  const profilePath = path.join(dataRoot, 'files').replace(/\\/g, '/')
  fs.mkdirSync(path.join(dataRoot, 'database'), { recursive: true })
  fs.mkdirSync(path.join(dataRoot, 'logs'), { recursive: true })
  fs.mkdirSync(path.join(dataRoot, 'files'), { recursive: true })
  backendProcess = spawn(javaExecutable, [
    '-Dfile.encoding=UTF-8',
    `-Dmtd.profile=${profilePath}`,
    `-Dmtd.data-dir=${dataRoot.replace(/\\/g, '/')}`,
    '-Dspring.profiles.active=desktop',
    `-Dserver.port=${BACKEND_PORT}`,
    '-jar', jarPath
  ], {
    cwd: app.getPath('userData'),
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe']
  })
  backendProcess.stdout.on('data', chunk => console.log(`[backend] ${chunk.toString().trimEnd()}`))
  backendProcess.stderr.on('data', chunk => console.error(`[backend] ${chunk.toString().trimEnd()}`))
  backendProcess.once('exit', code => {
    console.log(`本地后端已退出，代码 ${code}`)
    backendProcess = null
  })
  await waitForPort(BACKEND_PORT, 60000)
}

function isPortOpen(port) {
  return new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port })
    socket.setTimeout(500)
    socket.once('connect', () => { socket.destroy(); resolve(true) })
    socket.once('timeout', () => { socket.destroy(); resolve(false) })
    socket.once('error', () => resolve(false))
  })
}

async function waitForPort(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await isPortOpen(port)) return
    await new Promise(resolve => setTimeout(resolve, 500))
  }
  throw new Error(`本地后端在 ${timeoutMs / 1000} 秒内未能启动`)
}

function registerIpc() {
  ipcMain.handle('dialog:select-identity', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: '选择 SSH 私钥',
      properties: ['openFile'],
      filters: [{ name: 'SSH 私钥', extensions: ['pem', 'key', 'ppk', '*'] }]
    })
    return result.canceled ? '' : result.filePaths[0]
  })
  ipcMain.handle('servers:list', () => configStore.listServers())
  ipcMain.handle('servers:save', (_event, server) => {
    const saved = configStore.upsertServer(server)
    detectionService.refreshServer(saved.id)
    return saved
  })
  ipcMain.handle('servers:remove', async (_event, serverId) => {
    await sshManager.disconnect(serverId)
    const removed = configStore.removeServer(serverId)
    detectionService.refreshServer(serverId)
    return removed
  })
  ipcMain.handle('ssh:test', (_event, serverId) => sshManager.testConnection(serverId))
  ipcMain.handle('ssh:connect', (_event, serverId) => sshManager.connect(serverId).then(() => ({ ok: true })))
  ipcMain.handle('ssh:disconnect', (_event, serverId) => sshManager.disconnect(serverId).then(() => ({ ok: true })))
  ipcMain.handle('detection:run', (_event, request) => detectionService.run(request.serverId, request.mode || 'traffic'))
  ipcMain.handle('detection:summary', () => detectionService.getSummary())
  ipcMain.handle('cpu:read', (_event, serverId) => detectionService.run(serverId, 'cpu'))
  ipcMain.handle('traffic:read', (_event, serverId) => detectionService.run(serverId, 'traffic'))
  ipcMain.handle('random:read', (_event, serverId) => detectionService.run(serverId, 'random'))
  ipcMain.handle('cpu:list', (_event, filters) => detectionService.listCpuCandidates(filters))
  ipcMain.handle('traffic:list', (_event, filters) => detectionService.listTrafficAlerts(filters))
  ipcMain.handle('random:list', (_event, filters) => detectionService.listRandomObservations(filters))
  ipcMain.handle('alarms:list', (_event, filters) => detectionService.listTrafficAlerts(filters))
  ipcMain.handle('detection:remediate', (_event, request) => sshManager.remediate(request.serverId, request))
  ipcMain.handle('stream:start', (_event, serverId) => sshManager.startStream(serverId, payload => broadcast('detection:stream', payload)))
  ipcMain.handle('stream:stop', (_event, serverId) => sshManager.stopStream(serverId))
}

app.whenReady().then(async () => {
  try {
    configStore = new ConfigStore(app.getPath('userData'), safeStorage)
    sshManager = new SshManager(configStore, status => broadcast('ssh:status', status))
    detectionService = new DetectionService(configStore, sshManager, broadcast)
    registerIpc()
    await createWindow()
    await startBackend()
    await loadApplication()
    detectionService.startAll()
  } catch (error) {
    console.error(error)
    dialog.showErrorBox('MTD 启动失败', error.message)
    app.quit()
  }
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  if (detectionService) detectionService.stopAll()
  if (sshManager) sshManager.disconnectAll().catch(() => {})
  if (webServer) webServer.close()
  if (backendProcess) backendProcess.kill()
})
