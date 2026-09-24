'use strict'

const { contextBridge, ipcRenderer } = require('electron')

function subscribe(channel, callback) {
  const listener = (_event, payload) => callback(payload)
  ipcRenderer.on(channel, listener)
  return () => ipcRenderer.removeListener(channel, listener)
}

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  isDesktop: true,
  selectIdentityFile: () => ipcRenderer.invoke('dialog:select-identity'),
  listServers: () => ipcRenderer.invoke('servers:list'),
  saveServer: server => ipcRenderer.invoke('servers:save', server),
  removeServer: serverId => ipcRenderer.invoke('servers:remove', serverId),
  testConnection: serverId => ipcRenderer.invoke('ssh:test', serverId),
  connect: serverId => ipcRenderer.invoke('ssh:connect', serverId),
  disconnect: serverId => ipcRenderer.invoke('ssh:disconnect', serverId),
  runDetection: (serverId, mode) => ipcRenderer.invoke('detection:run', { serverId, mode }),
  readCpuResult: serverId => ipcRenderer.invoke('cpu:read', serverId),
  readTrafficAlerts: serverId => ipcRenderer.invoke('traffic:read', serverId),
  readRandomObservations: serverId => ipcRenderer.invoke('random:read', serverId),
  listCpuCandidates: filters => ipcRenderer.invoke('cpu:list', filters || {}),
  listTrafficAlerts: filters => ipcRenderer.invoke('traffic:list', filters || {}),
  listRandomObservations: filters => ipcRenderer.invoke('random:list', filters || {}),
  getSummary: () => ipcRenderer.invoke('detection:summary'),
  listAlarms: filters => ipcRenderer.invoke('alarms:list', filters || {}),
  remediate: request => ipcRenderer.invoke('detection:remediate', request),
  startStream: serverId => ipcRenderer.invoke('stream:start', serverId),
  stopStream: serverId => ipcRenderer.invoke('stream:stop', serverId),
  onSshStatus: callback => subscribe('ssh:status', callback),
  onDetectionResult: callback => subscribe('detection:result', callback),
  onDetectionStatus: callback => subscribe('detection:status', callback),
  onCpuResult: callback => subscribe('cpu:result', callback),
  onTrafficAlerts: callback => subscribe('traffic:alerts', callback),
  onRandomObservations: callback => subscribe('random:observations', callback),
  onAlarm: callback => subscribe('traffic:alerts', callback),
  onDetectionError: callback => subscribe('detection:error', callback),
  onStreamData: callback => subscribe('detection:stream', callback)
})