function bridge() {
  if (window.electronAPI && window.electronAPI.isDesktop) return window.electronAPI
  throw new Error('远程检测功能仅在 MTD Windows 客户端中可用')
}

export function isDesktopClient() {
  return Boolean(window.electronAPI && window.electronAPI.isDesktop)
}

export const desktopApi = {
  selectIdentityFile: () => bridge().selectIdentityFile(),
  listServers: () => bridge().listServers(),
  saveServer: server => bridge().saveServer(server),
  removeServer: serverId => bridge().removeServer(serverId),
  testConnection: serverId => bridge().testConnection(serverId),
  connect: serverId => bridge().connect(serverId),
  disconnect: serverId => bridge().disconnect(serverId),
  runDetection: (serverId, mode) => bridge().runDetection(serverId, mode),
  readCpuResult: serverId => bridge().readCpuResult(serverId),
  readTrafficAlerts: serverId => bridge().readTrafficAlerts(serverId),
  readRandomObservations: serverId => bridge().readRandomObservations(serverId),
  listCpuCandidates: filters => bridge().listCpuCandidates(filters),
  listTrafficAlerts: filters => bridge().listTrafficAlerts(filters),
  listRandomObservations: filters => bridge().listRandomObservations(filters),
  getSummary: () => bridge().getSummary(),
  listAlarms: filters => bridge().listAlarms(filters),
  remediate: request => bridge().remediate(request),
  startStream: serverId => bridge().startStream(serverId),
  stopStream: serverId => bridge().stopStream(serverId),
  onSshStatus: callback => bridge().onSshStatus(callback),
  onDetectionResult: callback => bridge().onDetectionResult(callback),
  onDetectionStatus: callback => bridge().onDetectionStatus(callback),
  onCpuResult: callback => bridge().onCpuResult(callback),
  onTrafficAlerts: callback => bridge().onTrafficAlerts(callback),
  onRandomObservations: callback => bridge().onRandomObservations(callback),
  onAlarm: callback => bridge().onAlarm(callback),
  onDetectionError: callback => bridge().onDetectionError(callback),
  onStreamData: callback => bridge().onStreamData(callback)
}