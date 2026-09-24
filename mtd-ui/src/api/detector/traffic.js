import request from '@/utils/request'

// 查询恶意流量信息列表
export function listTraffic(query) {
  return request({
    url: '/detector/traffic/list',
    method: 'get',
    params: query
  })
}

// 查询恶意流量信息详细
export function getTraffic(trafficId) {
  return request({
    url: '/detector/traffic/' + trafficId,
    method: 'get'
  })
}

// 新增恶意流量信息
export function addTraffic(data) {
  return request({
    url: '/detector/traffic',
    method: 'post',
    data: data
  })
}

// 修改恶意流量信息
export function updateTraffic(data) {
  return request({
    url: '/detector/traffic',
    method: 'put',
    data: data
  })
}

// 删除恶意流量信息
export function delTraffic(trafficId) {
  return request({
    url: '/detector/traffic/' + trafficId,
    method: 'delete'
  })
}
