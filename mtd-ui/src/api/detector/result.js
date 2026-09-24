import request from '@/utils/request'

// 查询科研成果列表
export function listResult(query) {
  return request({
    url: '/detector/result/list',
    method: 'get',
    params: query
  })
}

// 查询科研成果详细
export function getResult(resultId) {
  return request({
    url: '/detector/result/' + resultId,
    method: 'get'
  })
}

// 新增科研成果
export function addResult(data) {
  return request({
    url: '/detector/result',
    method: 'post',
    data: data
  })
}

// 修改科研成果
export function updateResult(data) {
  return request({
    url: '/detector/result',
    method: 'put',
    data: data
  })
}

// 删除科研成果
export function delResult(resultId) {
  return request({
    url: '/detector/result/' + resultId,
    method: 'delete'
  })
}
