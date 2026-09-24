import request from '@/utils/request'

// 查询检测规则列表
export function listRule(query) {
  return request({
    url: '/detector/rule/list',
    method: 'get',
    params: query
  })
}

// 查询检测规则详细
export function getRule(ruleId) {
  return request({
    url: '/detector/rule/' + ruleId,
    method: 'get'
  })
}

// 新增检测规则
export function addRule(data) {
  return request({
    url: '/detector/rule',
    method: 'post',
    data: data
  })
}

// 修改检测规则
export function updateRule(data) {
  return request({
    url: '/detector/rule',
    method: 'put',
    data: data
  })
}

// 删除检测规则
export function delRule(ruleId) {
  return request({
    url: '/detector/rule/' + ruleId,
    method: 'delete'
  })
}
