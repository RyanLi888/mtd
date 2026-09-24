package com.mtd.detector.service.impl;

import java.util.List;
import com.mtd.common.utils.DateUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.mtd.detector.mapper.DetectionRuleMapper;
import com.mtd.detector.domain.DetectionRule;
import com.mtd.detector.service.IDetectionRuleService;

/**
 * 检测规则Service业务层处理
 * 
 * @author lixu
 * @date 2025-05-19
 */
@Service
public class DetectionRuleServiceImpl implements IDetectionRuleService 
{
    @Autowired
    private DetectionRuleMapper detectionRuleMapper;

    /**
     * 查询检测规则
     * 
     * @param ruleId 检测规则主键
     * @return 检测规则
     */
    @Override
    public DetectionRule selectDetectionRuleByRuleId(Long ruleId)
    {
        return detectionRuleMapper.selectDetectionRuleByRuleId(ruleId);
    }

    /**
     * 查询检测规则列表
     * 
     * @param detectionRule 检测规则
     * @return 检测规则
     */
    @Override
    public List<DetectionRule> selectDetectionRuleList(DetectionRule detectionRule)
    {
        return detectionRuleMapper.selectDetectionRuleList(detectionRule);
    }

    /**
     * 新增检测规则
     * 
     * @param detectionRule 检测规则
     * @return 结果
     */
    @Override
    public int insertDetectionRule(DetectionRule detectionRule)
    {
        detectionRule.setCreateTime(DateUtils.getNowDate());
        return detectionRuleMapper.insertDetectionRule(detectionRule);
    }

    /**
     * 修改检测规则
     * 
     * @param detectionRule 检测规则
     * @return 结果
     */
    @Override
    public int updateDetectionRule(DetectionRule detectionRule)
    {
        return detectionRuleMapper.updateDetectionRule(detectionRule);
    }

    /**
     * 批量删除检测规则
     * 
     * @param ruleIds 需要删除的检测规则主键
     * @return 结果
     */
    @Override
    public int deleteDetectionRuleByRuleIds(Long[] ruleIds)
    {
        return detectionRuleMapper.deleteDetectionRuleByRuleIds(ruleIds);
    }

    /**
     * 删除检测规则信息
     * 
     * @param ruleId 检测规则主键
     * @return 结果
     */
    @Override
    public int deleteDetectionRuleByRuleId(Long ruleId)
    {
        return detectionRuleMapper.deleteDetectionRuleByRuleId(ruleId);
    }
}
