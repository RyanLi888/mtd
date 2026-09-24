package com.mtd.detector.domain;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.mtd.common.annotation.Excel;
import com.mtd.common.core.domain.BaseEntity;

/**
 * 检测规则对象 detection_rule
 * 
 * @author lixu
 * @date 2025-05-19
 */
public class DetectionRule extends BaseEntity
{
    private static final long serialVersionUID = 1L;

    /** 规则ID */
    @Excel(name = "规则ID")
    private Long ruleId;

    /** 规则名称 */
    @Excel(name = "规则名称")
    private String ruleName;

    /** 规则内容 */
    @Excel(name = "规则内容")
    private String ruleContent;

    public void setRuleId(Long ruleId) 
    {
        this.ruleId = ruleId;
    }

    public Long getRuleId() 
    {
        return ruleId;
    }

    public void setRuleName(String ruleName) 
    {
        this.ruleName = ruleName;
    }

    public String getRuleName() 
    {
        return ruleName;
    }

    public void setRuleContent(String ruleContent) 
    {
        this.ruleContent = ruleContent;
    }

    public String getRuleContent() 
    {
        return ruleContent;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this,ToStringStyle.MULTI_LINE_STYLE)
            .append("ruleId", getRuleId())
            .append("ruleName", getRuleName())
            .append("ruleContent", getRuleContent())
            .append("createTime", getCreateTime())
            .toString();
    }
}
