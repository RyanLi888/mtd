package com.mtd.detector.domain;

import java.util.Date;
import com.fasterxml.jackson.annotation.JsonFormat;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.mtd.common.annotation.Excel;
import com.mtd.common.core.domain.BaseEntity;

/**
 * 科研成果对象 research_result
 * 
 * @author lixu
 * @date 2025-05-19
 */
public class ResearchResult extends BaseEntity
{
    private static final long serialVersionUID = 1L;

    /** 成果ID */
    private Long resultId;

    /** 成果名称 */
    @Excel(name = "成果名称")
    private String resultName;

    /** 成果内容 */
    @Excel(name = "成果内容")
    private String resultContent;

    /** 发布时间 */
    @JsonFormat(pattern = "yyyy-MM-dd")
    @Excel(name = "发布时间", width = 30, dateFormat = "yyyy-MM-dd")
    private Date publishTime;

    public void setResultId(Long resultId) 
    {
        this.resultId = resultId;
    }

    public Long getResultId() 
    {
        return resultId;
    }

    public void setResultName(String resultName) 
    {
        this.resultName = resultName;
    }

    public String getResultName() 
    {
        return resultName;
    }

    public void setResultContent(String resultContent) 
    {
        this.resultContent = resultContent;
    }

    public String getResultContent() 
    {
        return resultContent;
    }

    public void setPublishTime(Date publishTime) 
    {
        this.publishTime = publishTime;
    }

    public Date getPublishTime() 
    {
        return publishTime;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this,ToStringStyle.MULTI_LINE_STYLE)
            .append("resultId", getResultId())
            .append("resultName", getResultName())
            .append("resultContent", getResultContent())
            .append("publishTime", getPublishTime())
            .toString();
    }
}
