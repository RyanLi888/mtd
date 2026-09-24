package com.mtd.detector.domain;

import java.util.Date;
import com.fasterxml.jackson.annotation.JsonFormat;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.mtd.common.annotation.Excel;
import com.mtd.common.core.domain.BaseEntity;

/**
 * 恶意流量信息对象 malicious_traffic
 * 
 * @author lixu
 * @date 2025-05-19
 */
public class traffic extends BaseEntity
{
    private static final long serialVersionUID = 1L;

    /** 流量ID */
    @Excel(name = "流量ID")
    private Long trafficId;

    /** 源IP地址 */
    @Excel(name = "源IP地址")
    private String sourceIp;

    /** 目标IP地址 */
    @Excel(name = "目标IP地址")
    private String destinationIp;

    /** 流量时间 */
    @JsonFormat(pattern = "yyyy-MM-dd")
    @Excel(name = "流量时间", width = 30, dateFormat = "yyyy-MM-dd")
    private Date trafficTime;

    /** 威胁等级 */
    @Excel(name = "威胁等级")
    private String threatLevel;

    public void setTrafficId(Long trafficId) 
    {
        this.trafficId = trafficId;
    }

    public Long getTrafficId() 
    {
        return trafficId;
    }

    public void setSourceIp(String sourceIp) 
    {
        this.sourceIp = sourceIp;
    }

    public String getSourceIp() 
    {
        return sourceIp;
    }

    public void setDestinationIp(String destinationIp) 
    {
        this.destinationIp = destinationIp;
    }

    public String getDestinationIp() 
    {
        return destinationIp;
    }

    public void setTrafficTime(Date trafficTime) 
    {
        this.trafficTime = trafficTime;
    }

    public Date getTrafficTime() 
    {
        return trafficTime;
    }

    public void setThreatLevel(String threatLevel) 
    {
        this.threatLevel = threatLevel;
    }

    public String getThreatLevel() 
    {
        return threatLevel;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this,ToStringStyle.MULTI_LINE_STYLE)
            .append("trafficId", getTrafficId())
            .append("sourceIp", getSourceIp())
            .append("destinationIp", getDestinationIp())
            .append("trafficTime", getTrafficTime())
            .append("threatLevel", getThreatLevel())
            .toString();
    }
}
