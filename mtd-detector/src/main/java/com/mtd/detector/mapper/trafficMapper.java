package com.mtd.detector.mapper;

import java.util.List;
import com.mtd.detector.domain.traffic;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

/**
 * 恶意流量信息Mapper接口
 * 
 * @author lixu
 * @date 2025-05-19
 */
@Mapper
public interface trafficMapper 
{
    /**
     * 查询恶意流量信息
     * 
     * @param trafficId 恶意流量信息主键
     * @return 恶意流量信息
     */
    public traffic selecttrafficByTrafficId(Long trafficId);

    /**
     * 查询恶意流量信息列表
     * 
     * @param traffic 恶意流量信息
     * @return 恶意流量信息集合
     */
    public List<traffic> selecttrafficList(traffic traffic);

    /**
     * 新增恶意流量信息
     * 
     * @param traffic 恶意流量信息
     * @return 结果
     */
    public int inserttraffic(traffic traffic);

    /**
     * 修改恶意流量信息
     * 
     * @param traffic 恶意流量信息
     * @return 结果
     */
    public int updatetraffic(traffic traffic);

    /**
     * 删除恶意流量信息
     * 
     * @param trafficId 恶意流量信息主键
     * @return 结果
     */
    public int deletetrafficByTrafficId(Long trafficId);

    /**
     * 批量删除恶意流量信息
     * 
     * @param trafficIds 需要删除的数据主键集合
     * @return 结果
     */
    public int deletetrafficByTrafficIds(Long[] trafficIds);
//
//    @Select("SELECT * FROM your_traffic_table_name WHERE traffic_id = #{trafficId}")
//    traffic selectTrafficById(Long trafficId);

}
