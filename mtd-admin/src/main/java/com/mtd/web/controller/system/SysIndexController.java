package com.mtd.web.controller.system;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.mtd.common.config.MtdConfig;
import com.mtd.common.utils.StringUtils;

/**
 * 首页
 *
 */
@RestController
public class SysIndexController
{
    /** 系统基础配置 */
    @Autowired
    private MtdConfig mtdConfig;

    /**
     * 访问首页，提示语
     */
    @RequestMapping("/")
    public String index()
    {
        return StringUtils.format("{}服务运行中，当前版本：v{}。", mtdConfig.getName(), mtdConfig.getVersion());
    }
}
