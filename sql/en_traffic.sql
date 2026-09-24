-- 恶意流量信息表
DROP TABLE IF EXISTS `malicious_traffic`;
CREATE TABLE `malicious_traffic` (
                                     `traffic_id` BIGINT(20) NOT NULL AUTO_INCREMENT COMMENT '流量ID',
                                     `source_ip` VARCHAR(128) DEFAULT '' COMMENT '源IP地址',
                                     `destination_ip` VARCHAR(128) DEFAULT '' COMMENT '目标IP地址',
                                     `traffic_time` DATETIME COMMENT '流量时间',
                                     `threat_level` VARCHAR(20) DEFAULT '' COMMENT '威胁等级',
                                     PRIMARY KEY (`traffic_id`)
) ENGINE=INNODB AUTO_INCREMENT=1 COMMENT='恶意流量信息表';

-- 检测规则表
DROP TABLE IF EXISTS `detection_rule`;
CREATE TABLE `detection_rule` (
                                  `rule_id` BIGINT(20) NOT NULL AUTO_INCREMENT COMMENT '规则ID',
                                  `rule_name` VARCHAR(100) DEFAULT '' COMMENT '规则名称',
                                  `rule_content` TEXT COMMENT '规则内容',
                                  `create_time` DATETIME COMMENT '创建时间',
                                  PRIMARY KEY (`rule_id`)
) ENGINE=INNODB AUTO_INCREMENT=1 COMMENT='检测规则表';

-- 科研成果表
DROP TABLE IF EXISTS `research_result`;
CREATE TABLE `research_result` (
                                   `result_id` BIGINT(20) NOT NULL AUTO_INCREMENT COMMENT '成果ID',
                                   `result_name` VARCHAR(200) DEFAULT '' COMMENT '成果名称',
                                   `result_content` TEXT COMMENT '成果内容',
                                   `publish_time` DATETIME COMMENT '发布时间',
                                   PRIMARY KEY (`result_id`)
) ENGINE=INNODB AUTO_INCREMENT=1 COMMENT='科研成果表';