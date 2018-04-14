
-- SWEF PLUGIN REGISTRATION --

INSERT IGNORE INTO `swef_config_plugin`
    (
      `plugin_Dash_Allow`, `plugin_Dash_Usergroup_Preg_Match`, `plugin_Enabled`,
    `plugin_Context_LIKE`, `plugin_Classname`, `plugin_Handle_Priority`
  )
  VALUES
    ( 0, '', 0, 'api', '\\Swef\\SwefSecurity', 3 ),
    ( 1, '<^sysadmin$>', 0, 'dashboard', '\\Swef\\SwefSecurity', 3 ),
    ( 0, '', 0, 'www-%', '\\Swef\\SwefSecurity', 3 );


-- SWEFSECURITY PROCEDURES --

DELIMITER $$

DROP PROCEDURE IF EXISTS `swefSecurityScansLoad`$$
CREATE PROCEDURE `swefSecurityScansLoad`()
BEGIN
  SELECT `scan_Variable` AS `variable`
        ,`scan_Variable_2` AS `variable_2`
        ,`scan_History_Length_Seconds` AS `history_length`
        ,`scan_Store_Lines_Per_Value` AS `store_lines`
        ,`scantime_Hits_Max` AS `hits_max`
        ,`scantime_Time_Seconds` AS `time`
        ,`scantime_Mitigation` AS `mitigation_time`
        ,`scantime_Alert` AS `alert_time`
        ,`scantime_Notification` AS `notification_time`
        ,`scanmatch_Match_Var` AS `match_var`
        ,`scanmatch_Compare_Operator` AS `compare_operator`
        ,`scanmatch_Persistence_Seconds` AS `persistence`
        ,`scanmatch_Mitigation` AS `mitigation_match`
        ,`scanmatch_Alert` AS `alert_match`
        ,`scanmatch_Notification` AS `notification_match`
  FROM `swefsecurity_scan`
  LEFT JOIN `swefsecurity_scantime`
         ON `scantime_Variable`=`scan_Variable`
  LEFT JOIN `swefsecurity_scanmatch`
         ON `scanmatch_Variable`=`scan_Variable`
  ORDER BY `scan_Priority`,`scantime_Time_Seconds`,`scanmatch_Match_Var`;
END$$

DELIMITER ;


-- SWEFSECURITY TABLES --

DROP TABLE IF EXISTS `swefsecurity_scan`;
CREATE TABLE `swefsecurity_scan` (
  `scan_Priority` int(11) unsigned NOT NULL,
  `scan_Variable` varchar(64) CHARACTER SET ascii NOT NULL,
  `scan_History_Length_Seconds` int(11) unsigned NOT NULL,
  `scan_Variable_2` varchar(64) CHARACTER SET ascii NOT NULL,
  `scan_Store_Lines_Per_Value` int(11) unsigned NOT NULL DEFAULT '64',
  PRIMARY KEY (`scan_Variable`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `swefsecurity_scan` (`scan_Priority`, `scan_Variable`, `scan_History_Length_Seconds`, `scan_Variable_2`, `scan_Store_Lines_Per_Value`) VALUES
(1, '$_POST[\'JSON\']', 20, '$_SERVER[\'REMOTE_ADDR\']',  64),
(1, '$_POST[\'sweflogin-email\']',  3600, '', 64),
(2, '$_POST[\'sweflogin-password\']', 3600, '', 64),
(0, '$_SERVER[\'REMOTE_ADDR\']',  60, '', 64);

DROP TABLE IF EXISTS `swefsecurity_scanmatch`;
CREATE TABLE `swefsecurity_scanmatch` (
  `scanmatch_Variable` varchar(64) CHARACTER SET ascii NOT NULL,
  `scanmatch_Match_Var` varchar(64) CHARACTER SET ascii NOT NULL,
  `scanmatch_Compare_Operator` varchar(64) CHARACTER SET ascii NOT NULL,
  `scanmatch_Persistence_Seconds` int(11) unsigned NOT NULL,
  `scanmatch_Mitigation` varchar(64) CHARACTER SET ascii NOT NULL,
  `scanmatch_Alert` int(1) unsigned NOT NULL,
  `scanmatch_Notification` varchar(255) NOT NULL,
  `scanmatch_Description` varchar(255) NOT NULL,
  PRIMARY KEY (`scanmatch_Variable`,`scanmatch_Match_Var`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `swefsecurity_scanmatch` (`scanmatch_Variable`, `scanmatch_Match_Var`, `scanmatch_Compare_Operator`, `scanmatch_Persistence_Seconds`, `scanmatch_Mitigation`, `scanmatch_Alert`, `scanmatch_Notification`, `scanmatch_Description`) VALUES
('$_POST[\'sweflogin-email\']', '$_SERVER[\'REMOTE_ADDR\']',  '!=', 60, 'unset',  1,  'Login failed - please try again',  'Login email posts from different IP addresses within 60 seconds');

DROP TABLE IF EXISTS `swefsecurity_scantime`;
CREATE TABLE `swefsecurity_scantime` (
  `scantime_Variable` varchar(64) CHARACTER SET ascii NOT NULL,
  `scantime_Hits_Max` int(11) unsigned NOT NULL,
  `scantime_Time_Seconds` int(11) unsigned NOT NULL,
  `scantime_Mitigation` varchar(64) CHARACTER SET ascii NOT NULL,
  `scantime_Alert` int(1) unsigned NOT NULL,
  `scantime_Notification` varchar(255) NOT NULL,
  `scantime_Description` varchar(255) NOT NULL,
  PRIMARY KEY (`scantime_Variable`,`scantime_Time_Seconds`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `swefsecurity_scantime` (`scantime_Variable`, `scantime_Hits_Max`, `scantime_Time_Seconds`, `scantime_Mitigation`, `scantime_Alert`, `scantime_Notification`, `scantime_Description`) VALUES
('$_POST[\'JSON\']',  10, 10, 'die',  1,  'Too many request from this IP address',  'Too many API posts for a given REMOTE_ADDR in 1 second'),
('$_POST[\'sweflogin-email\']', 2,  2,  'unset',  0,  'Login failed - please try again',  'Too many login posts for this email address in 2 seconds'),
('$_POST[\'sweflogin-email\']', 3,  600,  'unset',  1,  'Login failed - please try again',  'Too many login posts for this email in 10 minutes'),
('$_POST[\'sweflogin-password\']',  2,  2,  'unset',  0,  '', 'Too many login posts of this password in 2 seconds'),
('$_POST[\'sweflogin-password\']',  10, 600,  'unset',  0,  '', 'Too many login posts of this password in 10 minutes'),
('$_SERVER[\'REMOTE_ADDR\']', 5,  2,  'die',  0,  '', 'Too many requests from this IP address in 2 seconds'),
('$_SERVER[\'REMOTE_ADDR\']', 20, 60, 'die',  1,  '', 'Too many requests from this IP address in 1 minute');
