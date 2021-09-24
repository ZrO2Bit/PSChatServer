CREATE TABLE `message` (
  `roomid` varchar(16) DEFAULT NULL,
  `userid` varchar(16) DEFAULT NULL,
  `content` text,
  `timestamp` varchar(13) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `user` (
  `userid` varchar(16) DEFAULT NULL,
  `pwd` varchar(32) DEFAULT NULL,
  `username` text
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `userrel` (
  `targetuser` varchar(16) DEFAULT NULL,
  `sourceuser` varchar(16) DEFAULT NULL,
  `status` varchar(1) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;