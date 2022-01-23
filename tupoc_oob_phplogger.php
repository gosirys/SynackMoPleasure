<?php

/*
Title: OOB HTTP Request logger for TuPOC with Discord notification
Author: by Osirys

What this script does:
	This PHP script will fetch the entire HTTP request from the client, store
	the results in the logs, and send you a notification over Discord

How to use this:
	Once all is setup, you can test it out this way:
		https://youruser.x1.pe/path_to_this_script/yoob-log-notify.php?label=<UNIQUE_ID_CODENAME>

	the label is to help you identify which request/function you tested
	label doesn't have to be there, you can also omit it.

	If you have a SSRF (HTTP) on a target and RoE only allows TuPOC,
	you can do the following:
		http://vuln.target/page?ssrf=https://youruser.x1.pe/path_to_this_script/yoob-log-notify.php?label=TestingPageSSRF

How to set this up:

	Compile notify (Project Discovery) on your computer,
	then upload it in a folder under your $_SERVER['HOME']
	within TuPOC. Don't forget to chmod+x it
	As per notify's docs, create your config file and also
	place it within your $_SERVER['HOME']

	Then put as per below:
		1. notify's binary path 
		2. notify's yaml config path

	Then, create a folder in the directory where you will put this script
	for storing interaction logs, and set its value below.
	Make sure PHP has write access to it.

*/

$notify_bin_path="/osyfgfdghjdj/notify";
$notify_yaml_path="/osyfgfdghjdj/notify_config.yaml";
$oob_logs_path="/oob_logs_whatever/";

function myshellexec($cfe) {
	$res = '';
	if (!empty($cfe)) {

		if (@function_exists('passthru')) {
			@ob_start();
			@passthru($cfe);
			$res = @ob_get_contents();
			@ob_end_clean();
		}
		elseif (@function_exists('exec')) {
			@exec($cfe,$res);
			$res = join("\n",$res);
		}
		elseif (@function_exists('shell_exec')) {
			$res = @shell_exec($cfe);
		}
		elseif (@function_exists('system')) {
			@ob_start();
			@system($cfe);
			$res = @ob_get_contents();
			@ob_end_clean();
		}
		elseif (@is_resource($f = @popen($cfe,"r"))) {
			$res = "";
			if (@function_exists('fread') &&@function_exists('feof')) {
				while (!@feof($f)) {
					$res .= @fread($f,1024);
				}
			}
			elseif (@function_exists('fgets') &&@function_exists('feof')) {
				while(!@feof($f)) {
					$res .= @fgets($f,1024);
				}
			}
			@pclose($f);
		}
		elseif (@is_resource($f = @proc_open($cfe,array(1 =>array("pipe","w")),$pipes))) {
			$res = "";
			if(@function_exists('fread') &&@function_exists('feof')) {
				while(!@feof($pipes[1])) {
					$res .= @fread($pipes[1],1024);
				}
			}
			elseif (@function_exists('fgets') &&@function_exists('feof')) {
				while(!@feof($pipes[1])) {
					$res .= @fgets($pipes[1],1024);
				}
			}
			@proc_close($f);
		}
		// see: https://github.com/mm0r1/exploits/blob/master/php-filter-bypass/exploit.php
		elseif(@function_exists('pwn')) {
			@ob_start();
			pwn($cfe);
			$res = @ob_get_contents();
			@ob_end_clean();
		}
	}
	return $res;
}


function getIPAddress() {  
	//whether ip is from the share internet  
	 if (!empty($_SERVER['HTTP_CLIENT_IP'])) {  
		$ip = $_SERVER['HTTP_CLIENT_IP'];  
	}  
	//whether ip is from the proxy  
	elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {  
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];  
	}  
	//whether ip is from the remote address  
	else {  
		$ip = $_SERVER['REMOTE_ADDR'];  
	}  
	return $ip;  
}  

function logRequest($targetFile,$oob_notification_filename,$label){
	$headerList = [];
	foreach ($_SERVER as $name => $value) {

		if (preg_match('/^HTTP_/',$name)) {
		// convert HTTP_HEADER_NAME to Header-Name

			$name = strtr(substr($name,5),'_',' ');
			$name = ucwords(strtolower($name));
			$name = strtr($name,' ','-');
			$headerList[$name] = $value;
		}
	}

	$data = sprintf("%s %s %s\n", $_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI'], $_SERVER['SERVER_PROTOCOL']);

	foreach ($headerList as $name => $value) {
		$data .= $name.': '.$value."\n";
	}

	$data .= "\n";
	
	$time_request_inbound=date('Y-m-d H:i:s', $_SERVER['REQUEST_TIME']);
	$victim=getIPAddress();

	$final_content="\nIncoming HTTP request from ".$victim." at ".$time_request_inbound.
					" UTC\nRaw HTTP request dump:\n\n".$data.file_get_contents('php://input');
	
	file_put_contents($targetFile, $final_content."\n");

	$label_str="\n";
	if (strlen($label) > 0) {
		
		$label=filter_var($label,FILTER_SANITIZE_STRING);
		$label_str="\nLabel used: *".$label."*\n";
	}

	$not_str="**OOB just triggered on TuPOC**".$label_str."Check log file: *".basename($targetFile)."*\n";
	file_put_contents($oob_notification_filename,$not_str);
	
	$cmd=$_SERVER['HOME'].$notify_bin_path." -id notify -provider discord -provider-config ".
	$_SERVER['HOME'].$notify_yaml_path." -rl 1 -bulk -data ".$oob_notification_filename;
	
	$output=myshellexec($cmd." 2>&1");

}

$label='';
if (isset($_GET['label'])) {
	$label=$_GET['label'];
}

$filename=".".$oob_logs_path."post-".time().".log";
$oob_notification_filename=".".$oob_logs_path."notification_summary-".time().".log";
logRequest($filename,$oob_notification_filename,$label);

?>
