<?php $q = function () {
	
$f2b = new F2BanReporter(array(
	'authlog'	=> 'auth.log',
	'banlog'	=> 'fail2ban.log',
	'defaultemail'	=> 'abuse@localhost',
	'serverip' => trim(file_get_contents('http://wtfismyip.com/text')),
	'subject' => "[FAIL2BAN REPORT] %IP% from your network attacked us (%SERVERIP%)!",
	'body' => "Hello! Our server (%SERVERIP%) banned %IP% for intrusion attempt:\n%LOG%\n",
	//'mailfunction' => 'mail', /* Uncomment this*/
	/* Comment this line */ 'mailfunction' => function($to, $subject, $body) {var_dump(array($to, $subject, $body));},
));
$f2b->send();

};