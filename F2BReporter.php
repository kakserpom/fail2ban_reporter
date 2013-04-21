<?php
$q = null;
include 'F2BReporter_cfg.php';
class F2BanReporter {
	 protected $authlog;
	 protected $banlog;
	 protected $cfg;
	 protected $reports;
	 protected $logs = array();
	 public function __construct($cfg) {
	 	$this->cfg = $cfg;
	 	$jailconf = file_get_contents($this->cfg['jailconf']);
	 	$self = $this;
	 	preg_replace_callback('~^\s*(?:\[(.+?)\]|logpath\s*=\s*(.+?))(?=#|$)~m', function ($m) use ($self, &$section) {
	 		if ($m[1] !== '') {
	 			$section = $m[1];
	 			return;
	 		}
	 		if ($section === null) {
	 			return;
	 		}
	 		$path = $m[2];
	 		$glob = glob($path);
	 		if (empty($glob)) {
	 			return;
	 		}
	 		if (!isset($self->logs[$section])) {
	 			$self->logs[$section] = $glob;
	 		} else {
	 			$self->logs[$section] = array_merge($self->logs[$section], $glob);
	 		}
	 	}, $jailconf);
	 }
	 public function renderTemplate($r, $tpl) {
	 	$self = $this;
	 	$body = preg_replace_callback('~%(IP|LOG|SERVERIP)%~', function ($m) use ($r, $self) {
	 		$t = $m[1];
	 		if ($t === 'IP') {
	 			return $r['ip'];
	 		}
	 		if ($t === 'LOG') {
	 			return implode("\n", $r['entries']);
	 		}
	 		if ($t === 'SERVERIP') {
	 			return $self->cfg['serverip'];
	 		}
	 	}, $tpl);
		return $body;
	 }
	 public function send() {
	 	foreach ($this->getReports() as $r) {
	 		$email = $r['abusemailbox'] ?: $this->cfg['defaultemail'];
	 		$subject = $this->renderTemplate($r, $this->cfg['subject']);
			$body = $this->renderTemplate($r, $this->cfg['body']);
			call_user_func($this->cfg['mailfunction'], $email, $subject, $body);
		}
	 }
	 public function addLogLine($ip, $line) {
	 	if (!isset($this->reports[$ip])) {
	 		$this->reports[$ip] = array(
	 			'ip' => $ip,
	 			'entries' => array()
	 		);
	 	}
	 	$this->reports[$ip]['entries'][] = $line;
	 }
	 public function getAbuseMailboxByIp($ip) {
	 	$o = file_get_contents('http://apps.db.ripe.net/whois/search.xml?query-string=' . $ip . '&source=ripe');
	 	if (!preg_match('~<attribute name="abuse-mailbox" value="(.*?)"/>~', $o, $m)) {
	 		return false;
	 	}
	 	return $m[1];
	 }
	 public function getReports() {
	 	$banned = array();
	 	if (!isset($this->logs['recidive'])) {
	 		throw new Exception('No recive files. Abort.');
	 	}
	 	foreach ($this->logs['recidive'] as $recidive) {
	 		$banned = array_merge($banned, $this->parseRecidiveLog($recidive));
	 	}
	 	foreach ($this->logs as $service => $pathes) {
	 		foreach ($pathes as $path) {
	 			$this->parseAccessLog($service, $path, $banned);
	 		}
	 	}
	 	foreach ($this->reports as &$r) {
	 		$r['abusemailbox'] = $this->getAbuseMailboxByIp($r['ip']);
	 	}
	 	return $this->reports;
	 }
	 public function parseAccessLog($service, $path, $banned) {
	 	if ($service === 'recidive') {
	 		return;
	 	}
	 	$log = new F2BLogAccessLog($path, $this);
	 	$log->setBanned($banned);
	 	$log->readAll();
	 }
	 public function parseRecidiveLog($path) {
	 	$banlog = new F2BLogRecidive($path, $this);
	 	$banlog->readAll();
	 	return $banlog->getBanned();
	 }
}
class F2BLogAccessLog extends F2BanReporterLogReader {
	protected $banned;
	protected function onLine($line) {
		if (!preg_match('~(?<=\W|^)\d+\.\d+\.\d+\.\d+(?=\W|$)~', $line, $m)) {
			return;
		}
		$ip = $m[0];
		if (!in_array($ip, $this->banned, true)) {
			return;
		}
		$this->parent->addLogLine($ip, $line);
	}
	public function setBanned($banned) {
		$this->banned = $banned;
	}
}
class F2BLogRecidive extends F2BanReporterLogReader {
	protected $banned = array();
	protected function onLine($line) {
		if (!preg_match('~^(\S+\s+\S+)\s+([\w+\.]+): WARNING \[ssh-ipfw\] Ban (.*)$~', $line, $m)) {
			return;
		}
		$this->banned[] = $m[3];
	}
	public function getBanned() {
		return $this->banned;
	}
}
abstract class F2BanReporterLogReader {

	/** 
	 * Parent
	 * @var object
	 */
	protected $parent;

	/** 
	 * Intenal buffer
	 * @var string
	 */
	protected $buf = '';

	/** 
	 * Path
	 * @var string
	 */
	protected $path = '';

	/** 
	 * File descriptor
	 * @var resource
	 */
	protected $fp;

	/** 
	 * Counter
	 * @var integer
	 */
	protected $count = 0;

	/** 
	 * Constructor
	 * @return void
	 */
	public function __construct($path, $parent) {
		$this->parent = $parent;
		$this->path = $path;
		$this->fp = fopen($this->path, 'r');
	}

	public function readAll() {
		while ($this->fp) {
			$l = fgets($this->fp);
			if ($l === false) {
				break;
			}
			$this->onLine($l);
		}
	}

	protected function onLine($line) {

	}
}
if ($q) {
	try {
		$q();
	} catch (Exception $e) {
		echo $e->getMessage() . PHP_EOL;
	}
}