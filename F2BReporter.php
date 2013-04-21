<?php
$q = null;
include 'F2BReporter_cfg.php';
class F2BanReporter {
	 protected $authlog;
	 protected $banlog;
	 protected $cfg;
	 protected $reports;
	 public function __construct($cfg) {
	 	$this->cfg = $cfg;
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
	 	$banned = $this->parseBanLog($this->cfg['banlog']);
	 	$this->parseAuthLog($this->cfg['authlog'], $banned);
	 	foreach ($this->reports as &$r) {
	 		$r['abusemailbox'] = $this->getAbuseMailboxByIp($r['ip']);
	 	}
	 	return $this->reports;
	 }
	 public function parseAuthLog($path, $banned) {
	 	$authlog = new F2BanAuthLog($path, $this);
	 	$authlog->setBanned($banned);
	 	$authlog->readAll();
	 }
	 public function parseBanLog($path) {
	 	$banlog = new F2BanLog($path, $this);
	 	$banlog->readAll();
	 	return $banlog->getBanned();
	 }
}
class F2BanAuthLog extends F2BanReporterLogReader {
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
class F2BanLog extends F2BanReporterLogReader {
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
	$q();
}