<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;
use Illuminate\Support\Facades\Log;
/**
 * Class Nfoservers
 * @package AbuseIO\Parsers
 */
class Nfoservers extends Parser
{
    /**
     * Create a new Nfoservers instance
     *
     * @param \PhpMimeMailParser\Parser $parsedMail phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse body
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        /**
         *  There is no attached report, the information is all in the mail body
         */
        $this->feedName = 'default';
        $body = $this->parsedMail->getMessageBody();
        $subject = $this->parsedMail->getHeader('subject');
        if ($this->isKnownFeed() && $this->isEnabledFeed()) {
            if (preg_match('/(.+)used for an attack: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/',$subject,$matches)){
                $type = trim($matches[1]);
                $report = [ 
                    'Source-IP' => $matches[2],
                    'Type' => $type,
                ];   
                if (preg_match('/Date\/timestamps \(far left\) are UTC\.(.*)\(The final octet of our customer/s', $body,$evidence_matches)){
                    $report['evidence'] = $evidence_matches[1];                  
                }    
                $received = $this->parsedMail->getHeaders()['date'];
                if (strtotime(date('d-m-Y H:i:s', strtotime($received))) !== (int)strtotime($received)) {
                    $received = date('d-m-Y H:i:s');
                }
                $report['Received-Date'] = $received;
                switch($type) {
                    case 'Open recursive resolver':
                        $this->feedName = 'dns_resolver';
                        break;
                    case 'Exploitable NTP server':
                        $this->feedName = 'ntp_server';
                        break;
                    case 'Compromised host':
                        $this->feedName = 'compromised_host';
                        break;
                    case 'Exploitable portmapper service':
                        $this->feedName = 'portmapper';
                        break;
                    case 'Exploitable chargen service':
                        $this->feedName = 'chargen';
                        break;
                    case 'Exploitable SSDP server':
                        $this->feedName = 'ssdp';
                        break;
                    default:
                        $this->feedName = 'default'; 
                }
            }
            if ($this->hasRequiredFields($report) === true) {
                $report = $this->applyFilters($report);
                $incident = new Incident();
                $incident->source      = config("{$this->configBase}.parser.name");
                $incident->source_id   =false;
                $incident->ip          =$report['Source-IP'];
                $incident->domain      =false;
                $incident->class       =config("{$this->configBase}.feeds.{$this->feedName}.class");
                $incident->type        =config("{$this->configBase}.feeds.{$this->feedName}.type");
                $incident->timestamp   =strtotime($report['Received-Date']);
                $incident->information =json_encode($report);
                $this->incidents[] = $incident;
            }    
        }
        return $this->success();
    }
}
