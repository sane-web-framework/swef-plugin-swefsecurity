<?php

namespace Swef;

class SwefSecurity extends \Swef\Bespoke\Plugin {

    public  $criticals        = array ();
    public  $directoriseChars = array ();
    public  $warnings         = array ();
    public  $notices          = array ();
    public  $notifications    = array ();
    public  $scans            = array ();        // Look-up table of hit scans and mitigations

    public function __construct ($page) {
        // Always construct the base class - PHP does not do this implicitly
        parent::__construct ($page,'\Swef\SwefSecurity');
        // Ensure swefsecurity_log_dir_scan exists
            if (!is_dir(swefsecurity_log_dir_scan)) {
                if (!mkdir(swefsecurity_log_dir_scan,SWEF_CHMOD_DIR)) {
                    array_push ($this->criticals,'Failed to make directory "'.swefsecurity_log_dir_scan.'"');
                    $this->page->diagnosticAdd ('Failed to make directory "'.swefsecurity_log_dir_scan.'"');
                    $this->die ();
                }
            }
        // Load scan configuration
        $this->scansLoad ();
        // Secure connection warnings
        $this->https ();
        // Session notices and warnings
        if (ini_get('session.use_strict_mode')!='On') {
            array_push ($this->criticals,'session.use_strict_mode is not On');
        }
        if (ini_get('session.cookie_lifetime')!=0) {
            array_push ($this->warnings,'session.cookie_lifetime is not 0');
        }
        if (ini_get('session.use_cookies')!='On') {
            array_push ($this->warnings,'session.use_cookies is not On');
        }
        if (ini_get('session.use_only_cookies')!='On') {
            array_push ($this->warnings,'session.use_only_cookies is not On');
        }
        if (ini_get('session.cookie_httponly')!='On') {
            array_push ($this->warnings,'session.cookie_httponly is not On');
        }
        if (ini_get('session.cookie_secure')!='On') {
            array_push ($this->warnings,'session.cookie_secure is not On');
        }
        if (ini_get('session.use_trans_sid')!='Off') {
            array_push ($this->warnings,'session.use_trans_sid is not Off');
        }
        if (ini_get('session.cache_limiter')!='nocache') {
            array_push ($this->warnings,'session.cache_limiter is not nocache');
        }
        array_push ($this->notices,'session.gc_maxlifetime='.ini_get('session.gc_maxlifetime'));
        array_push ($this->notices,'session.gc_probability='.ini_get('session.gc_probability'));
        array_push ($this->notices,'session.gc_divisor='.ini_get('session.gc_divisor'));
        array_push ($this->notices,'session.sid_length='.ini_get('session.sid_length'));
        array_push ($this->notices,'session.sid_bits_per_character='.ini_get('session.sid_bits_per_character'));
        array_push ($this->notices,'session.hash_function='.ini_get('session.hash_function'));
        // Scan file construction
        $this->directoriseChars     = explode (SWEF_STR__COMMA,swefsecurity_scan_directorise_chars_csv);
    }

    public function __destruct ( ) {
        // Always destruct the base class - PHP does not do this implicitly
        parent::__destruct ( );
    }

    public function _on_pluginsSetAfter ( ) {
        $this->expireSession ();
        $this->scan ();
    }

    public function _on_pageTemplateBefore ( ) {
        foreach ($this->notifications as $msg) {
            $this->notify ($msg);
            $this->page->diagnosticAdd ($msg);
        }
        return SWEF_BOOL_TRUE;
    }

    public function _on_pushAfter ( ) {
        $this->log ();
    }

    public function die ($msg=SWEF_STR__EMPTY) {
        while (ob_get_level()) {
            ob_end_clean ();
        }
        if (SWEF_DIAGNOSTIC) {
            $this->page->diagnosticOutput ();
        }
        else {
            $msg = SWEF_STR__EMPTY;
        }
        $this->page->swef->statusHeader (SWEF_HTTP_STATUS_CODE_420);
        die ($msg);
    }

    public function directorise ($string) {
        foreach ($this->directoriseChars as $c) {
            $string                 = str_replace ($c,SWEF_STR__FSLASH.$c,$string);
        }
        return $string;
    }

    public function expireSession ( ) {
        $expire                     = $this->page->_SESSION (SWEF_STR_START);
        $expire                    .= ini_get ('session.gc_maxlifetime');
        if ($this->page->swef->moment->unix()>$expire) {
            $this->log ('Expired session '.session_id().SWEF_STR__CRLF);
            $_SESSION               = array ();
            setcookie (session_name(),SWEF_STR__EMPTY);
            header ('Location: '.$_SERVER[REQUEST_URI]);
            exit;
        }
    }

    public function https ( ) {
        if (!array_key_exists('HTTPS',$_SERVER)) {
            array_push ($this->criticals,'Connection is not encrypted - $_SERVER[HTTPS] is not set');
            return SWEF_BOOL_FALSE;
        }
        if (empty($_SERVER['HTTPS'])) {
            array_push ($this->criticals,'Connection is not encrypted - $_SERVER[HTTPS]=');
            return SWEF_BOOL_FALSE;
        }
        if ($_SERVER['HTTPS']=='off') {
            array_push ($this->criticals,'Connection is not encrypted - $_SERVER[HTTPS]=off');
            return SWEF_BOOL_FALSE;
        }
        if ($_SERVER['SERVER_PORT']=='80') {
            array_push ($this->warnings,'Connection is on port 80 - is this really encrypted?');
            return SWEF_BOOL_FALSE;
        }
        if ($_SERVER['SERVER_PORT']!='443') {
            array_push ($this->warnings,'Connection is on port '.$_SERVER['SERVER_PORT'].' - is this really encrypted?');
        }
        return SWEF_BOOL_TRUE;
    }

    public function log ($info=null) {
        $this->page->diagnosticAdd ('SwefSecurity general log "'.swefsecurity_log.'"');
        if (is_readable(swefsecurity_log)){
            $this->page->diagnosticAdd ('Log file is readable so will use '.SWEF_F_APPEND);
            $mode           = SWEF_F_APPEND;
        }
        else {
            $this->page->diagnosticAdd ('Log file is not readable so will use '.SWEF_F_WRITE);
            $mode           = SWEF_F_WRITE;
        }
        $log                    = array ();
        array_push ($log,SWEF_STR_DIAGNOSTIC_HR.SWEF_STR__CRLF);
        array_push ($log,$this->page->swef->moment->unix().SWEF_STR__SPACE.$this->page->swef->moment->server().SWEF_STR__CRLF);
        array_push ($log,$_SERVER['REMOTE_ADDR'].' --> '.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'].SWEF_STR__CRLF);
        if ($info) {
            array_push ($log,$info);
        }
        foreach ($this->criticals as $msg) {
            $this->page->diagnosticAdd ('CRITICAL: '.$msg);
            array_push ($log,'CRITICAL: '.$msg.SWEF_STR__CRLF);
        }
        foreach ($this->warnings as $msg) {
            $this->page->diagnosticAdd ('WARNING: '.$msg);
            if (swefsecurity_log_all) {
                array_push ($log,'WARNING: '.$msg.SWEF_STR__CRLF);
            }
        }
        foreach ($this->notices as $msg) {
            $this->page->diagnosticAdd ('NOTICE: '.$msg);
            if (swefsecurity_log_all) {
                array_push ($log,'NOTICE: '.$msg.SWEF_STR__CRLF);
            }
        }
        $fp                         = @fopen (swefsecurity_log,$mode);
        if ($fp) {
            $write                  = @fwrite ($fp,implode(SWEF_STR__EMPTY,$log));
            @fclose ($fp);
            @chmod (swefsecurity_log,SWEF_CHMOD_FILE);
        }
        if (!$write) {
            $this->page->diagnosticAdd ('Could not write to file "'.$logfile.'" - dying now [1]');
            $this->die ();
        }
    }

    public function scan ( ) {
        $now                            = $this->page->swef->moment->unix ();
        $this->page->diagnosticAdd ('now = '.$now);
        $scanned                        = array ();
        $expired                        = array ();
        foreach ($this->scans as $vname=>$scan) {
            $value                      = null;
            if ($scan[swefsecurity_col_variable_2]) {
                // Value of the variable whose name is the value of $scan[swefsecurity_col_variable_2]
                @eval ( '$value = '.$scan[swefsecurity_col_variable_2].';' );
                if (!strlen($value)) {
                    array_push ($this->warnings,'Scanned variable '.$scan[swefsecurity_col_variable_2].' had no value - ignored');
                    continue;
                }
            }
            else {
                // Value of the variable whose name is the value of $vname
                @eval ( '$value = '.$vname.';' );
                if (!strlen($value)) {
                    array_push ($this->warnings,'Scanned variable '.$vname.' had no value - ignored');
                    continue;
                }
            }
            // Name of file containing timestamps and match variable data for this variable
            $file                       = $vname.SWEF_STR__DOT.$value;
            $file                      .= SWEF_STR_EXT_LOG;
            $file                       = swefsecurity_log_dir_scan.'/'.$this->directorise($file);
            if (!is_dir(dirname($file))){
                if (!mkdir(dirname($file),SWEF_CHMOD_DIR,swefsecurity_scan_directorise_recurse)) {
                    array_push ($this->criticals,'Failed to make directory '.dirname($file));
                    continue;
                }
            }
            // Load and unserialize() the data
            $times                      = null;
            if (is_readable($file)) {
                $times                  = @unserialize (file_get_contents($file));
                if (is_array($times)) {
                    $times              = array_slice ($times,1-$scan[swefsecurity_col_store_lines]);
                }
            }
            if (!$times) {
                $times                  = array ();
            }
            // Decapitate data
            foreach ($times as $i=>$data) {
                if ($data[0]<($now-$scan[swefsecurity_col_history_length])) {
                    unset ($times[$i]);
                    continue;
                }
            }
            // Start scanning for a necessary mitigation
            $new                        = array ($now);
            $mitigate                   = null;
            $fail                       = null;
            $i                          = 0;
            foreach ($scan[swefsecurity_str_matches] as $match_var=>$m) {
                eval ( '$match = '.$match_var.';' );
                array_push ($new,$match);
                $i++;
                if ($fail || !count($times)) {
                    continue;
                }
                $time                   = $times[count($times)-1][0];
                if ($time<($now-$m[swefsecurity_col_persistence])) {
                    continue;
                }
                $val                = $times[count($times)-1][$i];
                $op                 = $m[swefsecurity_col_compare_operator];
                $eval               = 'if ($val'.$op.$match_var.') {
                                           $fail = SWEF_BOOL_TRUE;
                                       }';
                eval ($eval);
                if ($fail) {
                    $mitigate                                   = $scan;
                    $mitigate[swefsecurity_str_index]           = $match_var;
                    $mitigate[swefsecurity_str_type]            = swefsecurity_str_matches;
                    if ($m[swefsecurity_col_alert_match]) {
                        $mitigate[swefsecurity_str_log]         = $match_var;
                        $mitigate[swefsecurity_str_log]        .= SWEF_STR__COLON;
                        $mitigate[swefsecurity_str_log]        .= SWEF_STR__SPACE;
                        $mitigate[swefsecurity_str_log]        .= $match;
                        $mitigate[swefsecurity_str_log]        .= $op;
                        $mitigate[swefsecurity_str_log]        .= $val;
                        $mitigate[swefsecurity_str_log]        .= SWEF_STR__SPACE;
                        $mitigate[swefsecurity_str_log]        .= swefsecurity_col_persistence;
                        $mitigate[swefsecurity_str_log]        .= SWEF_STR__COLON;
                        $mitigate[swefsecurity_str_log]        .= $m[swefsecurity_col_persistence];
                        $mitigate[swefsecurity_str_log]        .= swefsecurity_str_secs;
                    }
                }
            }
            if (!$mitigate) {
                foreach ($scan[swefsecurity_str_times] as $time=>$t) {
                    $count              = 0;
                    foreach ($times as $data) {
                        if ($data[0]>=($now-$time)) {
                            $count++;
                        }
                        if ($count>=$t[swefsecurity_col_hits_max]) {
                            $mitigate                                   = $scan;
                            $mitigate[swefsecurity_str_index]           = $time;
                            $mitigate[swefsecurity_str_type]            = swefsecurity_str_times;
                            if ($t[swefsecurity_col_alert_time]) {
                                if ($scan[swefsecurity_col_variable_2] && strlen($value_2)) {
                                    $mitigate[swefsecurity_str_log]     = $scan[swefsecurity_col_variable_2];
                                    $mitigate[swefsecurity_str_log]    .= SWEF_STR__EQUALS;
                                    $mitigate[swefsecurity_str_log]    .= $value_2;
                                    $mitigate[swefsecurity_str_log]    .= SWEF_STR__SPACE;
                                }
                                $mitigate[swefsecurity_str_log]         = $t[swefsecurity_col_hits_max];
                                $mitigate[swefsecurity_str_log]        .= swefsecurity_str_hits;
                                $mitigate[swefsecurity_str_log]        .= SWEF_STR__FSLASH;
                                $mitigate[swefsecurity_str_log]        .= $time;
                                $mitigate[swefsecurity_str_log]        .= swefsecurity_str_secs;
                                $mitigate[swefsecurity_str_log]        .= SWEF_STR__SPACE;
                                $mitigate[swefsecurity_str_log]        .= swefsecurity_str_exceeded;
                            }
                            break 2;
                        }
                    }
                }
            }
            array_push ($times,$new);
            $write                  = null;
            $fp                     = @fopen ($file,SWEF_F_WRITE);
            if ($fp) {
                $write              = @fwrite ($fp,serialize($times));
                @fclose ($fp);
                @chmod ($file,SWEF_CHMOD_FILE);
            }
            if (!$write) {
                array_push ($this->criticals,'Could not write to file "'.$file.'" [2]');
            }
            @chmod ($file,SWEF_CHMOD_FILE);
            if ($mitigate) {
                $mitigate[swefsecurity_str_file] = $file;
                $this->scanMitigate ($mitigate);
            }
        }
    }

    public function scanAlert ($scan) {
        $logfile            = realpath (swefsecurity_alert_log);
        if (!$logfile) {
            $logfile        = swefsecurity_alert_log;
        }
        if (is_readable($logfile)){
            $this->page->diagnosticAdd ('Alert log file is readable so will use '.SWEF_F_APPEND);
            $mode           = SWEF_F_APPEND;
        }
        else {
            $this->page->diagnosticAdd ('Alert log file is not readable so will use '.SWEF_F_WRITE);
            $mode           = SWEF_F_WRITE;
        }
        $log                = SWEF_STR_DIAGNOSTIC_HR.SWEF_STR__CRLF;
        $log               .= $this->page->swef->moment->unix().SWEF_STR__SPACE;
        $log               .= $this->page->swef->moment->server().SWEF_STR__CRLF;
        $log               .= $scan[swefsecurity_col_variable].SWEF_STR__SPACE;
        $log               .= $scan[swefsecurity_str_log].SWEF_STR__CRLF;
        $fp                 = fopen ($logfile,$mode);
        if ($fp) {
            $write          = fwrite ($fp,$log);
            @fclose ($fp);
            @chmod ($logfile,SWEF_CHMOD_FILE);
        }
        if (!$write) {
            $this->page->diagnosticAdd ('Could not write to file "'.$logfile.'" - dying now [3]');
            $this->die ();
        }
    }

    public function scanMitigate ($scan) {
        if ($scan[swefsecurity_str_type]==swefsecurity_str_matches) {
            $m              = $scan[swefsecurity_str_matches][$scan[swefsecurity_str_index]];
            $mitigation     = $m[swefsecurity_col_mitigation_match];
            $notification   = $m[swefsecurity_col_notification_match];
        }
        else {
            $t              = $scan[swefsecurity_str_times][$scan[swefsecurity_str_index]];
            $mitigation     = $t[swefsecurity_col_mitigation_time];
            $notification   = $t[swefsecurity_col_notification_time];
        }
        if ($scan[swefsecurity_str_log]) {
            $this->scanAlert ($scan);
        }
        if ($mitigation==swefsecurity_str_unset) {
            if ($notification) {
                $this->notify ($notification);
            }
            eval ( 'unset ('.$scan[swefsecurity_col_variable].');' );
            return;
        }
        if ($mitigation==swefsecurity_str_die) {
            $this->die ($notification);
        }
        return;
    }

    public function scansLoad ($force=null) {
        if (SWEF_CONFIG_STORE_LOOKUP_FILES && !$force) {
            $file               = swefsecurity_str_scans.SWEF_STR_EXT_VAR;
            $scans              = $this->page->swef->lookupFileGet ($file);
            if (is_array($scans)) {
                $this->page->diagnosticAdd ('Got scans from file inclusion');
                $this->scans    = $scans;
                return;
            }
        }
        $this->page->diagnosticAdd ('Getting scans from database');
        $scans                  = $this->page->swef->db->dbCall (swefsecurity_call_scansload);
        if (!is_array($scans)) {
            array_push ($this->criticals,'Could not load scans: '.$this->db->dbErrorLast());
            return SWEF_BOOL_FALSE;
        }

        foreach ($scans as $s) {
            if (!array_key_exists($s[swefsecurity_col_variable],$this->scans)) {
                $this->scans[$s[swefsecurity_col_variable]] = array (
                    swefsecurity_col_variable           =>  $s[swefsecurity_col_variable]
                   ,swefsecurity_col_variable_2         =>  $s[swefsecurity_col_variable_2]
                   ,swefsecurity_col_history_length     =>  $s[swefsecurity_col_history_length]
                   ,swefsecurity_col_store_lines        =>  $s[swefsecurity_col_store_lines]
                   ,swefsecurity_str_matches            =>  array ()
                   ,swefsecurity_str_times              =>  array ()
                   ,swefsecurity_str_log                =>  null
                );
            }
            if ($s[swefsecurity_col_match_var]) {
                if (!array_key_exists($s[swefsecurity_col_match_var],$this->scans[$s[swefsecurity_col_variable]][swefsecurity_str_matches])) {
                    $this->scans[$s[swefsecurity_col_variable]][swefsecurity_str_matches][$s[swefsecurity_col_match_var]] = array (
                        swefsecurity_col_compare_operator   =>  $s[swefsecurity_col_compare_operator]
                       ,swefsecurity_col_persistence        =>  $s[swefsecurity_col_persistence]
                       ,swefsecurity_col_mitigation_match   =>  $s[swefsecurity_col_mitigation_match]
                       ,swefsecurity_col_alert_match        =>  $s[swefsecurity_col_alert_match]
                       ,swefsecurity_col_notification_match =>  $s[swefsecurity_col_notification_match]
                    );
                }
            }
            if ($s[swefsecurity_col_time]) {
                if (!array_key_exists($s[swefsecurity_col_time],$this->scans[$s[swefsecurity_col_variable]][swefsecurity_str_times])) {
                    $this->scans[$s[swefsecurity_col_variable]][swefsecurity_str_times][$s[swefsecurity_col_time]] = array (
                        swefsecurity_col_hits_max           =>  $s[swefsecurity_col_hits_max]
                       ,swefsecurity_col_mitigation_time    =>  $s[swefsecurity_col_mitigation_time]
                       ,swefsecurity_col_alert_time         =>  $s[swefsecurity_col_alert_time]
                       ,swefsecurity_col_notification_time  =>  $s[swefsecurity_col_notification_time]
                    );
                }
            }
        }
        if (SWEF_CONFIG_STORE_LOOKUP_FILES) {
            $this->page->swef->lookupFileSet ($file,$this->scans);
        }
        return SWEF_BOOL_TRUE;
    }


/*
    DASHBOARD SECTION
     * Framework objects are accessed in the same ways as per the event handler section above
     * The framework plugin access control determines whether or not this dashboard is available
     * The rules are  described in the dashboard template included below
*/


    public function _dashboard ( ) {
        require_once swefsecurity_file_dash;
    }

    public function _info ( ) {
        $info   = __FILE__.SWEF_STR__CRLF;
        $info  .= SWEF_COL_CONTEXT.SWEF_STR__EQUALS;
        $info  .= $this->page->swef->context[SWEF_COL_CONTEXT];
        return $info;
    }

}

?>
