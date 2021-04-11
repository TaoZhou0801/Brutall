1. Project "brutall" is designed to be a command-line brute-force application,
    although the "command-line" function is not yet implemented. It is written with the idea
    to do authentication with MINIMAL packet interations (so that it runs fast) and to keep 
    MINIMAL dependency upon non-standard libraries (so that no unnecessary packets are sent 
    and maintenance should be easier). This project relies only on RFC documents and official 
    documentations.

2. files in "previous" folder were modules written before the framework was reconstructed,
    they will be migrated into the main program soon.

3. All modules are tested against the weak-password environments built in virtual machine,
    which is more convenient than writing go-styled testing files.

4. TODO:
    c. a "pause" function should be added. A seperate goroutine should wait and listen for 
        user input (a single "p" character maybe?). Once the input is detected, we should
        break the for loop in "login" method of every module (a go channel will do the work).
    d. SNMPv3, SSH, migration, and new modules!
    e. sasl qop: auth-conf, prep (low priority)
    f. ntlmv2 (low priority)
