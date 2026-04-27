The following is a list of data files that should be kept up-to-date from external data sources:

Maybe a separate document to track this, or maybe a unique string to grep for. Preliminary list:
- nmap-service-probes
    - Some match lines are auto-generated from source code (postgresql, for one)
    - Some lines depend on the current date (marked in comments by "TIME")
- nmap-mac-prefixes - from IEEE
- nmap-rpc - from IANA
- nmap-protocols - from IANA
- nmap-services - no current automated process for updating these from IANA
- nselib/tls.lua - TLS versions, ciphersuites, messages, and extensions from IANA
- nselib/eap.lua - EAP method types from IANA
- nselib/data/enterprise\_numbers.txt - from IANA
- nselib/data/mgroupnames.db - multicast group names from IANA
- scripts/snmp-interfaces.nse - interface types from IANA
- nselib/data/wp-plugins.lst - Wordpress plugins from wordpress.org
