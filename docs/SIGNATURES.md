In addition to the service and OS fingerprints, which receive frequent user
updates, NSE contains many fingerprint tables and lists that can get stale over
time. We should have an automated process for testing these against new OS and
service releases, but until then, we must have a complete list of them. Here's
a start:
- `nselib/data/dns-srv-names` - Unlike `dns-srv-names.full` which should really be populated from IANA directly, this one is supposed to contain the "most popular" names to reduce script run times.
- `nselib/data/favicon-db` - Maybe we can harvest some data from the Icons of the Web project? This was last updated in 2010.
- `nselib/data/http-default-accounts-fingerprints.lua`
- `http-devframework-fingerprints.lua`
- `http-fingerprints.lua` - the big one. We've updated this in the past to cover things from exploit-db.com, etc.
- `nselib/data/ike-fingerprints.lua` - updated with permission from https://github.com/royhills/ike-scan/blob/master/ike-vendor-ids
- `nselib/data/oracle-sids` - Some of these look to contain Oracle database version numbers, so they should be updated when new versions are released.
- `nselib/data/passwords.lst` - As new password dumps become available, we should update this list of 5000 common passwords. Also, it should contain some of the most-common default passwords ("admin", etc.)
- `nselib/data/usernames.lst` - anemic list, should contain the most common default usernames at least.
- `nselib/data/rtsp-urls.txt`
- `nselib/data/snmpcommunities.txt` - This is pitifully small: 6 communities, but there should be loads of defaults out there.
- `nselib/data/ssl-fingerprints` - Mostly from LittleBlackBox, which hasn't released in a while, but there are other sources we could tap.
- `nselib/data/vhosts-full.lst` and `nselib/data/vhosts-default.lst` - This could be updated with the scans.io DNS datasets for real-world results.
- `scripts/xmpp-info.nse` - contains a database of XMPP fingerprints based on ID structure.
- `scripts/http-waf-fingerprint.nse` - Web App Firewall behavioral fingerprints
- `scripts/http-php-version.nse` - MD5 checksums of PHP responses to some magic queries.
- `scripts/http-cakephp-version.nse` - Similar: MD5 checksums of default files.
- `scripts/sniffer-detect.nse` - particular behaviors of OS types in promiscuous mode.
- `scripts/smb-os-discovery.nse` - conversion of Windows version string to CPE; soon to be converted to a library, which will have to be added to this list.
- `nselib/mssql.lua` - MS SQL Server build number-to-version lookup table.
- `nmap-services` - port frequency data must be refreshed, requiring full-65535-port scans of large networks, home networks, and the Internet.
