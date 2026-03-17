# QuickDNS

Quickly resolve DNS records of specified domain. Written in native Ruby. \
Does not use any external Gems.

\
**Installation:** \
Add the script to your executable PATH.

\
**Usage:**

* `dns.rb domain.com` - displays DNS records of given domain for default DNS resolvers (8.8.8.8, 1.1.1.1)
* `dns.rb domain.com @resolver` - displays DNS zone of given domain for given @resolver
* `dns.rb IP` - displays reverse DNS with additional information regarding given IP address (uses ipapi.is API)

