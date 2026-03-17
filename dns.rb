#!/usr/bin/env ruby
# QuickDNS
# quickly resolve DNS records of specified domain
# Usage: dns [ domain.com | IP ] [@custom_resolver]
# https://github.com/pku188
#
# Copyright (c) 2026 Przemysław Kucaj
# Licensed under the MIT License.
# Full license text available at https://opensource.org/licenses/MIT

require 'resolv'
require 'net/http'
require 'json'
require 'uri'
require 'timeout'
require 'ipaddr'
require 'socket'

class QuickDNS
  RESOLVERS = %w[8.8.8.8 1.1.1.1].freeze
  MAIN_RESOLVER = '8.8.8.8'
  TIMEOUT = 5
  CONNECTIVITY_TIMEOUT = 2

  # ANSI color codes
  WHITE = "\033[1;97m"
  YELLOW = "\033[0;33m"
  NC = "\033[0m"

  def initialize
    @dns_cache = {}
    @reverse_cache = {}
    @ipinfo_cache = {}
    @active_resolvers = RESOLVERS.dup
    @main_resolver = MAIN_RESOLVER
  end

  def resolver_reachable?(ip, test_domain = "one.one.one.one")
    begin
      Timeout::timeout(CONNECTIVITY_TIMEOUT) do
        resolver = Resolv::DNS.new(nameserver: ip)
        resolver.timeouts = CONNECTIVITY_TIMEOUT
        resolver.getaddress(test_domain)
      end
      true
    rescue Timeout::Error, Resolv::ResolvError, Resolv::ResolvTimeout, SocketError, Errno::EHOSTUNREACH, Errno::ENETUNREACH
      false
    end
  end

  def parse_domain(input)
    return nil if input.nil? || input.empty?

    domain = input.downcase
    domain = domain.sub(/^[a-z]+:\/\//, '')  # Remove protocol
    domain = domain.sub(/^www\./, '')        # Remove www
    domain = domain.sub(/^.*@/, '')          # Remove user info
    domain = domain.sub(/\/.*$/, '')         # Remove path
    domain = domain.strip                    # Trim

    if domain.match?(/[^a-zA-Z0-9.:-]/)
      puts "Invalid characters in domain"
      exit 1
    end

    domain
  end

  def create_resolver(nameserver)
    resolver = Resolv::DNS.new(nameserver: nameserver)
    resolver.timeouts = TIMEOUT
    resolver
  end

  def get_dns_records(query, type, resolver_ip, recursive = true)
    cache_key = "#{query}:#{type}:#{resolver_ip}:#{recursive}"
    return @dns_cache[cache_key] if @dns_cache.key?(cache_key)

    begin
      resolver = create_resolver(resolver_ip)
      if recursive
        records = case type.upcase
                  when 'A'
                    resolver.getaddresses(query).select { |addr| addr.is_a?(Resolv::IPv4) }.map(&:to_s)
                  when 'AAAA'
                    resolver.getaddresses(query).select { |addr| addr.is_a?(Resolv::IPv6) }.map(&:to_s)
                  when 'MX'
                    resolver.getresources(query, Resolv::DNS::Resource::IN::MX).map { |r| [r.preference, r.exchange.to_s] }
                  when 'TXT'
                    resolver.getresources(query, Resolv::DNS::Resource::IN::TXT).map { |r| r.strings.join('') }
                  when 'NS'
                    resolver.getresources(query, Resolv::DNS::Resource::IN::NS).map { |r| r.name.to_s }
                  when 'CNAME'
                    resolver.getresources(query, Resolv::DNS::Resource::IN::CNAME).map { |r| r.name.to_s }
                  when 'SOA'
                    soa = resolver.getresources(query, Resolv::DNS::Resource::IN::SOA).first
                    if soa
                      ["#{soa.mname} #{soa.rname} #{soa.serial} #{soa.refresh} #{soa.retry} #{soa.expire} #{soa.minimum}"]
                    else
                      []
                    end
                  else
                    []
                  end
      else
        # Get authoritative DNS, cover cases like sub.domain.co.uk
        tld_arr = %w[co com org info net edu gov]
        parts = query.split('.')
        query =
          if parts.size > 2 && tld_arr.include?(parts[-2])
            parts.last(3).join('.')
          elsif parts.size > 2
            parts.last(2).join('.')
          else
            query
          end
        records = resolver.getresources(query, Resolv::DNS::Resource::IN::NS).map { |r| r.name.to_s }
      end

      @dns_cache[cache_key] = records
    rescue => e
      @dns_cache[cache_key] = []
    end

    @dns_cache[cache_key]
  end

  def get_reverse_dns(ip)
    return '' if ip.nil? || ip.empty?
    return @reverse_cache[ip] if @reverse_cache.key?(ip)

    begin
      resolver = create_resolver(@main_resolver)
      result = resolver.getname(ip)
      @reverse_cache[ip] = result.to_s
    rescue => e
      @reverse_cache[ip] = ip  # Return IP if no reverse DNS
    end

    @reverse_cache[ip]
  end

  def get_ipinfo(ip)
    return '' if ip.nil? || ip.empty?
    return @ipinfo_cache[ip] if @ipinfo_cache.key?(ip)

    begin
      uri = URI("https://api.ipapi.is/?q=#{ip}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.read_timeout = TIMEOUT
      http.open_timeout = TIMEOUT
      ca_file = '/etc/ssl/certs/ca-certificates.crt'
      if ::File.file?(ca_file)
        http.ca_file = ca_file
      end
      response = http.request(Net::HTTP::Get.new(uri))
      @ipinfo_cache[ip] = response.code == '200' ? response.body : ''
    rescue => e
      @ipinfo_cache[ip] = ''
    end

    @ipinfo_cache[ip]
  end

  def ip_address?(string)
    begin
      addr = IPAddr.new(string)
      addr.ipv4? || addr.ipv6?
    rescue IPAddr::InvalidAddressError
      false
    end
  end

  def valid_domain?(string)
    return false if string.nil? || !string.include?('.')
    return true if ip_address?(string)
    string.match?(/^[a-zA-Z0-9.-]+$/)
  end

  def process_ip(ip)
    puts "https://api.ipapi.is/?q=#{ip}"

    # Reverse DNS lookup
    reverse_result = get_reverse_dns(ip)
    if reverse_result != ip
      puts "IP: #{ip} => #{YELLOW}#{reverse_result}#{NC}"
    else
      puts "IP: #{ip} => #{YELLOW}No reverse DNS#{NC}"
    end

    # IP information
    ipinfo = get_ipinfo(ip)
    if !ipinfo.empty?
      begin
        data = JSON.parse(ipinfo)

        # Route
        puts "route: #{data['asn']['route']}" if data['asn'] && data['asn']['route']

        # Extract fields for comparison
        comp_name = data.dig('company', 'name')
        comp_domain = data.dig('company', 'domain')

        dc_name = data.dig('datacenter', 'datacenter')
        dc_domain = data.dig('datacenter', 'domain')

        asn_org = data.dig('asn', 'org')
        asn_domain = data.dig('asn', 'domain')

        # Company Line
        if comp_name
          comp_out = [comp_name, comp_domain].compact
          puts "company: #{comp_out.join(', ')}" if comp_out.any?
        end

        # Datacenter Line (Output only if differs from company)
        if (dc_name && ![comp_name, comp_domain].include?(dc_name)) || (dc_domain && ![comp_name, comp_domain].include?(dc_domain))
          dc_out = [dc_name, dc_domain].compact
          puts "datacenter: #{dc_out.join(', ')}" if dc_out.any?
        end

        # ASN Line (Output only if differs from company/DC)
        if (asn_org && ![comp_name, comp_domain, dc_name, dc_domain].include?(asn_org)) || (asn_domain && ![comp_name, comp_domain, dc_name, dc_domain].include?(asn_domain))
          asn_out = [asn_org, asn_domain].compact
          puts "asn: #{asn_out.join(', ')}" if asn_out.any?
        end

        # Location info
        if data['location']
          location_parts = [
            data['location']['zip'],
            data['location']['city'],
            data['location']['state'],
            data['location']['country'],
            data['location']['country_code']
          ].compact
          puts "zip: #{location_parts.join(', ')}" unless location_parts.empty?
        end

        # Type
        type_arr = []
        company_type, asn_type = data.dig('company', 'type'), data.dig('asn', 'type')
        type_arr << company_type if company_type
        type_arr << "#{asn_type} (asn)" if asn_type && asn_type != company_type
        puts "type: #{type_arr.join(', ')}" if type_arr.any?

        # Boolean flags
        keys = data.select { |k, v| v == true }.keys
        if keys.any?
          formatted_flags = keys.map do |key|
            if key == 'is_vpn'
              vpn_service = data.dig('vpn', 'service')
              vpn_service ? "#{key} (#{vpn_service})" : key
            else
              key
            end
          end
          puts "flags: #{formatted_flags.sort.join(', ')}"
        end

        # Abuser scores (company/ASN)
        abuser_scores = []
        abuser_scores << data['company']['abuser_score'] if data['company'] && data['company']['abuser_score']
        abuser_scores << data['asn']['abuser_score'] if data['asn'] && data['asn']['abuser_score']
        puts "abuser_score: #{abuser_scores.join(', ')}" unless abuser_scores.empty?

      rescue JSON::ParserError => e
        puts "Error parsing IP info JSON: #{e.message}"
      end
    else
      puts "Error: Failed to fetch IP info"
    end
  end

  def process_domain(domain)
    @active_resolvers.each do |resolver|
      print "\n#{WHITE}#{resolver}#{NC}\n"

      # A records
      a_records = get_dns_records(domain, 'A', resolver)
      a_records.sort_by do |ip|
        begin
          IPAddr.new(ip)
        rescue IPAddr::InvalidAddressError
          IPAddr.new("255.255.255.255")
        end
      end.each do |ip|
        reverse = get_reverse_dns(ip)
        puts "A:   #{ip}  -->  #{YELLOW}#{reverse}#{NC}"
      end

      # www records
      www_records = get_dns_records("www.#{domain}", 'A', resolver)
      www_records.sort_by do |ip|
        begin
          IPAddr.new(ip)
        rescue IPAddr::InvalidAddressError
          IPAddr.new("255.255.255.255")
        end
      end.each do |ip|
        reverse = get_reverse_dns(ip)
        puts "www: #{ip}  -->  #{YELLOW}#{reverse}#{NC}"
      end

      # MX records
      mx_records = get_dns_records(domain, 'MX', resolver)
      mx_records.sort_by { |preference, exchange| [preference, exchange] }.each do |preference, exchange|
        # Get A record for MX host
        mx_a_records = get_dns_records(exchange, 'A', resolver)
        if mx_a_records.empty?
          # Fallback to CNAME
          cname_records = get_dns_records(exchange, 'CNAME', resolver)
          mx_a_records = cname_records
        end

        if mx_a_records.any?
          mx_a_records.each do |ip|
            reverse = get_reverse_dns(ip)
            if reverse == ip
              puts "MX:  #{exchange} [#{preference}]  -->  #{YELLOW}#{reverse}#{NC}"
            else
              puts "MX:  #{exchange} [#{preference}]  -->  #{YELLOW}#{reverse}#{NC} [#{ip}]"
            end
          end
        else
          puts "MX:  #{exchange} [#{preference}]  -->  #{YELLOW}No A record#{NC}"
        end
      end
    end

    # TXT records
    txt_records = get_dns_records(domain, 'TXT', @main_resolver)
    puts "\n#{WHITE}TXT:#{NC}"
    txt_records.sort_by { |txt| txt }.each { |txt| puts "\"#{txt}\"" }

    # SOA record
    soa_records = get_dns_records(domain, 'SOA', @main_resolver)
    puts "\n#{WHITE}SOA:#{NC}"
    soa_records.each { |soa| puts soa }

    # NS records
    puts "\n#{WHITE}NS:#{NC}"
    ns_records = get_dns_records(domain, 'NS', @main_resolver)
    unless ns_records.empty?
      ns_records.sort.each do |ns|
        a_records = get_dns_records(ns, 'A', @main_resolver)
        if a_records.any?
          a_records.each do |ip|
            puts "#{ns} --> #{YELLOW}#{ip}#{NC}"
          end
        else
          puts "#{ns}"
        end
      end
    end

    # DNS records (authoritative NS from TLD)
    puts "\n#{WHITE}DNS:#{NC}"
    domain_parts = domain.split('.')
    tld = domain_parts.last

    tld_ns_records = get_dns_records("#{tld}.", 'NS', @main_resolver)
    unless tld_ns_records.empty?
      rand_tldns = tld_ns_records.sample
      # Non-recursive query to get authoritative answer
      auth_ns_records = get_dns_records(domain, 'NS', rand_tldns, false)
      puts auth_ns_records.sort.join("\n") unless auth_ns_records.empty?
    end
  end

  def run(args)
    custom_resolver = nil
    target_input = nil

    args.each do |arg|
      if arg.start_with?('@')
        custom_resolver = arg[1..-1].strip
        next if custom_resolver.empty?
      else
        target_input = arg
      end
    end

    domain = parse_domain(target_input)

    if domain.nil?
      show_usage
      return
    end

    # Handle custom resolver
    if custom_resolver
      unless ip_address?(custom_resolver) || valid_domain?(custom_resolver)
        puts "#{YELLOW}Invalid custom resolver: #{custom_resolver} (must be IP or valid hostname)#{NC}"
        exit 1
      end

      unless resolver_reachable?(custom_resolver, domain)
        puts "#{YELLOW}Error: Custom resolver #{custom_resolver} is unreachable or cannot resolve queries.#{NC}"
        exit 1
      end

      @active_resolvers = [custom_resolver]
      @main_resolver = custom_resolver
    end

    if ip_address?(domain)
      process_ip(domain)
    elsif valid_domain?(domain)
      process_domain(domain)
    else
      show_usage
    end
  end

  def show_usage
    puts "QuickDNS - quickly resolve DNS records of specified domain"
    puts "Usage: dns [domain.com | IP] [@custom_resolver]"
    puts "\nExamples:"
    puts "  dns example.com"
    puts "  dns 1.1.1.1"
    puts "  dns example.com @9.9.9.9"
    exit 1
  end
end

# Main execution
if __FILE__ == $0
  if ARGV.empty?
    QuickDNS.new.show_usage
  else
    QuickDNS.new.run(ARGV)
  end
end
