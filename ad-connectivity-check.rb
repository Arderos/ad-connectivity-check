#!/usr/bin/env ruby
# AD connectivity check by Arderos and kiawizard
require 'pry'
require 'resolv'
require 'io/console'
require 'net/ldap'
require 'socket'
require 'timeout'
require 'colorize'
require 'yaml'

# Define common AD ports
AD_PORTS = {ldap: 389, ldaps: 636, gc: 3268, gcs: 3269, krb_88: 88, krb_464: 464, rpc: 135, dns: 53, smb: 445}
def get_param(key)
  position = ARGV.index("-#{key}") || ARGV.index("--#{key}")
  return nil if !position
  ARGV[position+1]
end

# Check if the port is open
def port_open?(ip, port, seconds=1)
  Timeout::timeout(seconds) do
    begin
      TCPSocket.new(ip, port).close
      true
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
      false
    end
  end
rescue Timeout::Error
  false
end

# Check if a Domain Controller is also a Global Catalog
def is_gc?(dc,gcs)
  !(gcs.detect{|i| i[:distinguishedname].first.downcase.include?("=#{dc.downcase.split(".").first}")}.nil?)
end

# Ask the user for the domain name 
domain = get_param('domain') || get_param('d')
if !domain
  puts 'Enter the domain name:'
  domain = gets.chomp
end

# Connection timeout. Defaults to 1 if not specified
timeout = get_param('timeout') || get_param('t') || 1

# Ask the user for the domain username. Needed for AD search operations.
ad_username = get_param('username') || get_param('u')
while !ad_username || ad_username == ""
	puts 'Enter Active Directory username in "user@domain" format:'
	ad_username = gets.chomp
end

# Ask the user for the domain password. Needed for AD search operations.
ad_password = get_param('password') || get_param('p')
puts 'Entering the password as argument is insecure!' if ad_password
while !ad_password || ad_password == ""
	ad_password = IO::console.getpass("Enter Active Directory password:\n")
end

base_dn = domain.split(".").map { |dn_part| "dc=#{dn_part}" }.join(",")

# Get PDC for the current domain via DNS SRV record. We expect that it is available.
resolver = Resolv::DNS.new
pdc_name = resolver.getresources("_ldap._tcp.pdc._msdcs.#{domain}", Resolv::DNS::Resource::IN::SRV).first.target.to_s

# Create querier object to use in LDAP searches.
puts "Querying domain #{domain}, PDC #{pdc_name}, please wait."
ldap_querier = Net::LDAP.new(host: pdc_name, port: AD_PORTS[:ldaps], encryption: :simple_tls, base: base_dn, auth: {method: :simple, username: ad_username, password: ad_password})

# Create Global Catalog querier object to use in LDAP searches that require a search against a GC.
gc_ldap_querier = Net::LDAP.new(host: pdc_name, port: AD_PORTS[:gcs], encryption: :simple_tls, base: "", auth: {method: :simple, username: ad_username, password: ad_password})

# Find our the root domain of a forest. This is not an ideal way to do that
# We expect that the root naming context pointing to the domain will be the first object returned
# If any other object will be returned first the program will fail.
# This will be fixed by selecting objects containing only "DC" parts in their DN.
root_naming_context = gc_ldap_querier.search(attributes: "rootDomainNamingContext", scope: Net::LDAP::SearchScope_BaseObject)
root_domain = root_naming_context.map{|root_domain| root_domain[:rootdomainnamingcontext]}.flatten.first.split(",").map{|part| part.to_s.split('=').last}.join(".")

# Find out the root domain's PDC, root DN and creqte a querier for them.
root_pdc_name = resolver.getresources("_ldap._tcp.pdc._msdcs.#{root_domain}", Resolv::DNS::Resource::IN::SRV).first.target.to_s
root_base_dn = root_domain.split(".").map { |dn_part| "dc=#{dn_part}" }.join(",")
# root_ldap_querier is used to find GC servers in the forest, hence the "CN=Configuration" in the "base" argument. 
root_ldap_querier = Net::LDAP.new(host: root_pdc_name, port: AD_PORTS[:ldaps], encryption: :simple_tls, base: "CN=Configuration,#{root_base_dn}", auth: {method: :simple, username: ad_username, password: ad_password})
# Set up filters and query GC information
gc_filter1 = Net::LDAP::Filter.eq("objectCategory", "nTDSDSA")
gc_filter2 = Net::LDAP::Filter.eq("options", "1")
gc_composite_filter = Net::LDAP::Filter.join(gc_filter1, gc_filter2)
gcs = root_ldap_querier.search(filter: gc_composite_filter)

# Get subdomains by quiering trust relationship
ad_filter = Net::LDAP::Filter.eq("objectclass", "trustedDomain")
subdomains = ldap_querier.search(filter: ad_filter).map{|subdomain| subdomain[:cn].first }.select{|subdomain| subdomain.end_with?(domain)} + [domain]
kdcs = subdomains.map { |subdomain| resolver.getresources("_kerberos._tcp.#{subdomain}", Resolv::DNS::Resource::IN::SRV).map(&:target).map(&:to_s)  }.flatten

# Start KDC Check
puts "Query complete, got #{kdcs.size} KDCs, start checking ports availability"
failed_kdcs = {}
#Set up multithreading, we check domain controllers in parallel and their ports in sequence
threads = []
kdcs.each do |kdc|
  threads << Thread.new do
    badports={}
    AD_PORTS.each do |portname,port|
      #Check if the DC in question is also a GC - if not we will not check GC ports.
      if (![:gc, :gcs].include?(portname) || is_gc?(kdc,gcs)) && !port_open?(kdc, port, timeout)
        badports[portname.to_s] = port
      end
    end
    print("*")
    # Return an array containing a DC and it's failed ports
    [kdc, badports]
  end
end

# Combine information from all threads and build the final dictionary.
threads.each do |thread|
  kdc,badports = thread.value
  failed_kdcs[kdc] = badports if badports.any? 
end
puts()
# Print our the report
if failed_kdcs.any?
	puts "#{failed_kdcs.size} Domain Controllers have failed port checks:".red
    puts failed_kdcs.to_yaml.red
end



