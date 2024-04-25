# Domain Enumeration Tool
This tool is designed to assist in the collection of domain-related information including subdomain enumeration, DNS record retrieval, reverse DNS lookups, and WHOIS queries. It's useful for network administrators, security professionals, and anyone interested in domain and network analysis.

# Features
Subdomain Enumeration: Discover subdomains associated with a given domain.

DNS Record Lookup: Retrieve various DNS records such as A, MX, TXT, DNSKEY, and more.

Reverse DNS Lookup: Perform a reverse DNS lookup to find the domain name associated with an IP address.

WHOIS Query: Gather domain registration details.

SRV Record Enumeration: Find service records for specified services.

Zone Transfer Attempt: Check for DNS zone transfer misconfigurations.

# Prerequisites
Before you install and use this tool, ensure you have the following installed:
> Python 3.6 or higher
> 
> Pip (Python package installer)

# Installation
Clone this repository or download the source code:
> git clone https://github.com/your-username/domain-info-tool.git
> 
> cd domain-info-tool

Install required Python libraries:
> pip install -r requirements.txt

To run the tool, execute the following command in the terminal:
> python domain_info_tool.py

Follow the on-screen prompts to enter the domain name or IP address as required. The tool will provide options to choose which types of data to retrieve.

# Modules
This tool consists of several modules, each handling different tasks:

get_ip_address(domain_name): Resolves a domain name to its IP address.

reverse_dns_lookup(ip_address): Finds the domain associated with a given IP address.

enum_subdomains(domain): Lists all subdomains associated with the domain.

enum_dns_records(domain): Fetches DNS records associated with the domain.

whois_info(domain): Retrieves WHOIS information for the domain.

zone_transfer(domain, nameserver): Attempts a DNS zone transfer from the specified nameserver.

# Configurations
You can configure the tool according to your needs by modifying the config.py file. This file includes settings such as timeout periods for requests, the choice of DNS servers, and whether to perform verbose logging.

# Contributions
Contributions are welcome. Please fork the repository, make your changes, and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.
