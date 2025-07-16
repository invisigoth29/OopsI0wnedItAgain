# Enumeration Checklist

## General
- [ ] Port scanning (`nmap`, `naabu`, `rustscan`)
- [ ] Version fingerprinting (`nmap -sV`, `httpx`, `whatweb`)

## HTTP/Web
- [ ] Directory brute force (`ffuf`, `feroxbuster`, `dirsearch`)
- [ ] Analyze HTTP headers, cookies, CSP, CORS
- [ ] Test default files (`robots.txt`, `sitemap.xml`, `.git`)

## SMB/RDP/LDAP
- [ ] SMB share listing (`smbclient`, `enum4linux-ng`)
- [ ] Null sessions or open RDP ports
- [ ] LDAP enumeration (`ldapsearch`, `bloodhound`)

## DNS
- [ ] Zone transfer attempt
- [ ] Brute-force subdomains (`dnsx`, `massdns`)
