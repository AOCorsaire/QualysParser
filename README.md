# QualysParser
Parse Qualys Files

## Requirements
Perl

XML::Twig

## Examples
```
ant@host:~$ perl qualys_parse.pl Scan_Results_20171006_scan_1507278989_07019.xml 
192.168.0.1	82040			ICMP Replies Received
192.168.0.1	82045			Degree of Randomness of TCP Initial Sequence Numbers
192.168.0.1	82046			IP ID Values Randomness
192.168.0.1	6			DNS Host Name
192.168.0.1	45006			Traceroute
192.168.0.1	45004			Target Network Information
192.168.0.1	45005			Internet Service Provider
192.168.0.1	45039			Host Names Found
192.168.0.1	45038			Host Scan Time
192.168.0.1	86002	443	tcp	SSL Certificate - Information
192.168.0.1	38600	443	tcp	SSL Certificate will expire within next six months
192.168.0.1	38597	443	tcp	SSL/TLS invalid protocol version tolerance
192.168.0.1	42350	443	tcp	TLS Secure Renegotiation Extension Support Information
192.168.0.1	38116	443	tcp	SSL Server Information Retrieval
... [snip] ...
```
Also drops a file containing the dump of the data structure for further analysis
```
ant@uk-scan-02:~$ head -n 20 internal_qualys_output.txt 
$VAR1 = {
          'ip' => '192.168.0.1',
          'section' => 'INFOS',
          'cat_port' => '',
          'title' => 'ICMP Replies Received',
          'qid' => '82040',
          'cat_proto' => '',
          'severity' => '1',
          'cat_value' => 'TCP/IP'
        };

... [snip] ...
```
