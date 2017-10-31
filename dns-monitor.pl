#!/usr/bin/perl


@lines = `ps axuw | grep dns` ;
foreach $line (@lines) {
  if ($line =~ /dns-server-frag/) {
    exit(1) ;
    }
  }

$cmd = "/usr/local/bin/dns-server-frag -i eth0  -m 84:78:ac:0d:97:c1 -l 2600:3c00::f03c:91ff:fe0f:4e7d -p 53 -d 2600:3c00::f03c:91ff:fed5:7460 >/dev/null 2>/dev/null &" ;
system($cmd) ;
exit(1) ;


