#!/usr/bin/perl

use strict;
use warnings;

# Parse Qualys files
#
# perl qualys_parse.pl <qulays file>
#
# A A Dickinson A&O Corsaire 2016
#
# History
#      v0.2	Fix mssing QIDs
#      v0.1	Initial version

use XML::Twig;
use Data::Dumper;

my $file = $ARGV[0];
my $xs = XML::Twig->new(
	twig_roots => {
		'IP' => \&parse_ip,
	},
);

$xs->parsefile($file);

my @results;

sub parse_ip {
	my ($t, $elem) = @_;
	my $ip = $elem->{att}{'value'};
	foreach my $outer (qw(INFOS SERVICES VULNS PRACTICES)) {
		my $inner = $elem->first_child($outer);
                next if not defined $inner;
                my @cats = $inner->children();
		
                foreach my $cat (@cats) {
			

                        my $static;
                        $static->{section} = $outer;
                        $static->{ip} = $ip;
                        $static->{cat_value} = defined $cat->{'att'}{'value'} ? $cat->{'att'}{'value'} : '';
                        $static->{cat_port}  = defined $cat->{'att'}{'port'} ? $cat->{'att'}{'port'} : '';
                        $static->{cat_proto} = defined $cat->{'att'}{'protocol'} ? $cat->{'att'}{'protocol'} : '';

                        my @findings = $cat->children();
                        foreach my $inn (@findings) {
				my $tmp;
				foreach (keys %$static) { $tmp->{$_} = $static->{$_}; }
                                $tmp->{qid} = $inn->{'att'}{'number'};
				$tmp->{severity} = $inn->{'att'}{'severity'};
                                foreach my $e (qw(TITLE)) {
                                        my $x = $inn->first_child($e);
                                        $tmp->{lc($e)} = defined $x ? $x->text : '';
                                }
				push @results, $tmp;
			}

		}

	}
}

open(my $fh, ">", "./internal_qualys_output.txt");
foreach my $d (@results) {
	print "$d->{ip}\t$d->{qid}\t$d->{cat_port}\t$d->{cat_proto}\t$d->{title}\n";
	print $fh Dumper $d;
}
close($fh);
