#!/usr/bin/perl

use Net::ACME2;
use Net::ACME2::LetsEncrypt;
use Digest::SHA;
use MIME::Base64;

#####################
#   CONFIGURATION   #
#####################


$private_key = <<'PEMPRIVATEKEY';
# << PASTE YOUR ACCOUNT PRIVATE KEY HERE >>
PEMPRIVATEKEY

$cert_request = <<'LECSRB';
# << PASTE YOUR CSR HERE FOR THE CERTIFICATE YOU WANT >>
LECSRB

# << PASTE YOUR ACCOUNT URL, LEAVE EMPTY TO CREATE ACCOUNT >>
$account_url = "";

# << INPUT YOUR DOMAINS YOU WANT CERTIFICATE FOR >>
@domains = ('*.example.org', 'example.org');

# << INPUT THE FILESYSTEM PATH FOR THE CHALLENGE FILE >>
$challengepath = "/path/to/challenge/file.txt";

# << INPUT THE FILESYSTEM PATH WHRE TO WRITE THE FINISHED CERTIFICATE >>
$certpath = "/path/to/new/certificate.crt";


#####################
#   NOTE!!!!        #
#####################

# TO LAUNCH CERTIFICATE GENERATION - SUPPLY AN ARGUMENT OF "1" - like this: ./certbot.pl 1
# ELSE IT WILL LAUNCH IN POWERDNS PIPE MODE READY TO RECEIVE COMMANDS FROM A POWERDNS INSTANCE

#####################
#   SCRIPT          #
#####################

$|=1;

if ($#domains >= 60) {
print "LOG\tUnable to process more than 60 domains. (Response size would exceed 4097 and get rejected by LetsEncrypt)\nFAIL\n";
<>;
exit;
}

if ($ARGV[0] eq "1") {
        if ($account_url) {
                $acme = Net::ACME2::LetsEncrypt->new( key => $private_key, key_id => $account_url );
        }
        else
        {
                $acme = Net::ACME2::LetsEncrypt->new( key => $private_key);
                $acme->create_account( termsOfServiceAgreed => 1 );
                print "ACCOUNT URL: ".$acme->key_id."\n";
        }


        @ids = ();
        foreach $dom (@domains) {
                push(@ids, { type => 'dns', value => $dom } );
        }
        $order = $acme->create_order( identifiers => [@ids] );

        open(ACMEWRITE, ">".$challengepath);
        flock(ACMEWRITE,2);
        foreach $dauth ($order->authorizations()) {
                $fdauth = $acme->get_authorization( $dauth );
                foreach $chtype ($fdauth->challenges()) {
                        if ($chtype->type() eq "dns-01") {
                                $chalstring = $acme->make_key_authorization($chtype);
                                $sha = Digest::SHA::sha256($chalstring);
                                $b64 = MIME::Base64::encode_base64url($sha);
                                print "Creating challenge for ".$fdauth->identifier()->{'value'}."\n";
                                print ACMEWRITE $b64."\n";
                                push(@pendingcompletion, $chtype);
                        }
                }
        }
        close(ACMEWRITE);
        chmod(0666, $challengepath);
        sleep(5);
        print "Submitting challenges for validation...\n";
        foreach $uchall (@pendingcompletion) {
                 $acme->accept_challenge($uchall);
        }
        print "Getting validation results...\n";
        foreach $qdauth ($order->authorizations()) {
                $dauth = $acme->get_authorization( $qdauth );
                while (1) {
                        $valresult = $acme->poll_authorization($dauth);
                        if ($valresult eq "valid") {
                                print "Passed authorization for ".$dauth->identifier()->{'value'}."\n";
                                last;
                        }
                        else
                        {
                                if ($valresult eq "invalid") {
                                        print "Failed authorization for ".$dauth->identifier()->{'value'}."\n";
                                        die();
                                }
                        }
                        sleep 1;
                }
        }

        print "Generating certificate...\n";
        $acme->finalize_order($order,$cert_request) || die "Unable to generate certificate --> Possible failed some validation or exceeded rate limits\n";
        while ($order->status() ne 'valid') {
            sleep 1;
            $acme->poll_order($order);
        }
        $pem = $acme->get_certificate_chain($order);
        print "Writing certificate...\n";
        open(CERTFILE, ">".$certpath);
        print CERTFILE $pem;
        close(CERTFILE);
        print "Successfully generated LE certificate!\n";
}
else
{
        $line=<>;
        chomp($line);
        if ($line ne "HELO\t1") {
                print "FAIL\n";
                <>;
                exit;
        }
        print "OK\tLetsEncrypt ACME DNS Validator starting up\n";
        while(<>) {
                chomp();
                @arr=split(/\t/);
                if(@arr<6) {
                        print "LOG\tPowerDNS sent unparseable line\n";
                        print "FAIL\n";
                        next;
                }
                ($type,$qname,$qclass,$qtype,$id,$ip)=split(/\t/);
                if(($qtype eq "TXT" || $qtype eq "ANY") && ($qname =~ m/^_acme-challenge\./i)) {
                        open(ACMEFILE, $challengepath);
                        flock(ACMEFILE,1);
                        @acmes = <ACMEFILE>;
                        close(ACMEFILE);
                        $z = 0;
                        foreach $acme (@acmes) {
                                $acme =~ s/[^A-Za-z0-9_\-]*//sgi;
                                $acme = substr($acme,0,43);
                                if (length($acme) == 43) {
                                        print "DATA\t$qname\t$qclass\tTXT\t4\t1\t\"".$acme."\"\n";
                                        if (($z >= $#domains)||($z >= 60)) {
                                                last;
                                        }
                                $z++;
                                }
                        }
                }
                print "END\n";
        }
}
