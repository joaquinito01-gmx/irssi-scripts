use strict;
use vars qw($VERSION %IRSSI);

use Irssi;

$VERSION = '1.00';
%IRSSI = (
        authors         => 'Joaquinito01',
        contact         => 'joaquinito01-gmx@protonmail.com',
        name            => 'Security',
        description     => 'Ensure channel security with kickban and mutes',
        license         => '',
        changed         => ""
);
our @whois = ();

sub skb
{
        my($data, $server, $witem) = @_;
        return unless $witem;
        Irssi::print("$data");
        my @spl = split(' ', $data);
        if (scalar @spl < 1) {
                Irssi::print("Security: No kick target was given. Ban cannot be complete.");
                Irssi::signal_stop();
        }
        unshift @whois, "$spl[0],$witem->{name}";
        $server->command("WHOIS $spl[0]");
}

sub doban
{
        my($server, $chan, $client, $username, $hostname, $realname) = @_;
        $server->command("BAN $chan *!*\@$hostname");
        $server->command("KICK $chan $client Your behaviour is not conducive the the desired enviornment.");
}

sub whoisuser
{
        my($server, $data) = @_;
        my @info = split(' ', $data);
        my $client = $info[1];my $username = $info[2];my $hostname = $info[3];my $realname = $info[5];
        my $index = 0;
        foreach my $whoi (@whois) {
                $index++;
                my @inf = split(',', $whoi);
                my $chan = $inf[1];my $nick = $inf[0];
                if ($nick == $client) {
                        doban($server, $chan, $client, $username, $hostname, $realname);
                        splice(@whois, $index, 1);

                }
        }
}

Irssi::command_bind skb => \&skb;
Irssi::signal_add("event 311", "whoisuser")
