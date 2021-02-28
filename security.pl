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
        $server->command("BAN $witem->{name} $spl[0]");
        $server->command("KICK $witem->{name} $spl[0] Your behaviour is not conducive the the desired enviornment.");
}

Irssi::command_bind skb => \&skb;
