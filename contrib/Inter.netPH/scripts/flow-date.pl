#!/usr/bin/perl 
# script to group usage by shifts
#
# usage: flow-cat -a <flowdir> | 
#   ./flow-date.pl `flow-cat -a <flowdir> | flow-stat -f15`
#
# William Emmanuel S. YU <wyu@ateneo.edu>
# Ateneo de Manila University, Philippines
#

use Cflow qw(:flowvars find);

my (%u_bytes, %u_packets);
$u_bytes{"6-15"} = 0;
$u_packets{"6-15"} = 0;
$u_bytes{"14-23"} = 0;
$u_packets{"14-23"} = 0;
$u_bytes{"22-7"} = 0;
$u_packets{"22-7"} = 0;
$u_bytes{"8-17"} = 0;
$u_packets{"8-17"} = 0;
$u_bytes{"9-18"} = 0;
$u_packets{"9-18"} = 0;
$u_bytes{"total"} = 0;
$u_packets{"total"} = 0;

# check for arguement for total
if (scalar(@ARGV < 1)) {
  $u_bytes{"grand-total"} = 0;
} else {
  $u_bytes{"grand-total"} = <@ARGV>;
}

find(sub { wanted(\%u_bytes,\%u_packets) }, "-");
printf("%12s %25u %10.2f %10.2f \n", "6am to 3pm", $u_bytes{"6-15"}, ($u_bytes{"total"} != 0)?(($u_bytes{"6-15"}/$u_bytes{"total"})*100):0,($u_bytes{"grand-total"} != 0)?(($u_bytes{"6-15"}/$u_bytes{"grand-total"})*100):0);
printf("%12s %25u %10.2f %10.2f \n", "2pm to 11pm", $u_bytes{"14-23"}, ($u_bytes{"total"} != 0)?(($u_bytes{"14-23"}/$u_bytes{"total"})*100):0,($u_bytes{"grand-total"} != 0)?(($u_bytes{"14-23"}/$u_bytes{"grand-total"})*100):0);
printf("%12s %25u %10.2f %10.2f \n", "10pm to 7am", $u_bytes{"22-7"}, ($u_bytes{"total"} != 0)?(($u_bytes{"22-7"}/$u_bytes{"total"})*100):0,($u_bytes{"grand-total"} != 0)?(($u_bytes{"22-7"}/$u_bytes{"grand-total"})*100):0);
printf("%12s %25u %10.2f %10.2f \n", "8am to 5pm", $u_bytes{"8-17"}, ($u_bytes{"total"} != 0)?(($u_bytes{"8-17"}/$u_bytes{"total"})*100):0,($u_bytes{"grand-total"} != 0)?(($u_bytes{"8-17"}/$u_bytes{"grand-total"})*100):0);
printf("%12s %25u %10.2f %10.2f \n", "9am to 6pm", $u_bytes{"9-18"}, ($u_bytes{"total"} != 0)?(($u_bytes{"9-18"}/$u_bytes{"total"})*100):0,($u_bytes{"grand-total"} != 0)?(($u_bytes{"9-18"}/$u_bytes{"grand-total"})*100):0);

sub wanted {
  my @params = @_;
  $dummy = pop (@params);
  $u_bytes = pop (@params);
  $u_packets = pop (@params);

  # parse time of flow
  ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
    localtime($startime);

  # time adjustment fudge factor
  $hour = ($hour + 12) % 24;
  if (($min + 15) >= 60) {
    $hour = ($hour + 12) % 24;
  }

  # aggregate usage by group
  if (($hour >= 6) && ($hour <= 15)) { 
    $$u_bytes{"6-15"} += $bytes;
    $$u_packets{"6-15"} += $packets;
  }

  if (($hour >= 14) && ($hour <= 23)) { 
    $$u_bytes{"14-23"} += $bytes;
    $$u_packets{"14-23"} += $packets;
  }

  if (($hour >= 8) && ($hour <= 17)) { 
    $$u_bytes{"8-17"} += $bytes;
    $$u_packets{"8-17"} += $packets;
  }

  if (($hour >= 9) && ($hour <= 18)) { 
    $$u_bytes{"9-18"} += $bytes;
    $$u_packets{"9-18"} += $packets;
  }

  if (($hour >= 22) && ($hour <= 24)) { 
    $$u_bytes{"22-7"} += $bytes;
    $$u_packets{"22-7"} += $packets;
  }

  if (($hour >= 0) && ($hour <= 7)) { 
    $$u_bytes{"22-7"} += $bytes;
    $$u_packets{"22-7"} += $packets;
  }

  $$u_bytes{"total"} += $bytes;
  $$u_packets{"total"} += $packets;

}

