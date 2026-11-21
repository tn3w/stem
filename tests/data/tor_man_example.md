# NAME

tor - The second-generation onion router

# SYNOPSIS

**tor** \[*OPTION* *value*\]\...

# DESCRIPTION

Tor is a connection-oriented anonymizing communication service. Users
choose a source-routed path through a set of nodes, and negotiate a
\"virtual circuit\" through the network, in which each node knows its
predecessor and successor, but no others. Traffic flowing down the
circuit is unwrapped by a symmetric key at each node, which reveals the
downstream node.

# COMMAND-LINE OPTIONS

**-h**, **-help**

> Display a short help message and exit.

**-f** *FILE*

> Specify a new configuration file to contain further Tor configuration
> options OR pass **-** to make Tor read its configuration from standard
> input. (Default: \@CONFDIR@/torrc, or \$HOME/.torrc if that file is
> not found)

**\--allow-missing-torrc**

> Do not require that configuration file specified by **-f** exist if
> default torrc can be accessed.

Options on the command line override those in configuration files. See
the next section for more information.

# THE CONFIGURATION FILE FORMAT

All configuration options in a configuration are written on a single
line by default. They take the form of an option name and a value, or an
option name and a quoted value (option value or option \"value\").
Anything after a \# character is treated as a comment. Options are
case-insensitive. C-style escaped characters are allowed inside quoted
values. To split one configuration entry into multiple lines, use a
single backslash character (\\) before the end of the line. Comments can
be used in such multiline entries, but they must start at the beginning
of a line.

By default, an option on the command line overrides an option found in
the configuration file, and an option in a configuration file overrides
one in the defaults file.

# GENERAL OPTIONS

**BandwidthRate** *N*
**bytes**\|**KBytes**\|**MBytes**\|**GBytes**\|**KBits**\|**MBits**\|**GBits**

> A token bucket limits the average incoming bandwidth usage on this
> node to the specified number of bytes per second, and the average
> outgoing bandwidth usage to that same value. If you want to run a
> relay in the public network, this needs to be *at the very least* 75
> KBytes for a relay (that is, 600 kbits) or 50 KBytes for a bridge (400
> kbits) --- but of course, more is better; we recommend at least 250
> KBytes (2 mbits) if possible. (Default: 1 GByte)
>
> With this option, and in other options that take arguments in bytes,
> KBytes, and so on, other formats are also supported. Notably,
> \"KBytes\" can also be written as \"kilobytes\" or \"kb\"; \"MBytes\"
> can be written as \"megabytes\" or \"MB\"; \"kbits\" can be written as
> \"kilobits\"; and so forth. Tor also accepts \"byte\" and \"bit\" in
> the singular. The prefixes \"tera\" and \"T\" are also recognized. If
> no units are given, we default to bytes. To avoid confusion, we
> recommend writing \"bytes\" or \"bits\" explicitly, since it's easy to
> forget that \"B\" means bytes, not bits.

**BandwidthBurst** *N*
**bytes**\|**KBytes**\|**MBytes**\|**GBytes**\|**KBits**\|**MBits**\|**GBits**

> Limit the maximum token bucket size (also known as the burst) to the
> given number of bytes in each direction. (Default: 1 GByte)

**MaxAdvertisedBandwidth** *N*
**bytes**\|**KBytes**\|**MBytes**\|**GBytes**\|**KBits**\|**MBits**\|**GBits**

> If set, we will not advertise more than this amount of bandwidth for
> our BandwidthRate. Server operators who want to reduce the number of
> clients who ask to build circuits through them (since this is
> proportional to advertised bandwidth rate) can thus reduce the CPU
> demands on their server without impacting network performance.

# CLIENT OPTIONS

The following options are useful only for clients (that is, if
**SocksPort**, **TransPort**, **DNSPort**, or **NATDPort** is non-zero):

**Bridge** \[*transport*\] *IP*:*ORPort* \[*fingerprint*\]

> When set along with UseBridges, instructs Tor to use the relay at
> \"IP:ORPort\" as a \"bridge\" relaying into the Tor network. If
> \"fingerprint\" is provided (using the same format as for
> DirAuthority), we will verify that the relay running at that location
> has the right fingerprint. We also use fingerprint to look up the
> bridge descriptor at the bridge authority, if it's provided and if
> UpdateBridgesFromAuthority is set too.
>
> If \"transport\" is provided, and matches to a ClientTransportPlugin
> line, we use that pluggable transports proxy to transfer data to the
> bridge.

# SIGNALS

Tor catches the following signals:

**SIGTERM**

> Tor will catch this, clean up and sync to disk if necessary, and exit.

**SIGINT**

> Tor clients behave as with SIGTERM; but Tor servers will do a
> controlled slow shutdown, closing listeners and waiting 30 seconds
> before exiting. (The delay can be configured with the
> ShutdownWaitLength config option.)

**SIGHUP**

> The signal instructs Tor to reload its configuration (including
> closing and reopening logs), and kill and restart its helper processes
> if applicable.

# FILES

**\@CONFDIR@/torrc**

> The configuration file, which contains \"option value\" pairs.

**\$HOME/.torrc**

> Fallback location for torrc, if \@CONFDIR@/torrc is not found.

**\@LOCALSTATEDIR@/lib/tor/**

> The tor process stores keys and other data here.

*DataDirectory***/cached-status/**

> The most recently downloaded network status document for each
> authority. Each file holds one such document; the filenames are the
> hexadecimal identity key fingerprints of the directory authorities.
> Mostly obsolete.

*DataDirectory***/cached-certs**

> This file holds downloaded directory key certificates that are used to
> verify authenticity of documents generated by Tor directory
> authorities.

*DataDirectory***/state**

> A set of persistent key-value mappings. These are documented in the
> file. These include:
>
> > ·
> >
> > The current entry guards and their status.
>
> > ·
> >
> > The current bandwidth accounting values (unused so far; see below).
>
> > ·
> >
> > When the file was last written
>
> > ·
> >
> > What version of Tor generated the state file
>
> > ·
> >
> > A short history of bandwidth usage, as produced in the server
> > descriptors.

*DataDirectory***/bw_accounting**

> Used to track bandwidth accounting values (when the current period
> starts and ends; how much has been read and written so far this
> period). This file is obsolete, and the data is now stored in the
> state file as well. Only used when bandwidth accounting is enabled.

# SEE ALSO

**torsocks**(1), **torify**(1)

**https://www.torproject.org/**

**torspec:** **https://spec.torproject.org**

# BUGS

Plenty, probably. Tor is still in development. Please report them at
https://trac.torproject.org/.

# AUTHORS

Roger Dingledine \[arma at mit.edu\], Nick Mathewson \[nickm at
alum.mit.edu\].
