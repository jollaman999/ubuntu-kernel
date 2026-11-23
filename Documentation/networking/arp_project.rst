.. SPDX-License-Identifier: GPL-2.0

============
arp_project
============

Keeps the gateways of a machine's routes from being pointed at somebody
else's hardware address.

Carried from jolla-kernel_bullhead and jolla-kernel_joan, where it
shipped on 3.10 and 4.4, and reworked so that a permanent block cannot
be turned against the gateway itself.

What it is for
==============

ARP asks the link "who has this address?" and whoever owns it answers
"I do, here is my hardware address". Nothing checks the answer.

So anything on the link that answers for the gateway, first or more
often than the gateway does, gets the ARP table pointed at itself, and
everything leaving the machine goes through it.

arp_project pins the gateway's hardware address and refuses attempts to
move it.

How it works
============

The whole path, in order. Each step has a section of its own below.

1. **The gateways come from the routing table.** When a nexthop joins
   or leaves a device, the FIB calls ``arp_gw_routes_changed()``, and
   ``ARP_GW_SYNC_DELAY`` later ``arp_gw_sync_work()`` walks the routes
   under RTNL and makes a record for every IPv4 gateway of the device.
   Changes that come in the meantime join that one walk. Records are
   made nowhere else. See `Limits`_ for which gateways and how many.

2. **The first address is learnt from this host's own question.** A
   record starts with nothing protected. ``arp_gw_claim()`` fills it
   from a valid ARP table entry, or from the reply to this host's
   request for the gateway. Until then no frame claiming the gateway
   reaches the ARP table.

3. **Every ARP packet from a gateway is judged first.** ``arp_process()``
   calls ``arp_gw_check()`` before it touches the ARP table. The
   protected address passes. A blocked sender is refused, and so is
   every other claim unless it answers this host's own broadcast for the
   gateway. A refused packet is still handled, so a request for this
   host gets its answer; only the ARP table is held back. See
   `How a packet is handled`_.

4. **That one kind of claim is verified.** Unicast probes go to the
   protected address and to the claimant, three rounds a second apart.
   ``arp_gw_verify_work()``, one per network namespace, runs the rounds
   on time and reads the verdict. See `Verification`_.

5. **The verdict is applied.** ``arp_gw_apply_verdict()`` accepts
   another port or refuses it when there is no room left, blocks the
   claimant, takes or refuses a replacement, or blocks nobody, and logs
   which.

6. **Blocks last until they are cleared or time out.** Blocked addresses
   go to the block list of the network namespace, which
   ``arp_is_attacker()`` checks in step 3. A protected address is never
   refused for being on it. The ``clear_*`` files in `sysfs`_ undo a
   block or a learnt address.

How a packet is handled
=======================

``arp_gw_check()`` in ``net/ipv4/arp.c`` runs ahead of every path that
can change the ARP table. Refusing a packet there keeps it off the ARP
table and does nothing more: the packet is still handled, and a request
for this host is answered, because a gateway that gets no answer can no
longer reach this host. That holds while ``ignore_gw_update_by_request``
and ``ignore_gw_update_by_reply`` are set, see `Switches`_::

  1) find the record of the gateway this packet
     claims to be                                   arp_gw_find()
  2) is there one?
       no  -> pass it on, done
  3) is the sender hardware address blocked?
       yes, and not protected -> refuse it, done
       yes, but protected     -> unblock it, go on
  4) judge it in arp_gw_claim()

``arp_gw_claim()``::

  nothing protected yet
     ARP table holds a valid gateway entry    -> protect that
     a reply to this host's request for the
     gateway, addressed to this host, within
     ARP_PROBE_WINDOW, from a unicast address -> protect its sender
     anything else                            -> refuse it quietly

  sender hardware address == protected?
     yes -> the gateway itself, pass it on

  sender hardware address accepted as another port of the gateway?
     a reply this host asked for   -> pass it on
     a reply nobody asked for      -> drop it from the accepted ports,
                                      leave the ARP table as it is
     a request                     -> answer it, keep the table as it is

  somebody else is claiming the gateway
     a reply to a broadcast request this host sent for the gateway,
     addressed to this host, within ARP_PROBE_WINDOW
                                   -> verify, and keep the ARP table
                                      out of it meanwhile
     anything else                 -> refuse it, nothing is probed

A reply nobody asked for is what a spoofing tool sends by default, and a
verification opened by one used to be how a live attacker proved itself
another port of the gateway. Now an attacker has to answer the moment
this host asks the whole link, which it only does to resolve the
gateway from scratch; refreshing an entry asks the address the table
already holds, and nobody else sees that. A port that got in that way
and then sprays replies is dropped on the first one, and a request
never moves the table to a port other than the protected one. Dropping
the port leaves the gateway's ARP entry alone. The reply that got it
dropped carries nothing but a source address anybody can write into a
frame, and failing the entry on it would let one forged reply throw out
a real port's entry and send this host back to broadcasting, which is
the race to answer first all over again. A real port proves itself
again on the next broadcast.

When the table holds nothing yet, the first address is taken from the
reply itself: on the reply that first resolves the gateway the neighbour
entry is still incomplete, so protection read off the table would only
appear on some later packet. Only that one reply can set it. Any
station can send a broadcast reply, a gratuitous one or a request from
the gateway's address before the gateway is first resolved, and taking
the address from it would protect the sender's and make the real
gateway the claimant. Until the address is set those frames are refused
without a log line, since the gateway itself may well ask for this host
before this host asks for it; it is answered, and the table learns the
gateway when this host asks. A unicast address here is one a station
can have: not all zeros and, on Ethernet, not multicast.

Verification
============

A competing claim is not judged on the spot. While it is being checked
the ARP table stays as it was, so nothing is lost by waiting. The
packets themselves are still handled: a gateway asking for this host's
address gets its answer, and needs it to go on reaching this host::

  three times, a second apart:
     send a unicast ARP request for the gateway address to the
     protected address, and another to the claimant

Unicast is the point. A switch delivers a frame addressed to one
hardware address only to the port behind it, so nobody else sees the
question.

The rounds run on time, not on the claimant's packets. The first goes
out with the reply that opens the verification; a work item of the
network namespace sends the other two and reads the verdict a second
after the last, about three seconds after the claim, and closes the
verification. The claimant does not have to say anything more for
that. If the work runs late, ``ARP_VERIFY_DEADLINE`` after the claim
the verdict is read off whatever the rounds collected. Until the
verdict every packet of the claimant is refused.

A reply counts as an answer only if it comes back to this machine within
``ARP_PROBE_WINDOW`` of that probe, and only one reply per probe is
counted.

===================  =================================  =========================
Outcome              Meaning                            Action
===================  =================================  =========================
both answer          one gateway with a second port,    accepted as another port
                     or an attacker live beside it;     with
                     ARP cannot tell which              allow_multi_gw_hwaddr,
                                                        blocked without it;
                                                        refused when all
                                                        ARP_GW_ALT_MACS further
                                                        ports are taken
only the claimant    the protected address is gone      replacement, taken only
                                                        when
                                                        allow_gw_hwaddr_change
                                                        is set, or on the first
                                                        verdict after the
                                                        gateway's route came
                                                        back
claimant silent      the packet named somebody else     nobody is blocked
===================  =================================  =========================

The protected address has to answer once, a claimant two of the three.

A replacement that is taken moves the protection to the new address at
once. The ARP table follows on the new address's own answer: right
after the verdict this host sends it a unicast request, and the reply
comes from the protected address now, so it is taken the usual way.
A port accepted beside the gateway does not move the table. The
protected address is still answering and the table stays with it; the
new port is let through from then on.

Blocking a claimant also fails the gateway's ARP entry when that entry
holds the blocked address, so the next packet resolves the gateway
again. A permanent or noarp entry is left as it was set, and logged:
what the administrator pinned is not for a packet off the link to undo.

The two halves are not equally sound:

- **The protected address answering cannot be forged away.** Nothing on
  the wire stops a live gateway from replying to a request addressed to
  it, so an attacker cannot make it look dead and cannot reach the
  replacement verdict while it is answering.

- **A claimant answering can be manufactured.** See `Limits`_.

A refused claimant usually keeps talking, and every packet of it would
open another verification: the same two probes once a second, for as
long as it kept at it, and never a different verdict. So a refusal
stands for ``ARP_VERIFY_HOLDOFF`` before the claimant is put through a
verification again. That goes for a claimant that never answered, a
replacement that was refused and a further port with no room left. It
is refused throughout either way; only the probing waits. A gateway
that does come back is picked up on the first verification after that.

sysfs
=====

``/sys/kernel/arp_project/``

These are one setting for the whole machine, not per interface and not
per network namespace. The protected addresses are remembered for each
gateway of each device. Each network namespace has a block list of its
own, sixteen slots shared by its devices; each entry belongs to the
device it was caught on and blocks the address only there.
``attacker_timeout`` and ``clear_attacker_hwaddr`` act on the lists of
every namespace at once.

Switches
--------

============================  =======  =====================================
File                          Default  Meaning
============================  =======  =====================================
arp_project_enable                  1  the whole thing on or off
print_arp_info                      0  dump ARP packets to the log, rate
                                       limited per packet
ignore_gw_update_by_request         1  keep refused requests off the ARP
                                       table
ignore_gw_update_by_reply           1  keep refused replies off the ARP
                                       table
ignore_proxy_arp                    0  send no proxy ARP answers; the
                                       request is handled as usual
ignore_gw_redirect                  1  ignore an ICMP redirect from a
                                       gateway to a next hop that is not
                                       one
allow_gw_hwaddr_change              0  take a new gateway address once the
                                       old one is proven gone
allow_multi_gw_hwaddr               1  accept a second address that proves
                                       itself another port of the gateway;
                                       0 blocks it instead
attacker_timeout                    0  seconds a block lasts, 0 means until
                                       it is cleared by hand
============================  =======  =====================================

``attacker_timeout`` takes at most 86400 (``ATTACKER_TIMEOUT_MAX``, a
day); a larger value is refused with ``EINVAL`` and the old one stays.
Writing a value other than 0 starts the count again for every address
already blocked, in every namespace.

``print_arp_info`` checks ``net_ratelimit()`` once per packet, so a
packet is printed whole or not at all, and a flood leaves a few packets
in the log rather than thousands.

``ignore_gw_update_by_request`` and ``ignore_gw_update_by_reply`` are
what makes a refusal hold. With one of them at 0, every packet of that
kind that arp_project refuses still reaches the ARP table: a blocked
address, a claimant under verification, and a frame from the gateway's
address before anything is protected, which can leave an entry behind
to be protected on the next packet. The verdicts and log lines stay the
same; only the table no longer follows them.

``allow_multi_gw_hwaddr`` is a choice between two failures. At 1, the
default, a live attacker that answers this host's broadcast for the
gateway within ``ARP_PROBE_WINDOW`` and then answers the probes
addressed to it is accepted as a further port, and from then on
whichever port answers a broadcast first gets the ARP table, the
attacker included. ``protected_gw_hwaddr`` still names the first
address, and a port is dropped on the first reply nobody asked for, but
one that only speaks when asked stays. At 0 that attacker is blocked,
and so is the real second port of an HA pair or a bonded link: its
answers never reach the ARP table, and a gateway that fails over to it
is cut off. Keep 1 where the gateway may answer from more than one
address, and set 0 where it is known to answer from one. Turning it to 0
drops every accepted further port in every namespace, so each is judged
under the stricter rule on its next claim.

``allow_gw_hwaddr_change`` off still lets one replacement through: on
the first verdict after the gateway's route came back, see `Limits`_.

``ignore_gw_redirect`` covers a way around ARP altogether. An ICMP
redirect that claims to come from a gateway moves the traffic for a
destination to another next hop, and its source address is as easy to
forge as an ARP reply. With this set, a redirect from a gateway a route
of the device goes through, to a next hop that is not such a gateway,
is ignored and logged. One to another gateway of the device is taken as
usual. The kernel's own checks, ``accept_redirects`` among them, still
come first.

``ignore_proxy_arp`` defaults off here, unlike on the phone kernels.
Proxy ARP is a normal thing to run on a router or a container host.
Turned on, it stops only the answer given on another host's behalf.
The request is not dropped: it is handled like any other request for
an address that is not this host's, so an entry the table already
holds for the sender is still refreshed.

State
-----

========================  ====  ==================================
File                      Mode  Contents
========================  ====  ==================================
protected_gw_hwaddr       0400  ifindex, gateway address, the
                                protected hardware address and the
                                namespace inode, one line per
                                gateway a route goes through
alt_gw_hwaddr             0400  the further ports accepted for each
                                gateway, one line per port in the
                                same shape, up to eight per gateway
detected_attacker_hwaddr  0400  ifindex, hardware address and
                                namespace inode of every blocked
                                host, one line each, up to sixteen
                                per namespace, oldest evicted
clear_gw_hwaddr           0200  write 1 to forget those and learn
                                again
clear_attacker_hwaddr     0200  write 1 to unblock all of them
arp_project_version       0444  version
how_to_use                0444  this page, in short
how_to_use_ko             0444  the same in Korean
========================  ====  ==================================

The two clear files do different things. ``clear_attacker_hwaddr``
withdraws "this one is an attacker". ``clear_gw_hwaddr`` withdraws "the
gateway is this address", which is what a real router swap needs, and
what a machine that booted while an attack was already running needs.

The three read files list every network namespace, so they are for
root. They hold one page: when a list does not fit, the lines that do
are followed by one that says so and names the file to read in
``/proc/net/arp_project`` instead.

Per namespace
-------------

``/proc/net/arp_project/`` is the view from inside a network namespace,
a container's included. Like ``/proc/net/arp``, each namespace has its
own files and sees only its own gateways and blocks. The files are
0444, start with a header line and are never cut short.

=================  ===================================================
File               Contents
=================  ===================================================
protected_gw       device, gateway address and protected hardware
                   address, one line per gateway a route goes through
alt_gw             the further ports accepted, one line per port in
                   the same shape
detected_attacker  device and hardware address of every blocked host
=================  ===================================================

Using it
========

::

  # what is being protected
  cat /sys/kernel/arp_project/protected_gw_hwaddr
  # 2 192.0.2.1 aa:bb:cc:dd:ee:ff 4026531833

  # the same, seen from inside one namespace
  ip netns exec NAME cat /proc/net/arp_project/protected_gw
  # Device           Gateway         HWaddress
  # eth0             192.0.2.1       aa:bb:cc:dd:ee:ff

  # what is blocked
  cat /sys/kernel/arp_project/detected_attacker_hwaddr

  # what it decided
  dmesg | grep arp_project

  # the router really was replaced
  echo 1 > /sys/kernel/arp_project/clear_gw_hwaddr

  # let a wrongly blocked host back in
  echo 1 > /sys/kernel/arp_project/clear_attacker_hwaddr

Log lines
---------

==========================================================================  =====================
Line                                                                        Meaning
==========================================================================  =====================
X is claiming the gateway, probing both                                     verification began
ARP spoofing attacker detected as X                                         X is blocked
Deleted gateway from ARP table                                              the gateway's entry
                                                                            held the address
                                                                            just blocked and
                                                                            was failed
gateway entry holding X is static, left in place                            as above, but the
                                                                            entry is permanent
                                                                            or noarp and stays
not blocking X, it is the protected gateway                                 X is protected for
                                                                            a gateway of the
                                                                            device, so it is
                                                                            never blocked
X is a protected gateway, unblocked                                         X was on the block
                                                                            list but is
                                                                            protected for a
                                                                            gateway of the
                                                                            device; its packet
                                                                            passes and the
                                                                            entry goes
X also answers for the gateway, accepting it as another gateway port        both answered and
                                                                            allow_multi_gw_hwaddr
                                                                            is set, X is
                                                                            accepted as another
                                                                            port
X answers for the gateway too, but all 8 further ports are taken; refused   both answered but
                                                                            there is no room
                                                                            for another port,
                                                                            X is refused, not
                                                                            blocked
X was detected as an attacker!                                              a packet from a
                                                                            blocked X was kept
                                                                            off the table
X never answered for the gateway, blocking nobody                           the packet named
                                                                            somebody else
X was a gateway port but answered unasked, dropped                          X was accepted as
                                                                            another port and
                                                                            sent a reply
                                                                            nobody asked for,
                                                                            so it was dropped
                                                                            from the accepted
                                                                            ports; the ARP
                                                                            table keeps what
                                                                            it holds
X claims the gateway without being asked, ignored                           a reply nobody
                                                                            asked for, or a
                                                                            request for this
                                                                            host or a
                                                                            gratuitous one,
                                                                            was refused; a
                                                                            request for some
                                                                            other host is
                                                                            refused silently
X stays refused for the gateway, not verifying it again yet                 an earlier refusal
                                                                            still stands
gateway looks replaced by X, refused because allow_gw_hwaddr_change is off  a replacement was
                                                                            refused
gateway replaced, now protecting X                                          a replacement was
                                                                            taken
gateway changed while its route was away, now protecting X                  the first verdict
                                                                            after the route
                                                                            came back found
                                                                            the old address
                                                                            silent, so X was
                                                                            taken
refused an ICMP redirect from protected gateway X to unprotected Y          a redirect off a
                                                                            gateway was
                                                                            ignored, see
                                                                            ignore_gw_redirect
X asked for the gateway it is cached as                                     reported only, see
                                                                            `Limits`_
==========================================================================  =====================

Limits
======

Most of these cannot be closed at the ARP layer.

**The first address learnt is trusted.** Protection starts from the
first answer to this host's broadcast for the gateway, or from a valid
ARP table entry when there already is one. An attacker that answers that
broadcast before the gateway does is protected, and so is an address
the table already held, from before the route existed or from while
arp_project was off: a machine booted into an attack protects the
attacker. A host that moves to another network runs the same race on
the first verdict after the route comes back, see below.
``protected_gw_hwaddr`` shows what was taken and ``clear_gw_hwaddr`` is
the only way out.

**A live attacker gets in as a further port** at the default
``allow_multi_gw_hwaddr``, if it answers this host's broadcast for the
gateway within ``ARP_PROBE_WINDOW`` and then answers its probes. From
then on whichever port answers a broadcast first gets the ARP table. See
`Switches`_ for what setting it to 0 costs instead.

**Framing another host is not fully closed.** The evidence for blocking,
that a claimant answered a probe, can be manufactured: ARP has nowhere
to carry a nonce, so a reply cannot be tied to the request that asked
for it, only to the moment it arrives. Measured against this code:

===================  ==================  ==================
Forged replies       Framing succeeded   Gateway protection
===================  ==================  ==================
two a second         0 of 10             held
fifty a second       5 of 5              held
===================  ==================  ==================

The gateway stayed protected either way, which is the guarantee worth
having. ``protected_gw_hwaddr`` is that guarantee, not the block list.
The first row still holds with the rounds running on time: measured
again, 0 of 10 framed, the verification opening in 6 of them. The rounds
start from the forged reply that opened the verification and run a
second apart, so an even stream of two a second keeps falling between
the windows. A stream timed to that schedule would land inside them,
and ARP has no way to tell it from a real answer.

**An attacker that can silence the gateway** reaches the replacement
verdict. With ``allow_gw_hwaddr_change`` clear the replacement is still
refused and only logged, except on the first verdict after the
gateway's route came back.

**With ignore_gw_update_by_request or ignore_gw_update_by_reply at 0**
the refusals of that kind of packet are log lines only, and the ARP
table takes the packet anyway. See `Switches`_.

**IEEE 1394 (firewire)** ARP carries no target hardware address, so
there a reply counts as addressed to this host by its target IP alone.
That is enough to take the first protected address from the reply to
this host's own request. On Ethernet the target hardware address is
written by the sender too and proves nothing more; what guards the first
answer is the window after the request and the race to answer first.
Everything else still needs a target hardware address that is this
host's, so a claim never opens a verification there, and neither a
replacement nor a further port is ever taken.

**Which gateways.** Every IPv4 gateway a route of the device goes
through, in any table, the default route's and every other one's alike,
and the gateway of every ``ip nexthop`` object, whether a route uses it
yet or not. A backup default route behind a lower metric is protected
before it is ever used.

The records follow the routing table, not the packets. The FIB calls
``arp_gw_routes_changed()`` whenever a nexthop joins or leaves a device,
the nexthop notifier does the same for nexthop objects, and a work item
then walks the routes under RTNL ``ARP_GW_SYNC_DELAY`` later and brings
every device's records in line. Changes that come in the meantime join
that walk, so filling a table with many routes costs a few walks rather
than one per route. Records are only made there, so the receive path
allocates nothing and nothing arriving on the wire can make the list
grow. While ``arp_project_enable`` is 0 the routes are not followed at
all and the lists show what they held when it went off; turning it on
again syncs every namespace.

A gateway whose last route goes away keeps its record, but it is no
longer consulted and no longer listed. Routes come and go with the
link, and a gateway that comes back finds its protected address still
there instead of learning it again, unguarded.

A host that moved to another network can find a different router at
the same gateway address, and the old protected address then never
answers again. So a record whose route comes back is judged once on the
link it came back on: when the first verdict after that finds the
claimant answering and the old address silent, the claimant is taken
whatever ``allow_gw_hwaddr_change`` says. After a link flap the old
address answers and keeps the gateway. The exception ends with that
verdict, or as soon as the old address answers something this host
asked. An attacker that answers the broadcast and its probes while the
old address is silent is taken just the same, so it is the same race as
the first address learnt.

**Sizes.** Up to 64 routed gateways per device; a route through a 65th
is left unprotected and logged. Up to 8 records of gateways that lost
their routes; past that the oldest goes. Up to 8 further ports per
gateway; past that one more port that proves itself is refused for
``ARP_VERIFY_HOLDOFF``, not blocked. Sixteen blocked addresses per
network namespace, shared by its devices and gateways; past that the
oldest entry of that namespace gives way, and the lists of other
namespaces are not touched.

**An attacker working through hardware addresses** only fills the block
list. The lasting defence is the protected address.

Source
======

=============================  =====================================
File                           Contents
=============================  =====================================
include/net/arp_project.h      version, log prefix, and what the FIB
                               and the redirect path call
net/ipv4/arp.c                 protection, verification, block list,
                               sysfs and /proc/net/arp_project
net/ipv4/fib_semantics.c       ip_fib_for_each_gw(), the gateways of
                               a device's nexthops, and the calls to
                               arp_gw_routes_changed()
include/net/ip_fib.h           its declaration
net/ipv4/route.c               the call to arp_gw_redirect_refused()
                               in __ip_do_redirect()
=============================  =====================================

Constants in ``net/ipv4/arp.c``:

======================  =======  ==================================
Name                    Value    Meaning
======================  =======  ==================================
ARP_ATTACKER_SLOTS           16  block list entries per namespace
ARP_VERIFY_ROUNDS             3  probe rounds
ARP_VERIFY_INTERVAL          1s  between rounds, and from the last
                                 round to the verdict
ARP_VERIFY_DEADLINE          4s  the verdict at the latest, when the
                                 rounds run late
ARP_PROBE_WINDOW          300ms  how late a reply may be
ARP_VERIFY_HOLDOFF          60s  how long a refusal stands unasked
ARP_PROTECTED_ANSWERS         1  answers the protected address owes
ARP_CLAIMANT_ANSWERS          2  answers a claimant owes
ARP_GW_ROUTED_MAX            64  routed gateways per device
ARP_GW_UNROUTED_MAX           8  records kept after the route went
ARP_GW_ALT_MACS               8  further ports per gateway
ARP_GW_SYNC_DELAY         100ms  how long route changes gather
                                 before one sync
======================  =======  ==================================
