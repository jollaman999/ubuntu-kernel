.. SPDX-License-Identifier: GPL-2.0

============
arp_project
============

Keeps the default gateway from being pointed at somebody else's hardware
address.

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

How a packet is handled
=======================

``arp_gw_check()`` in ``net/ipv4/arp.c`` runs ahead of every path that
can change the ARP table::

  1) find this device's default route gateway      arp_gw_of()
  2) does this packet claim that address?
       no  -> pass it on, done
  3) is the sender hardware address blocked?
       yes -> drop it, done
  4) judge it in arp_gw_claim()

``arp_gw_claim()``::

  nothing protected yet
     ARP table already holds a gateway address -> protect that
     ARP table holds nothing yet               -> protect what this
                                                  packet is about to
                                                  put there

  sender hardware address == protected?
     yes -> the gateway itself, pass it on
     no  -> somebody else is claiming it. Verify, and keep the ARP
            table out of it meanwhile.

The second case matters. Taking the address from the ARP table alone is
too late: on the reply that first resolves the gateway the neighbour
entry is still incomplete, so the protection would only appear on some
later packet and everything in between would go unguarded.

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

A reply counts as an answer only if it comes back to this machine within
``ARP_PROBE_WINDOW`` of that probe, and only one reply per probe is
counted.

===================  =================================  =========================
Outcome              Meaning                            Action
===================  =================================  =========================
both answer          the gateway is there and someone   attack, the claimant is
                     else is claiming its address       blocked
only the claimant    the protected address is gone      replacement, taken only
                                                        when
                                                        allow_gw_hwaddr_change
                                                        is set
claimant silent      the packet named somebody else     nobody is blocked
===================  =================================  =========================

The protected address has to answer once, a claimant two of the three.

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
verification again. It is refused throughout either way; only the
probing waits. A gateway that does come back is picked up on the first
verification after that.

sysfs
=====

``/sys/kernel/arp_project/``

These are one setting for the whole machine, not per interface and not
per network namespace. What is remembered, the protected addresses and
the block list, is per device.

Switches
--------

============================  =======  =====================================
File                          Default  Meaning
============================  =======  =====================================
arp_project_enable                  1  the whole thing on or off
print_arp_info                      0  dump every ARP packet to the log
ignore_gw_update_by_request         1  ignore requests that move the
                                       gateway
ignore_gw_update_by_reply           1  ignore replies that move the
                                       gateway
ignore_proxy_arp                    0  drop proxy ARP requests outright
allow_gw_hwaddr_change              0  take a new gateway address once the
                                       old one is proven gone
attacker_timeout                    0  seconds a block lasts, 0 means until
                                       it is cleared by hand
============================  =======  =====================================

``ignore_proxy_arp`` defaults off here, unlike on the phone kernels.
Proxy ARP is a normal thing to run on a router or a container host.

State
-----

========================  ====  ==================================
File                      Mode  Contents
========================  ====  ==================================
protected_gw_hwaddr       0444  ifindex, gateway address and the
                                protected hardware address, one
                                line each, up to eight gateways
alt_gw_hwaddr             0444  the further ports accepted for each
                                gateway, in the same shape, up to
                                eight per gateway
detected_attacker_hwaddr  0444  ifindex and hardware address of
                                every blocked host, up to sixteen
                                per device, oldest evicted
clear_gw_hwaddr           0200  write 1 to forget those and learn
                                again
clear_attacker_hwaddr     0200  write 1 to unblock all of them
arp_project_version       0444  version
how_to_use                0444  this page, in short
========================  ====  ==================================

The two clear files do different things. ``clear_attacker_hwaddr``
withdraws "this one is an attacker". ``clear_gw_hwaddr`` withdraws "the
gateway is this address", which is what a real router swap needs, and
what a machine that booted while an attack was already running needs.

Using it
========

::

  # what is being protected
  cat /sys/kernel/arp_project/protected_gw_hwaddr
  # 2 192.168.0.1 aa:bb:cc:dd:ee:ff

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

=========================================================  ===================
Line                                                       Meaning
=========================================================  ===================
X is claiming the gateway, probing both                    verification began
ARP spoofing attacker detected as X                        X is blocked
X was detected as an attacker!                             a packet from a
                                                           blocked X was
                                                           dropped
X never answered for the gateway, blocking nobody          the packet named
                                                           somebody else
X stays refused for the gateway, not verifying it again    an earlier refusal
yet                                                        still stands
gateway looks replaced by X, refused because               a replacement was
allow_gw_hwaddr_change is off                              refused
gateway replaced, now protecting X                         a replacement was
                                                           taken
X asked for the gateway it is cached as                    reported only, see
                                                           `Limits`_
=========================================================  ===================

Limits
======

None of these can be closed at the ARP layer.

**The first address learnt is trusted.** A machine booted into an attack
protects the attacker. ``protected_gw_hwaddr`` shows what was taken and
``clear_gw_hwaddr`` is the only way out.

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
Probes are sent in response to a claim, so a slow stream puts its next
packet outside the window.

**An attacker that can silence the gateway** reaches the replacement
verdict. With ``allow_gw_hwaddr_change`` clear the replacement is still
refused and only logged.

**Sizes.** Eight gateways and sixteen blocked addresses per device. Past
the first, further gateways go unprotected with a warning in the log;
past the second, the oldest entry gives way.

**An attacker working through hardware addresses** only fills the block
list. The lasting defence is the protected address.

Source
======

=============================  =====================================
File                           Contents
=============================  =====================================
include/net/arp_project.h      version and log prefix
net/ipv4/arp.c                 protection, verification, block list,
                               sysfs
net/ipv4/fib_semantics.c       ip_fib_get_gw(), the default route's
                               gateway
include/net/ip_fib.h           its declaration
=============================  =====================================

Constants in ``net/ipv4/arp.c``:

======================  =======  ==================================
Name                    Value    Meaning
======================  =======  ==================================
ARP_GW_SLOTS                  8  gateway records
ARP_ATTACKER_SLOTS           16  block list entries
ARP_VERIFY_ROUNDS             3  probe rounds
ARP_VERIFY_INTERVAL          1s  between rounds
ARP_PROBE_WINDOW          300ms  how late a reply may be
ARP_VERIFY_HOLDOFF          60s  how long a refusal stands unasked
ARP_PROTECTED_ANSWERS         1  answers the protected address owes
ARP_CLAIMANT_ANSWERS          2  answers a claimant owes
ARP_GW_CACHE_TTL             1s  default route lookup cache
======================  =======  ==================================
