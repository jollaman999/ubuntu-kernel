/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * arp_project
 *
 * Keep the gateways the routes go through from being taken over by ARP
 * spoofing.
 *
 * Copyright (C) 2017-2026 jollaman999 <admin@jollaman999.com>
 */
#ifndef _ARP_PROJECT_H
#define _ARP_PROJECT_H

#define ARP_PROJECT		"arp_project: "
#define ARP_PROJECT_VERSION	"2.7"

struct net;

/*
 * The gateway records of a device, one for every gateway its routes go
 * through. The set hangs off the in_device, allocated with it and freed
 * with it. What it holds is private to net/ipv4/arp.c.
 */
struct arp_gw_dev;

struct arp_gw_dev *arp_gw_dev_alloc(void);
void arp_gw_dev_free(struct arp_gw_dev *gd);

/*
 * Called from the FIB whenever a nexthop joins or leaves a device's
 * nexthop list, so the gateway records can be brought in line with the
 * routes. Any context.
 */
void arp_gw_routes_changed(struct net *net);

#endif	/* _ARP_PROJECT_H */
