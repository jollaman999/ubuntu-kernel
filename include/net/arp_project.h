/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * arp_project
 *
 * Keep the default gateway from being taken over by ARP spoofing.
 *
 * Copyright (C) 2017-2026 jollaman999 <admin@jollaman999.com>
 */
#ifndef _ARP_PROJECT_H
#define _ARP_PROJECT_H

#define ARP_PROJECT		"arp_project: "
#define ARP_PROJECT_VERSION	"2.5"

/*
 * The gateway record of a device. One per in_device, allocated with it
 * and freed with it, so there is no table to run out of. What it holds
 * is private to net/ipv4/arp.c.
 */
struct arp_gw_rec;

struct arp_gw_rec *arp_gw_rec_alloc(void);
void arp_gw_rec_free(struct arp_gw_rec *rec);

#endif	/* _ARP_PROJECT_H */
