// SPDX-License-Identifier: GPL-2.0-or-later
/* linux/net/ipv4/arp.c
 *
 * Copyright (C) 1994 by Florian  La Roche
 *
 * arp_project, the gateway spoofing defence in this file:
 * Copyright (C) 2017-2026 jollaman999 <admin@jollaman999.com>
 *
 * This module implements the Address Resolution Protocol ARP (RFC 826),
 * which is used to convert IP addresses (or in the future maybe other
 * high-level addresses) into a low-level hardware address (like an Ethernet
 * address).
 *
 * Fixes:
 *		Alan Cox	:	Removed the Ethernet assumptions in
 *					Florian's code
 *		Alan Cox	:	Fixed some small errors in the ARP
 *					logic
 *		Alan Cox	:	Allow >4K in /proc
 *		Alan Cox	:	Make ARP add its own protocol entry
 *		Ross Martin     :       Rewrote arp_rcv() and arp_get_info()
 *		Stephen Henson	:	Add AX25 support to arp_get_info()
 *		Alan Cox	:	Drop data when a device is downed.
 *		Alan Cox	:	Use init_timer().
 *		Alan Cox	:	Double lock fixes.
 *		Martin Seine	:	Move the arphdr structure
 *					to if_arp.h for compatibility.
 *					with BSD based programs.
 *		Andrew Tridgell :       Added ARP netmask code and
 *					re-arranged proxy handling.
 *		Alan Cox	:	Changed to use notifiers.
 *		Niibe Yutaka	:	Reply for this device or proxies only.
 *		Alan Cox	:	Don't proxy across hardware types!
 *		Jonathan Naylor :	Added support for NET/ROM.
 *		Mike Shaver     :       RFC1122 checks.
 *		Jonathan Naylor :	Only lookup the hardware address for
 *					the correct hardware type.
 *		Germano Caronni	:	Assorted subtle races.
 *		Craig Schlenter :	Don't modify permanent entry
 *					during arp_rcv.
 *		Russ Nelson	:	Tidied up a few bits.
 *		Alexey Kuznetsov:	Major changes to caching and behaviour,
 *					eg intelligent arp probing and
 *					generation
 *					of host down events.
 *		Alan Cox	:	Missing unlock in device events.
 *		Eckes		:	ARP ioctl control errors.
 *		Alexey Kuznetsov:	Arp free fix.
 *		Manuel Rodriguez:	Gratuitous ARP.
 *              Jonathan Layes  :       Added arpd support through kerneld
 *                                      message queue (960314)
 *		Mike Shaver	:	/proc/sys/net/ipv4/arp_* support
 *		Mike McLagan    :	Routing by source
 *		Stuart Cheshire	:	Metricom and grat arp fixes
 *					*** FOR 2.1 clean this up ***
 *		Lawrence V. Stefani: (08/12/96) Added FDDI support.
 *		Alan Cox	:	Took the AP1000 nasty FDDI hack and
 *					folded into the mainstream FDDI code.
 *					Ack spit, Linus how did you allow that
 *					one in...
 *		Jes Sorensen	:	Make FDDI work again in 2.1.x and
 *					clean up the APFDDI & gen. FDDI bits.
 *		Alexey Kuznetsov:	new arp state machine;
 *					now it is in net/core/neighbour.c.
 *		Krzysztof Halasa:	Added Frame Relay ARP support.
 *		Arnaldo C. Melo :	convert /proc/net/arp to seq_file
 *		Shmulik Hen:		Split arp_send to arp_create and
 *					arp_xmit so intermediate drivers like
 *					bonding can change the skb before
 *					sending (e.g. insert 8021q tag).
 *		Harald Welte	:	convert to make use of jenkins hash
 *		Jesper D. Brouer:       Proxy ARP PVLAN RFC 3069 support.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/hex.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/fddidevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/ax25.h>
#include <net/dst_metadata.h>
#include <net/ip_tunnels.h>

#include <linux/uaccess.h>

#include <linux/netfilter_arp.h>

/* arp_project */
#include <linux/kobject.h>
#include <net/ip_fib.h>
#include <net/arp_project.h>

static bool arp_project_enable = true;
static bool print_arp_info;
static bool ignore_gw_update_by_request = true;
static bool ignore_gw_update_by_reply = true;
/*
 * Proxy ARP is a normal thing to run on a router or a container host, so
 * unlike the phone kernel this is off by default here.
 */
static bool ignore_proxy_arp;

/*
 * Seconds a blocked hardware address stays blocked. 0, the default,
 * keeps it until clear_attacker_hwaddr is written.
 */
static unsigned int attacker_timeout;
#define ATTACKER_TIMEOUT_MAX 86400

/*
 *	Interface to generic neighbour cache.
 */
static u32 arp_hash(const void *pkey, const struct net_device *dev, __u32 *hash_rnd);
static bool arp_key_eq(const struct neighbour *n, const void *pkey);
static int arp_constructor(struct neighbour *neigh);
static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb);
static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb);
static void parp_redo(struct sk_buff *skb);
static int arp_is_multicast(const void *pkey);

static const struct neigh_ops arp_generic_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_connected_output,
};

static const struct neigh_ops arp_hh_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_resolve_output,
};

static const struct neigh_ops arp_direct_ops = {
	.family =		AF_INET,
	.output =		neigh_direct_output,
	.connected_output =	neigh_direct_output,
};

struct neigh_table arp_tbl = {
	.family		= AF_INET,
	.key_len	= 4,
	.protocol	= cpu_to_be16(ETH_P_IP),
	.hash		= arp_hash,
	.key_eq		= arp_key_eq,
	.constructor	= arp_constructor,
	.proxy_redo	= parp_redo,
	.is_multicast	= arp_is_multicast,
	.id		= "arp_cache",
	.parms		= {
		.tbl			= &arp_tbl,
		.reachable_time		= 30 * HZ,
		.data	= {
			[NEIGH_VAR_MCAST_PROBES] = 3,
			[NEIGH_VAR_UCAST_PROBES] = 3,
			[NEIGH_VAR_RETRANS_TIME] = 1 * HZ,
			[NEIGH_VAR_BASE_REACHABLE_TIME] = 30 * HZ,
			[NEIGH_VAR_DELAY_PROBE_TIME] = 5 * HZ,
			[NEIGH_VAR_INTERVAL_PROBE_TIME_MS] = 5 * HZ,
			[NEIGH_VAR_GC_STALETIME] = 60 * HZ,
			[NEIGH_VAR_QUEUE_LEN_BYTES] = SK_WMEM_DEFAULT,
			[NEIGH_VAR_PROXY_QLEN] = 64,
			[NEIGH_VAR_ANYCAST_DELAY] = 1 * HZ,
			[NEIGH_VAR_PROXY_DELAY]	= (8 * HZ) / 10,
			[NEIGH_VAR_LOCKTIME] = 1 * HZ,
		},
	},
	.gc_interval	= 30 * HZ,
	.gc_thresh1	= 128,
	.gc_thresh2	= 512,
	.gc_thresh3	= 1024,
};
EXPORT_SYMBOL(arp_tbl);

int arp_mc_map(__be32 addr, u8 *haddr, struct net_device *dev, int dir)
{
	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		ip_eth_mc_map(addr, haddr);
		return 0;
	case ARPHRD_INFINIBAND:
		ip_ib_mc_map(addr, dev->broadcast, haddr);
		return 0;
	case ARPHRD_IPGRE:
		ip_ipgre_mc_map(addr, dev->broadcast, haddr);
		return 0;
	default:
		if (dir) {
			memcpy(haddr, dev->broadcast, dev->addr_len);
			return 0;
		}
	}
	return -EINVAL;
}


static u32 arp_hash(const void *pkey,
		    const struct net_device *dev,
		    __u32 *hash_rnd)
{
	return arp_hashfn(pkey, dev, hash_rnd);
}

static bool arp_key_eq(const struct neighbour *neigh, const void *pkey)
{
	return neigh_key_eq32(neigh, pkey);
}

static int arp_constructor(struct neighbour *neigh)
{
	__be32 addr;
	struct net_device *dev = neigh->dev;
	struct in_device *in_dev;
	struct neigh_parms *parms;
	u32 inaddr_any = INADDR_ANY;

	if (dev->flags & (IFF_LOOPBACK | IFF_POINTOPOINT))
		memcpy(neigh->primary_key, &inaddr_any, arp_tbl.key_len);

	addr = *(__be32 *)neigh->primary_key;
	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev) {
		rcu_read_unlock();
		return -EINVAL;
	}

	neigh->type = inet_addr_type_dev_table(dev_net(dev), dev, addr);

	parms = in_dev->arp_parms;
	__neigh_parms_put(neigh->parms);
	neigh->parms = neigh_parms_clone(parms);
	rcu_read_unlock();

	if (!dev->header_ops) {
		neigh->nud_state = NUD_NOARP;
		neigh->ops = &arp_direct_ops;
		neigh->output = neigh_direct_output;
	} else {
		/* Good devices (checked by reading texts, but only Ethernet is
		   tested)

		   ARPHRD_ETHER: (ethernet, apfddi)
		   ARPHRD_FDDI: (fddi)
		   ARPHRD_IEEE802: (tr)
		   ARPHRD_METRICOM: (strip)
		   ARPHRD_ARCNET:
		   etc. etc. etc.

		   ARPHRD_IPDDP will also work, if author repairs it.
		   I did not it, because this driver does not work even
		   in old paradigm.
		 */

		if (neigh->type == RTN_MULTICAST) {
			neigh->nud_state = NUD_NOARP;
			arp_mc_map(addr, neigh->ha, dev, 1);
		} else if (dev->flags & (IFF_NOARP | IFF_LOOPBACK)) {
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->dev_addr, dev->addr_len);
		} else if (neigh->type == RTN_BROADCAST ||
			   (dev->flags & IFF_POINTOPOINT)) {
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->broadcast, dev->addr_len);
		}

		if (dev->header_ops->cache)
			neigh->ops = &arp_hh_ops;
		else
			neigh->ops = &arp_generic_ops;

		if (neigh->nud_state & NUD_VALID)
			neigh->output = neigh->ops->connected_output;
		else
			neigh->output = neigh->ops->output;
	}
	return 0;
}

static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb)
{
	dst_link_failure(skb);
	kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_FAILED);
}

/*
 * arp_project
 *
 * Print ARP packet informations
 *
 * @dev - net device
 * @arp - arp header
 * @is_send - 0: Received ARP, 1: Sending ARP
 */
static void arp_print_info(struct net_device *dev, struct arphdr *arp,
			   int is_send)
{
	unsigned char *arp_ptr;
	unsigned char *sha, *tha;
	unsigned char *sip, *tip;

	arp_ptr = (unsigned char *)(arp + 1);
	sha = arp_ptr;
	arp_ptr += dev->addr_len;
	sip = arp_ptr;
	arp_ptr += 4;
	tha = arp_ptr;
	arp_ptr += dev->addr_len;
	tip = arp_ptr;

	pr_info(ARP_PROJECT "%s - =============== ARP Info ===============\n",
		__func__);
	pr_info(ARP_PROJECT "%s - %s dev_addr: %*phC\n", __func__,
		is_send ? "Sending" : "Received", dev->addr_len, dev->dev_addr);

	if (arp->ar_op == htons(ARPOP_REQUEST))
		pr_info(ARP_PROJECT "%s - Operation: Request(1)\n", __func__);
	else if (arp->ar_op == htons(ARPOP_REPLY))
		pr_info(ARP_PROJECT "%s - Operation: Reply(2)\n", __func__);

	pr_info(ARP_PROJECT "%s - Sender HW: %*phC\n", __func__,
		dev->addr_len, sha);
	pr_info(ARP_PROJECT "%s - Sender IP: %pI4\n", __func__, sip);
	pr_info(ARP_PROJECT "%s - Target HW: %*phC\n", __func__,
		dev->addr_len, tha);
	pr_info(ARP_PROJECT "%s - Target IP: %pI4\n", __func__, tip);
}

/* Create and send an arp packet. */
static void arp_send_dst(int type, int ptype, __be32 dest_ip,
			 struct net_device *dev, __be32 src_ip,
			 const unsigned char *dest_hw,
			 const unsigned char *src_hw,
			 const unsigned char *target_hw,
			 struct dst_entry *dst)
{
	struct sk_buff *skb;

	/* arp on this interface. */
	if (dev->flags & IFF_NOARP)
		return;

	skb = arp_create(type, ptype, dest_ip, dev, src_ip,
			 dest_hw, src_hw, target_hw);
	if (!skb)
		return;

	/* arp_project */
	if (arp_project_enable && print_arp_info)
		arp_print_info(dev, arp_hdr(skb), 1);

	skb_dst_set(skb, dst_clone(dst));
	arp_xmit(skb);
}

void arp_send(int type, int ptype, __be32 dest_ip,
	      struct net_device *dev, __be32 src_ip,
	      const unsigned char *dest_hw, const unsigned char *src_hw,
	      const unsigned char *target_hw)
{
	arp_send_dst(type, ptype, dest_ip, dev, src_ip, dest_hw, src_hw,
		     target_hw, NULL);
}
EXPORT_SYMBOL(arp_send);

static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb)
{
	__be32 saddr = 0;
	u8 dst_ha[MAX_ADDR_LEN], *dst_hw = NULL;
	struct net_device *dev = neigh->dev;
	__be32 target = *(__be32 *)neigh->primary_key;
	int probes = atomic_read(&neigh->probes);
	struct in_device *in_dev;
	struct dst_entry *dst = NULL;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev) {
		rcu_read_unlock();
		return;
	}
	switch (IN_DEV_ARP_ANNOUNCE(in_dev)) {
	default:
	case 0:		/* By default announce any local IP */
		if (skb && inet_addr_type_dev_table(dev_net(dev), dev,
					  ip_hdr(skb)->saddr) == RTN_LOCAL)
			saddr = ip_hdr(skb)->saddr;
		break;
	case 1:		/* Restrict announcements of saddr in same subnet */
		if (!skb)
			break;
		saddr = ip_hdr(skb)->saddr;
		if (inet_addr_type_dev_table(dev_net(dev), dev,
					     saddr) == RTN_LOCAL) {
			/* saddr should be known to target */
			if (inet_addr_onlink(in_dev, target, saddr))
				break;
		}
		saddr = 0;
		break;
	case 2:		/* Avoid secondary IPs, get a primary/preferred one */
		break;
	}
	rcu_read_unlock();

	if (!saddr)
		saddr = inet_select_addr(dev, target, RT_SCOPE_LINK);

	probes -= NEIGH_VAR(neigh->parms, UCAST_PROBES);
	if (probes < 0) {
		if (!(READ_ONCE(neigh->nud_state) & NUD_VALID))
			pr_debug("trying to ucast probe in NUD_INVALID\n");
		neigh_ha_snapshot(dst_ha, neigh, dev);
		dst_hw = dst_ha;
	} else {
		probes -= NEIGH_VAR(neigh->parms, APP_PROBES);
		if (probes < 0) {
			neigh_app_ns(neigh);
			return;
		}
	}

	if (skb && !(dev->priv_flags & IFF_XMIT_DST_RELEASE))
		dst = skb_dst(skb);
	arp_send_dst(ARPOP_REQUEST, ETH_P_ARP, target, dev, saddr,
		     dst_hw, dev->dev_addr, NULL, dst);
}

static int arp_ignore(struct in_device *in_dev, __be32 sip, __be32 tip)
{
	struct net *net = dev_net(in_dev->dev);
	int scope;

	switch (IN_DEV_ARP_IGNORE(in_dev)) {
	case 0:	/* Reply, the tip is already validated */
		return 0;
	case 1:	/* Reply only if tip is configured on the incoming interface */
		sip = 0;
		scope = RT_SCOPE_HOST;
		break;
	case 2:	/*
		 * Reply only if tip is configured on the incoming interface
		 * and is in same subnet as sip
		 */
		scope = RT_SCOPE_HOST;
		break;
	case 3:	/* Do not reply for scope host addresses */
		sip = 0;
		scope = RT_SCOPE_LINK;
		in_dev = NULL;
		break;
	case 4:	/* Reserved */
	case 5:
	case 6:
	case 7:
		return 0;
	case 8:	/* Do not reply */
		return 1;
	default:
		return 0;
	}
	return !inet_confirm_addr(net, in_dev, sip, tip, scope);
}

static int arp_accept(struct in_device *in_dev, __be32 sip)
{
	struct net *net = dev_net(in_dev->dev);
	int scope = RT_SCOPE_LINK;

	switch (IN_DEV_ARP_ACCEPT(in_dev)) {
	case 0: /* Don't create new entries from garp */
		return 0;
	case 1: /* Create new entries from garp */
		return 1;
	case 2: /* Create a neighbor in the arp table only if sip
		 * is in the same subnet as an address configured
		 * on the interface that received the garp message
		 */
		return !!inet_confirm_addr(net, in_dev, sip, 0, scope);
	default:
		return 0;
	}
}

static int arp_filter(__be32 sip, __be32 tip, struct net_device *dev)
{
	struct rtable *rt;
	int flag = 0;
	/*unsigned long now; */
	struct net *net = dev_net(dev);

	rt = ip_route_output(net, sip, tip, 0, l3mdev_master_ifindex_rcu(dev),
			     RT_SCOPE_UNIVERSE);
	if (IS_ERR(rt))
		return 1;
	if (rt->dst.dev != dev) {
		__NET_INC_STATS(net, LINUX_MIB_ARPFILTER);
		flag = 1;
	}
	ip_rt_put(rt);
	return flag;
}

/*
 * Check if we can use proxy ARP for this path
 */
static inline int arp_fwd_proxy(struct in_device *in_dev,
				struct net_device *dev,	struct rtable *rt)
{
	struct in_device *out_dev;
	int imi, omi = -1;

	if (rt->dst.dev == dev)
		return 0;

	if (!IN_DEV_PROXY_ARP(in_dev))
		return 0;
	imi = IN_DEV_MEDIUM_ID(in_dev);
	if (imi == 0)
		return 1;
	if (imi == -1)
		return 0;

	/* place to check for proxy_arp for routes */

	out_dev = __in_dev_get_rcu(rt->dst.dev);
	if (out_dev)
		omi = IN_DEV_MEDIUM_ID(out_dev);

	return omi != imi && omi != -1;
}

/*
 * Check for RFC3069 proxy arp private VLAN (allow to send back to same dev)
 *
 * RFC3069 supports proxy arp replies back to the same interface.  This
 * is done to support (ethernet) switch features, like RFC 3069, where
 * the individual ports are not allowed to communicate with each
 * other, BUT they are allowed to talk to the upstream router.  As
 * described in RFC 3069, it is possible to allow these hosts to
 * communicate through the upstream router, by proxy_arp'ing.
 *
 * RFC 3069: "VLAN Aggregation for Efficient IP Address Allocation"
 *
 *  This technology is known by different names:
 *    In RFC 3069 it is called VLAN Aggregation.
 *    Cisco and Allied Telesyn call it Private VLAN.
 *    Hewlett-Packard call it Source-Port filtering or port-isolation.
 *    Ericsson call it MAC-Forced Forwarding (RFC Draft).
 *
 */
static inline int arp_fwd_pvlan(struct in_device *in_dev,
				struct net_device *dev,	struct rtable *rt,
				__be32 sip, __be32 tip)
{
	/* Private VLAN is only concerned about the same ethernet segment */
	if (rt->dst.dev != dev)
		return 0;

	/* Don't reply on self probes (often done by windowz boxes)*/
	if (sip == tip)
		return 0;

	if (IN_DEV_PROXY_ARP_PVLAN(in_dev))
		return 1;
	else
		return 0;
}

/*
 *	Interface to link layer: send routine and receive handler.
 */

/*
 *	Create an arp packet. If dest_hw is not set, we create a broadcast
 *	message.
 */
struct sk_buff *arp_create(int type, int ptype, __be32 dest_ip,
			   struct net_device *dev, __be32 src_ip,
			   const unsigned char *dest_hw,
			   const unsigned char *src_hw,
			   const unsigned char *target_hw)
{
	struct sk_buff *skb;
	struct arphdr *arp;
	unsigned char *arp_ptr;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;

	/*
	 *	Allocate a buffer
	 */

	skb = alloc_skb(arp_hdr_len(dev) + hlen + tlen, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	skb_put(skb, arp_hdr_len(dev));
	skb->dev = dev;
	skb->protocol = htons(ETH_P_ARP);
	if (!src_hw)
		src_hw = dev->dev_addr;
	if (!dest_hw)
		dest_hw = dev->broadcast;

	/* Fill the device header for the ARP frame.
	 * Note: skb->head can be changed.
	 */
	if (dev_hard_header(skb, dev, ptype, dest_hw, src_hw, skb->len) < 0)
		goto out;

	arp = arp_hdr(skb);
	/*
	 * Fill out the arp protocol part.
	 *
	 * The arp hardware type should match the device type, except for FDDI,
	 * which (according to RFC 1390) should always equal 1 (Ethernet).
	 */
	/*
	 *	Exceptions everywhere. AX.25 uses the AX.25 PID value not the
	 *	DIX code for the protocol. Make these device structure fields.
	 */
	switch (dev->type) {
	default:
		arp->ar_hrd = htons(dev->type);
		arp->ar_pro = htons(ETH_P_IP);
		break;

#if IS_ENABLED(CONFIG_AX25)
	case ARPHRD_AX25:
		arp->ar_hrd = htons(ARPHRD_AX25);
		arp->ar_pro = htons(AX25_P_IP);
		break;

#if IS_ENABLED(CONFIG_NETROM)
	case ARPHRD_NETROM:
		arp->ar_hrd = htons(ARPHRD_NETROM);
		arp->ar_pro = htons(AX25_P_IP);
		break;
#endif
#endif

#if IS_ENABLED(CONFIG_FDDI)
	case ARPHRD_FDDI:
		arp->ar_hrd = htons(ARPHRD_ETHER);
		arp->ar_pro = htons(ETH_P_IP);
		break;
#endif
	}

	arp->ar_hln = dev->addr_len;
	arp->ar_pln = 4;
	arp->ar_op = htons(type);

	arp_ptr = (unsigned char *)(arp + 1);

	memcpy(arp_ptr, src_hw, dev->addr_len);
	arp_ptr += dev->addr_len;
	memcpy(arp_ptr, &src_ip, 4);
	arp_ptr += 4;

	switch (dev->type) {
#if IS_ENABLED(CONFIG_FIREWIRE_NET)
	case ARPHRD_IEEE1394:
		break;
#endif
	default:
		if (target_hw)
			memcpy(arp_ptr, target_hw, dev->addr_len);
		else
			memset(arp_ptr, 0, dev->addr_len);
		arp_ptr += dev->addr_len;
	}
	memcpy(arp_ptr, &dest_ip, 4);

	return skb;

out:
	kfree_skb(skb);
	return NULL;
}
EXPORT_SYMBOL(arp_create);

static int arp_xmit_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	return dev_queue_xmit(skb);
}

/*
 *	Send an arp packet.
 */
void arp_xmit(struct sk_buff *skb)
{
	rcu_read_lock();
	/* Send it off, maybe filter it using firewalling first.  */
	NF_HOOK(NFPROTO_ARP, NF_ARP_OUT,
		dev_net_rcu(skb->dev), NULL, skb, NULL, skb->dev,
		arp_xmit_finish);
	rcu_read_unlock();
}
EXPORT_SYMBOL(arp_xmit);

static bool arp_is_garp(struct net *net, struct net_device *dev,
			int *addr_type, __be16 ar_op,
			__be32 sip, __be32 tip,
			unsigned char *sha, unsigned char *tha)
{
	bool is_garp = tip == sip;

	/* Gratuitous ARP _replies_ also require target hwaddr to be
	 * the same as source.
	 */
	if (is_garp && ar_op == htons(ARPOP_REPLY))
		is_garp =
			/* IPv4 over IEEE 1394 doesn't provide target
			 * hardware address field in its ARP payload.
			 */
			tha &&
			!memcmp(tha, sha, dev->addr_len);

	if (is_garp) {
		*addr_type = inet_addr_type_dev_table(net, dev, sip);
		if (*addr_type != RTN_UNICAST)
			is_garp = false;
	}
	return is_garp;
}

/*
 *	Process an arp request.
 */

/*
 * arp_project
 *
 * The sender hardware address lives in the ARP payload, where whoever
 * sent the frame chose it. A packet whose Ethernet source disagrees
 * with it is never used as evidence about anybody.
 *
 * Link types whose header is not an Ethernet header are accepted as
 * before, since there is nothing to compare against.
 */
static bool arp_sha_matches_link(const struct sk_buff *skb,
				 const unsigned char *sha)
{
	const struct net_device *dev = skb->dev;

	if (dev->type != ARPHRD_ETHER)
		return true;

	if (!skb_mac_header_was_set(skb))
		return false;

	return !memcmp(eth_hdr(skb)->h_source, sha, dev->addr_len);
}

/*
 * arp_project
 *
 * Gateway records. One per device and gateway address.
 *
 * The protected address is the only hardware address this gateway is
 * allowed to have. It is taken the first time the ARP table holds one,
 * and nothing arriving on the wire can move it.
 *
 * Records are keyed by ifindex and by the namespace inode number, both
 * of which are plain values, so no device is ever dereferenced or
 * pinned from here. Records are dropped when the device goes away.
 */
#define ARP_GW_SLOTS		8
#define ARP_GW_ALT_MACS		8
#define ARP_VERIFY_ROUNDS	3
#define ARP_VERIFY_INTERVAL	HZ

/*
 * How long after a probe a reply is still taken as an answer to it.
 * ARP has nowhere to put a nonce, so this window is the only thing
 * tying a reply back to the request that asked for it.
 */
#define ARP_PROBE_WINDOW	msecs_to_jiffies(300)

/*
 * The protected address answering at all is enough: nothing on the wire
 * can stop a live gateway from replying to a request addressed to it.
 * A claimant has to answer more than once, because a reply that merely
 * looks like an answer can be manufactured.
 */
#define ARP_PROTECTED_ANSWERS	1
#define ARP_CLAIMANT_ANSWERS	2

struct arp_gw_rec {
	int		ifindex;
	unsigned int	netns;
	__be32		gw;
	u8		addr_len;

	bool		protected;
	unsigned char	protected_hwaddr[MAX_ADDR_LEN];

	/* Verification of a competing claim. */
	bool		verifying;
	u8		round;
	u8		protected_replies;
	u8		claimant_replies;
	unsigned long	round_due;
	/* When the last probe went out, cleared once an answer is taken. */
	unsigned long	protected_probe_at;
	unsigned long	claimant_probe_at;
	unsigned char	claimant_hwaddr[MAX_ADDR_LEN];

	/*
	 * Further hardware addresses accepted for this gateway, for a
	 * gateway that answers from more than one port (an HA pair sharing
	 * the address, a bonded link). Only filled when
	 * allow_multi_gw_hwaddr is set.
	 */
	u8		alt_count;
	unsigned char	alt_hwaddr[ARP_GW_ALT_MACS][MAX_ADDR_LEN];

	/*
	 * Rate limit on outgoing probes, kept across verification restarts.
	 * A claimant whose address changes with every packet resets the
	 * verification each time; without this the receive path would send
	 * a fresh pair of probes on every such packet. This bounds them to
	 * one pair per interval however often the claim restarts.
	 */
	unsigned long	probe_throttle;
};

static DEFINE_SPINLOCK(gw_lock);
static struct arp_gw_rec gw_recs[ARP_GW_SLOTS];
static bool allow_gw_hwaddr_change;

/*
 * A gateway can legitimately answer from more than one hardware address:
 * an HA pair sharing the address, a bonded link. With this set, a second
 * address that proves itself live the same way the protected one does is
 * accepted as another of the gateway's ports rather than blocked. It is
 * on by default, because the alternative is to block a real gateway's
 * second port and cut the route it serves. Set it to 0 to keep the
 * stricter rule that a second live answer is an attack.
 *
 * ARP cannot tell an HA gateway from an attacker that is itself live at
 * the gateway address, so with this on such an attacker would be accepted
 * as a gateway port. protected_gw_hwaddr still pins the first address.
 */
static bool allow_multi_gw_hwaddr = true;

enum arp_gw_verdict {
	ARP_GW_NOTHING,		/* nothing to say about this packet */
	ARP_GW_DENY,		/* competing claim, not judged yet */
	ARP_GW_ATTACKER,	/* claimant answers for the gateway and the
				 * protected address answers too */
	ARP_GW_REPLACED,	/* protected address stopped answering */
	ARP_GW_RELEARNED,	/* as above, and the address was taken */
	ARP_GW_NOT_PROVEN,	/* claimant never answered a probe */
	ARP_GW_COGATEWAY,	/* claimant proved itself another gateway
				 * port and was accepted */
};

/* Both callers hold gw_lock. */
static struct arp_gw_rec *__arp_gw_find(const struct net_device *dev,
					__be32 gw)
{
	unsigned int netns = dev_net(dev)->ns.inum;
	int i;

	for (i = 0; i < ARP_GW_SLOTS; i++) {
		if (gw_recs[i].addr_len && gw_recs[i].ifindex == dev->ifindex &&
		    gw_recs[i].netns == netns && gw_recs[i].gw == gw)
			return &gw_recs[i];
	}

	return NULL;
}

static struct arp_gw_rec *__arp_gw_get(const struct net_device *dev, __be32 gw)
{
	struct arp_gw_rec *rec = __arp_gw_find(dev, gw);
	int i;

	if (rec)
		return rec;

	for (i = 0; i < ARP_GW_SLOTS; i++) {
		if (gw_recs[i].addr_len)
			continue;

		rec = &gw_recs[i];
		memset(rec, 0, sizeof(*rec));
		rec->ifindex = dev->ifindex;
		rec->netns = dev_net(dev)->ns.inum;
		rec->gw = gw;
		rec->addr_len = dev->addr_len;

		return rec;
	}

	return NULL;
}

static void __arp_gw_verify_reset(struct arp_gw_rec *rec)
{
	rec->verifying = false;
	rec->round = 0;
	rec->protected_replies = 0;
	rec->claimant_replies = 0;
	rec->round_due = 0;
	rec->protected_probe_at = 0;
	rec->claimant_probe_at = 0;
	memset(rec->claimant_hwaddr, 0, sizeof(rec->claimant_hwaddr));
}

/* Is this address already accepted as one of the gateway's ports?
 * Callers hold gw_lock.
 */
static bool __arp_gw_alt_match(const struct arp_gw_rec *rec,
			       const unsigned char *sha, u8 addr_len)
{
	u8 i;

	for (i = 0; i < rec->alt_count; i++)
		if (!memcmp(rec->alt_hwaddr[i], sha, addr_len))
			return true;

	return false;
}

/*
 * Remember a further hardware address the gateway answers from. Best
 * effort: a full set just means the address is proven again next time,
 * which the probe throttle bounds. Callers hold gw_lock.
 */
static void __arp_gw_alt_store(struct arp_gw_rec *rec,
			       const unsigned char *sha, u8 addr_len)
{
	if (__arp_gw_alt_match(rec, sha, addr_len))
		return;
	if (rec->alt_count >= ARP_GW_ALT_MACS)
		return;

	memcpy(rec->alt_hwaddr[rec->alt_count], sha, addr_len);
	rec->alt_count++;
}

/* Drop every record belonging to a device that is going away. */
static void arp_gw_forget_dev(const struct net_device *dev)
{
	unsigned int netns = dev_net(dev)->ns.inum;
	int i;

	spin_lock_bh(&gw_lock);
	for (i = 0; i < ARP_GW_SLOTS; i++) {
		if (gw_recs[i].addr_len && gw_recs[i].ifindex == dev->ifindex &&
		    gw_recs[i].netns == netns)
			memset(&gw_recs[i], 0, sizeof(gw_recs[i]));
	}
	spin_unlock_bh(&gw_lock);
}

static void arp_gw_forget_all(void)
{
	spin_lock_bh(&gw_lock);
	memset(gw_recs, 0, sizeof(gw_recs));
	spin_unlock_bh(&gw_lock);
}

/*
 * arp_project
 *
 * The default route is looked up for every ARP packet that arrives, and
 * that lookup walks a trie, so the answer is kept for ARP_GW_CACHE_TTL.
 * One entry per CPU is enough: this runs in the receive softirq, so the
 * entry cannot be touched from anywhere else while it is being used,
 * and a machine only has a handful of devices carrying ARP.
 *
 * A route change takes up to ARP_GW_CACHE_TTL to be noticed. Nothing is
 * decided from a stale answer that would not also have been decided a
 * second earlier.
 */
#define ARP_GW_CACHE_TTL	HZ

struct arp_gw_cache {
	int		ifindex;
	unsigned int	netns;
	__be32		gw;
	unsigned long	expires;
};

static DEFINE_PER_CPU(struct arp_gw_cache, arp_gw_cache);

static __be32 arp_gw_of(struct net_device *dev)
{
	unsigned int netns = dev_net(dev)->ns.inum;
	struct arp_gw_cache *c = this_cpu_ptr(&arp_gw_cache);

	if (c->expires && c->ifindex == dev->ifindex && c->netns == netns &&
	    time_before_eq(jiffies, c->expires))
		return c->gw;

	c->gw = ip_fib_get_gw(dev);
	c->ifindex = dev->ifindex;
	c->netns = netns;
	c->expires = jiffies + ARP_GW_CACHE_TTL;

	return c->gw;
}

/* Throw the cache away when a device goes, so an ifindex cannot be reused. */
static void arp_gw_cache_flush(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		per_cpu_ptr(&arp_gw_cache, cpu)->expires = 0;
}

/*
 * A unicast ARP request for the gateway's address, sent to one specific
 * hardware address. Nobody else on a switched link sees it, so an answer
 * to it is the one piece of evidence here that the sender of a packet
 * cannot write for somebody else.
 */
static void arp_gw_probe(struct net_device *dev, __be32 gw,
			 const unsigned char *target_ha)
{
	__be32 saddr = inet_select_addr(dev, gw, RT_SCOPE_LINK);

	if (!saddr)
		return;

	arp_send(ARPOP_REQUEST, ETH_P_ARP, gw, dev, saddr, target_ha,
		 dev->dev_addr, NULL);
}

/*
 * arp_project
 *
 * Handle a packet that claims the gateway's protocol address.
 *
 * The rules are:
 *
 *   The protected address is accepted and noted as alive.
 *
 *   Any other address is refused, and is probed. So is the protected
 *   address. Over ARP_VERIFY_ROUNDS rounds we watch which of the two
 *   answers a request addressed to it alone, counting only replies that
 *   land inside ARP_PROBE_WINDOW after the probe and only one per probe:
 *
 *     both answer          the gateway is still there and somebody else
 *                          is claiming its address as well, which is an
 *                          attack. The claimant is blocked.
 *
 *     only the claimant    the protected address is gone, so the gateway
 *                          was replaced rather than attacked. It is
 *                          taken only when allow_gw_hwaddr_change is set.
 *
 *     claimant silent      whoever sent the packet put somebody else's
 *                          address in it. Nobody is blocked.
 *
 * The protected address is never blocked, whatever arrives on the wire.
 */
static enum arp_gw_verdict arp_gw_claim(struct net_device *dev, __be32 gw,
					unsigned char *sha, bool trusted,
					bool answered,
					unsigned char *probe_protected,
					unsigned char *probe_claimant,
					unsigned char *blocked)
{
	enum arp_gw_verdict verdict = ARP_GW_NOTHING;
	struct arp_gw_rec *rec;
	struct neighbour *n;
	unsigned char cached[MAX_ADDR_LEN];
	bool have_cached = false;

	/* What the ARP table holds for the gateway right now. */
	n = neigh_lookup(&arp_tbl, &gw, dev);
	if (n) {
		if (memchr_inv(n->ha, 0, dev->addr_len)) {
			neigh_ha_snapshot(cached, n, dev);
			have_cached = true;
		}
		neigh_release(n);
	}

	spin_lock_bh(&gw_lock);

	rec = __arp_gw_get(dev, gw);
	if (!rec) {
		spin_unlock_bh(&gw_lock);
		pr_warn_once(ARP_PROJECT
			     "%s: no free gateway record, %pI4 on %s is unprotected\n",
			     __func__, &gw, dev->name);
		return ARP_GW_NOTHING;
	}

	/*
	 * The first address the gateway is known by is the protected one.
	 *
	 * Taking it from the ARP table alone is too late: on the reply that
	 * first resolves the gateway the entry is still incomplete, so the
	 * protection would only appear on some later packet and everything
	 * in between would go unguarded. When there is nothing cached yet,
	 * protect what this packet is about to put there instead.
	 */
	if (!rec->protected) {
		if (have_cached) {
			memcpy(rec->protected_hwaddr, cached, dev->addr_len);
			rec->protected = true;
		} else if (trusted) {
			memcpy(rec->protected_hwaddr, sha, dev->addr_len);
			rec->protected = true;
		}
	}

	if (!rec->protected) {
		spin_unlock_bh(&gw_lock);
		return ARP_GW_NOTHING;
	}

	if (!memcmp(sha, rec->protected_hwaddr, dev->addr_len)) {
		/*
		 * The gateway itself. Only a reply that lands inside the
		 * window after the probe we addressed to it counts, and only
		 * one per probe, so a stream of replies cannot stand in for
		 * answers that were never given.
		 */
		if (trusted && answered && rec->verifying &&
		    rec->protected_probe_at &&
		    time_before_eq(jiffies,
				   rec->protected_probe_at + ARP_PROBE_WINDOW)) {
			rec->protected_probe_at = 0;
			if (rec->protected_replies < U8_MAX)
				rec->protected_replies++;
		}
		spin_unlock_bh(&gw_lock);

		return ARP_GW_NOTHING;
	}

	/*
	 * An address already accepted as another of the gateway's ports.
	 * Let it through like the protected one, without verifying again.
	 */
	if (__arp_gw_alt_match(rec, sha, dev->addr_len)) {
		spin_unlock_bh(&gw_lock);
		return ARP_GW_NOTHING;
	}

	/* Somebody else is claiming the gateway's address. */
	verdict = ARP_GW_DENY;

	if (!rec->verifying) {
		__arp_gw_verify_reset(rec);
		rec->verifying = true;
		memcpy(rec->claimant_hwaddr, sha, dev->addr_len);
	} else if (memcmp(rec->claimant_hwaddr, sha, dev->addr_len)) {
		/* A second claimant. Start over on the newest one. */
		__arp_gw_verify_reset(rec);
		rec->verifying = true;
		memcpy(rec->claimant_hwaddr, sha, dev->addr_len);
	} else if (trusted && answered && rec->claimant_probe_at &&
		   time_before_eq(jiffies,
				  rec->claimant_probe_at + ARP_PROBE_WINDOW)) {
		rec->claimant_probe_at = 0;
		if (rec->claimant_replies < U8_MAX)
			rec->claimant_replies++;
	}

	if (rec->round < ARP_VERIFY_ROUNDS &&
	    (!rec->round_due || time_after_eq(jiffies, rec->round_due)) &&
	    time_after_eq(jiffies, rec->probe_throttle)) {
		memcpy(probe_protected, rec->protected_hwaddr, dev->addr_len);
		memcpy(probe_claimant, rec->claimant_hwaddr, dev->addr_len);
		rec->round++;
		rec->round_due = jiffies + ARP_VERIFY_INTERVAL;
		rec->probe_throttle = jiffies + ARP_VERIFY_INTERVAL;
		rec->protected_probe_at = jiffies;
		rec->claimant_probe_at = jiffies;
		verdict = ARP_GW_DENY;
	} else if (rec->round >= ARP_VERIFY_ROUNDS &&
		   time_after_eq(jiffies, rec->round_due)) {
		if (rec->claimant_replies < ARP_CLAIMANT_ANSWERS) {
			verdict = ARP_GW_NOT_PROVEN;
		} else if (rec->protected_replies >= ARP_PROTECTED_ANSWERS) {
			/*
			 * The protected address and the claimant each answer a
			 * probe addressed to it alone. That is a gateway with
			 * more than one port, or a live attacker beside the
			 * real gateway; ARP cannot tell the two apart. With
			 * allow_multi_gw_hwaddr the claimant is taken as
			 * another gateway port, otherwise the stricter rule
			 * stands and it is blocked.
			 */
			memcpy(blocked, rec->claimant_hwaddr, dev->addr_len);
			if (allow_multi_gw_hwaddr) {
				__arp_gw_alt_store(rec, rec->claimant_hwaddr,
						   dev->addr_len);
				verdict = ARP_GW_COGATEWAY;
			} else {
				verdict = ARP_GW_ATTACKER;
			}
		} else if (!allow_gw_hwaddr_change) {
			verdict = ARP_GW_REPLACED;
		} else {
			memcpy(rec->protected_hwaddr, rec->claimant_hwaddr,
			       dev->addr_len);
			verdict = ARP_GW_RELEARNED;
		}
		__arp_gw_verify_reset(rec);
	}

	spin_unlock_bh(&gw_lock);

	return verdict;
}

/*
 * arp_project
 *
 * Blocked hardware addresses.
 *
 * One entry per address that verification proved hostile, held per
 * device. attacker_timeout defaults to 0, which keeps an entry until
 * clear_attacker_hwaddr is written. An attacker working through a run of
 * addresses fills the table, so the oldest entry gives way rather than
 * the newest being turned away.
 */
#define ARP_ATTACKER_SLOTS	16

struct arp_attacker {
	int		ifindex;
	unsigned int	netns;
	u8		addr_len;
	unsigned char	hwaddr[MAX_ADDR_LEN];
	unsigned long	seen;
	unsigned long	expires;
};

static DEFINE_SPINLOCK(attacker_lock);
static struct arp_attacker attackers[ARP_ATTACKER_SLOTS];

/* Drop entries older than attacker_timeout. Callers hold attacker_lock. */
static unsigned int __arp_attacker_expire(void)
{
	unsigned int dropped = 0;
	int i;

	if (!attacker_timeout)
		return 0;

	for (i = 0; i < ARP_ATTACKER_SLOTS; i++) {
		if (!attackers[i].addr_len)
			continue;
		if (time_before_eq(jiffies, attackers[i].expires))
			continue;

		memset(&attackers[i], 0, sizeof(attackers[i]));
		dropped++;
	}

	return dropped;
}

/* Callers hold attacker_lock. */
static struct arp_attacker *__arp_attacker_find(const struct net_device *dev,
						const unsigned char *hwaddr)
{
	unsigned int netns = dev_net(dev)->ns.inum;
	int i;

	for (i = 0; i < ARP_ATTACKER_SLOTS; i++) {
		if (attackers[i].addr_len == dev->addr_len &&
		    attackers[i].ifindex == dev->ifindex &&
		    attackers[i].netns == netns &&
		    !memcmp(attackers[i].hwaddr, hwaddr, dev->addr_len))
			return &attackers[i];
	}

	return NULL;
}

static bool arp_is_attacker(const struct net_device *dev,
			    const unsigned char *hwaddr)
{
	unsigned int dropped;
	bool match;

	spin_lock_bh(&attacker_lock);
	dropped = __arp_attacker_expire();
	match = __arp_attacker_find(dev, hwaddr) != NULL;
	spin_unlock_bh(&attacker_lock);

	if (dropped)
		pr_info(ARP_PROJECT "%s: %u blocked address(es) timed out\n",
			__func__, dropped);

	return match;
}

static void arp_set_attacker(const struct net_device *dev,
			     const unsigned char *hwaddr)
{
	struct arp_attacker *slot;
	bool evicted = false;
	int i;

	if (WARN_ON_ONCE(dev->addr_len > MAX_ADDR_LEN))
		return;

	spin_lock_bh(&attacker_lock);
	__arp_attacker_expire();

	slot = __arp_attacker_find(dev, hwaddr);
	if (!slot) {
		/* A free slot if there is one, otherwise the oldest entry. */
		for (i = 0; i < ARP_ATTACKER_SLOTS; i++) {
			if (!attackers[i].addr_len) {
				slot = &attackers[i];
				break;
			}
			if (!slot || time_before(attackers[i].seen, slot->seen))
				slot = &attackers[i];
		}
		evicted = slot->addr_len != 0;
	}

	memset(slot, 0, sizeof(*slot));
	slot->ifindex = dev->ifindex;
	slot->netns = dev_net(dev)->ns.inum;
	slot->addr_len = dev->addr_len;
	memcpy(slot->hwaddr, hwaddr, dev->addr_len);
	slot->seen = jiffies;
	slot->expires = jiffies + attacker_timeout * HZ;
	spin_unlock_bh(&attacker_lock);

	if (evicted)
		pr_warn(ARP_PROJECT
			"%s: all %d slots were taken, dropped the oldest\n",
			__func__, ARP_ATTACKER_SLOTS);
}

static void arp_clear_attackers(void)
{
	spin_lock_bh(&attacker_lock);
	memset(attackers, 0, sizeof(attackers));
	spin_unlock_bh(&attacker_lock);
}

/* Drop every entry belonging to a device that is going away. */
static void arp_attacker_forget_dev(const struct net_device *dev)
{
	unsigned int netns = dev_net(dev)->ns.inum;
	int i;

	spin_lock_bh(&attacker_lock);
	for (i = 0; i < ARP_ATTACKER_SLOTS; i++) {
		if (attackers[i].addr_len && attackers[i].ifindex == dev->ifindex &&
		    attackers[i].netns == netns)
			memset(&attackers[i], 0, sizeof(attackers[i]));
	}
	spin_unlock_bh(&attacker_lock);
}

/*
 * A protected gateway is never blocked. Without this one rule, a forged
 * packet naming the real gateway would take the gateway away for good,
 * which is the whole reason the record can be permanent.
 */
static bool arp_gw_is_protected(const struct net_device *dev,
				const unsigned char *hwaddr)
{
	unsigned int netns = dev_net(dev)->ns.inum;
	bool found = false;
	int i;

	spin_lock_bh(&gw_lock);
	for (i = 0; i < ARP_GW_SLOTS; i++) {
		if (gw_recs[i].addr_len == dev->addr_len &&
		    gw_recs[i].ifindex == dev->ifindex &&
		    gw_recs[i].netns == netns && gw_recs[i].protected &&
		    !memcmp(gw_recs[i].protected_hwaddr, hwaddr, dev->addr_len)) {
			found = true;
			break;
		}
	}
	spin_unlock_bh(&gw_lock);

	return found;
}

/* Drop the gateway entry when it is holding the address we just blocked. */
static void arp_gw_drop_entry(struct net_device *dev, __be32 gw,
			      const unsigned char *hwaddr)
{
	struct neighbour *n = neigh_lookup(&arp_tbl, &gw, dev);

	if (!n)
		return;

	if (memchr_inv(n->ha, 0, dev->addr_len) &&
	    !memcmp(n->ha, hwaddr, dev->addr_len)) {
		pr_warn(ARP_PROJECT "%s: Deleting gateway from ARP table...\n",
			__func__);
		if (n->nud_state & ~NUD_NOARP)
			neigh_update(n, NULL, NUD_FAILED,
				     NEIGH_UPDATE_F_OVERRIDE |
				     NEIGH_UPDATE_F_ADMIN, 0);
	}

	neigh_release(n);
}

/*
 * arp_project
 *
 * A request asking for the gateway's address, sent from the address the
 * ARP table holds for the gateway, cannot have come from the gateway.
 * Either the table is holding somebody else's address or the request was
 * forged, and the packet alone cannot say which, so this only reports.
 */
static void arp_gw_report_request(struct net_device *dev, __be32 gw,
				  __be32 sip, unsigned char *sha, bool trusted)
{
	struct neighbour *n;

	if (sip == gw)
		return;

	n = neigh_lookup(&arp_tbl, &gw, dev);
	if (!n)
		return;

	if (memchr_inv(n->ha, 0, dev->addr_len) &&
	    !memcmp(n->ha, sha, dev->addr_len))
		pr_warn_ratelimited(ARP_PROJECT
			"%s: %*phC asked for the gateway it is cached as%s\n",
			__func__, dev->addr_len, sha,
			trusted ? "" : " (link source does not match)");

	neigh_release(n);
}

/*
 * arp_project
 *
 * Everything that mentions the gateway comes through here, ahead of any
 * path that could change the ARP table.
 *
 * Returns true when the packet must not be allowed any further.
 */
static bool arp_gw_check(const struct sk_buff *skb, struct net_device *dev,
			 __be16 ar_op, __be32 sip, __be32 tip,
			 unsigned char *sha, unsigned char *tha)
{
	unsigned char probe_protected[MAX_ADDR_LEN] = { };
	unsigned char probe_claimant[MAX_ADDR_LEN] = { };
	unsigned char blocked[MAX_ADDR_LEN] = { };
	bool is_reply = ar_op == htons(ARPOP_REPLY);
	enum arp_gw_verdict verdict;
	bool trusted, answered;
	bool deny = false;
	__be32 gw;

	gw = arp_gw_of(dev);
	if (!gw)
		return false;

	if (print_arp_info)
		pr_info(ARP_PROJECT "%s - Gateway IP: %pI4\n", __func__, &gw);

	trusted = arp_sha_matches_link(skb, sha);

	/*
	 * A reply addressed to this host is what an answer to the unicast
	 * probe below looks like. Anything else is somebody talking at us
	 * on their own initiative and proves nothing about who they are.
	 */
	answered = is_reply && tha &&
		   !memcmp(tha, dev->dev_addr, dev->addr_len);

	if (!is_reply && tip == gw)
		arp_gw_report_request(dev, gw, sip, sha, trusted);

	if (sip != gw)
		return false;

	if (arp_is_attacker(dev, sha)) {
		pr_info_ratelimited(ARP_PROJECT
				    "%s: %*phC was detected as an attacker!\n",
				    __func__, dev->addr_len, sha);
		deny = true;
		goto decided;
	}

	verdict = arp_gw_claim(dev, gw, sha, trusted, answered, probe_protected,
			       probe_claimant, blocked);

	if (memchr_inv(probe_protected, 0, dev->addr_len))
		arp_gw_probe(dev, gw, probe_protected);
	if (memchr_inv(probe_claimant, 0, dev->addr_len))
		arp_gw_probe(dev, gw, probe_claimant);

	switch (verdict) {
	case ARP_GW_NOTHING:
		break;
	case ARP_GW_DENY:
		pr_info_ratelimited(ARP_PROJECT
			"%s: %*phC is claiming the gateway, probing both\n",
			__func__, dev->addr_len, sha);
		deny = true;
		break;
	case ARP_GW_NOT_PROVEN:
		pr_info_ratelimited(ARP_PROJECT
			"%s: %*phC never answered for the gateway, blocking nobody\n",
			__func__, dev->addr_len, sha);
		deny = true;
		break;
	case ARP_GW_ATTACKER:
		if (arp_gw_is_protected(dev, blocked)) {
			pr_warn_ratelimited(ARP_PROJECT
				"%s: not blocking %*phC, it is the protected gateway\n",
				__func__, dev->addr_len, blocked);
		} else {
			pr_warn(ARP_PROJECT
				"%s: ARP spoofing attacker detected as %*phC\n",
				__func__, dev->addr_len, blocked);
			arp_set_attacker(dev, blocked);
			arp_gw_drop_entry(dev, gw, blocked);
		}
		deny = true;
		break;
	case ARP_GW_COGATEWAY:
		pr_warn(ARP_PROJECT
			"%s: %*phC also answers for the gateway, accepting it as another gateway port\n",
			__func__, dev->addr_len, blocked);
		break;
	case ARP_GW_REPLACED:
		pr_warn_ratelimited(ARP_PROJECT
			"%s: gateway looks replaced by %*phC, refused because allow_gw_hwaddr_change is off\n",
			__func__, dev->addr_len, sha);
		deny = true;
		break;
	case ARP_GW_RELEARNED:
		pr_warn(ARP_PROJECT "%s: gateway replaced, now protecting %*phC\n",
			__func__, dev->addr_len, sha);
		break;
	}

decided:
	if (!deny)
		return false;

	return is_reply ? ignore_gw_update_by_reply : ignore_gw_update_by_request;
}

static int arp_process(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct in_device *in_dev = __in_dev_get_rcu(dev);
	struct arphdr *arp;
	unsigned char *arp_ptr;
	struct rtable *rt;
	unsigned char *sha;
	unsigned char *tha = NULL;
	__be32 sip, tip;
	u16 dev_type = dev->type;
	int addr_type;
	struct neighbour *n;
	struct dst_entry *reply_dst = NULL;
	bool is_garp = false;

	/* arp_rcv below verifies the ARP header and verifies the device
	 * is ARP'able.
	 */

	if (!in_dev)
		goto out_free_skb;

	arp = arp_hdr(skb);

	switch (dev_type) {
	default:
		if (arp->ar_pro != htons(ETH_P_IP) ||
		    htons(dev_type) != arp->ar_hrd)
			goto out_free_skb;
		break;
	case ARPHRD_ETHER:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		/*
		 * ETHERNET, and Fibre Channel (which are IEEE 802
		 * devices, according to RFC 2625) devices will accept ARP
		 * hardware types of either 1 (Ethernet) or 6 (IEEE 802.2).
		 * This is the case also of FDDI, where the RFC 1390 says that
		 * FDDI devices should accept ARP hardware of (1) Ethernet,
		 * however, to be more robust, we'll accept both 1 (Ethernet)
		 * or 6 (IEEE 802.2)
		 */
		if ((arp->ar_hrd != htons(ARPHRD_ETHER) &&
		     arp->ar_hrd != htons(ARPHRD_IEEE802)) ||
		    arp->ar_pro != htons(ETH_P_IP))
			goto out_free_skb;
		break;
	case ARPHRD_AX25:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_AX25))
			goto out_free_skb;
		break;
	case ARPHRD_NETROM:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_NETROM))
			goto out_free_skb;
		break;
	}

	/* Understand only these message types */

	if (arp->ar_op != htons(ARPOP_REPLY) &&
	    arp->ar_op != htons(ARPOP_REQUEST))
		goto out_free_skb;

	/* arp_project */
	if (arp_project_enable && print_arp_info)
		arp_print_info(dev, arp, 0);

/*
 *	Extract fields
 */
	arp_ptr = (unsigned char *)(arp + 1);
	sha	= arp_ptr;
	arp_ptr += dev->addr_len;
	memcpy(&sip, arp_ptr, 4);
	arp_ptr += 4;
	switch (dev_type) {
#if IS_ENABLED(CONFIG_FIREWIRE_NET)
	case ARPHRD_IEEE1394:
		break;
#endif
	default:
		tha = arp_ptr;
		arp_ptr += dev->addr_len;
	}
	memcpy(&tip, arp_ptr, 4);
/*
 *	Check for bad requests for 127.x.x.x and requests for multicast
 *	addresses.  If this is one such, delete it.
 */
	if (ipv4_is_multicast(tip) ||
	    (!IN_DEV_ROUTE_LOCALNET(in_dev) && ipv4_is_loopback(tip)))
		goto out_free_skb;

 /*
  *	For some 802.11 wireless deployments (and possibly other networks),
  *	there will be an ARP proxy and gratuitous ARP frames are attacks
  *	and thus should not be accepted.
  */
	if (sip == tip && IN_DEV_ORCONF(in_dev, DROP_GRATUITOUS_ARP))
		goto out_free_skb;

/*
 *     Special case: We must set Frame Relay source Q.922 address
 */
	if (dev_type == ARPHRD_DLCI)
		sha = dev->broadcast;

/*
 *  Process entry.  The idea here is we want to send a reply if it is a
 *  request for us or if it is a request for someone else that we hold
 *  a proxy for.  We want to add an entry to our cache if it is a reply
 *  to us or if it is a request for our address.
 *  (The assumption for this last is that if someone is requesting our
 *  address, they are probably intending to talk to us, so it saves time
 *  if we cache their address.  Their address is also probably not in
 *  our cache, since ours is not in their cache.)
 *
 *  Putting this another way, we only care about replies if they are to
 *  us, in which case we add them to the cache.  For requests, we care
 *  about those for us and those for our proxies.  We reply to both,
 *  and in the case of requests for us we add the requester to the arp
 *  cache.
 */

	if (arp->ar_op == htons(ARPOP_REQUEST) && skb_metadata_dst(skb))
		reply_dst = (struct dst_entry *)
			    iptunnel_metadata_reply(skb_metadata_dst(skb),
						    GFP_ATOMIC);

	/* Special case: IPv4 duplicate address detection packet (RFC2131) */
	if (sip == 0) {
		if (arp->ar_op == htons(ARPOP_REQUEST) &&
		    inet_addr_type_dev_table(net, dev, tip) == RTN_LOCAL &&
		    !arp_ignore(in_dev, sip, tip))
			arp_send_dst(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip,
				     sha, dev->dev_addr, sha, reply_dst);
		goto out_consume_skb;
	}

	/*
	 * arp_project
	 *
	 * Everything about the gateway is decided here, ahead of every
	 * path below that could change the ARP table.
	 */
	if (arp_project_enable &&
	    arp_gw_check(skb, dev, arp->ar_op, sip, tip, sha, tha))
		goto out_consume_skb;

	if (arp->ar_op == htons(ARPOP_REQUEST) &&
	    ip_route_input_noref(skb, tip, sip, 0, dev) == 0) {

		rt = skb_rtable(skb);
		addr_type = rt->rt_type;

		if (addr_type == RTN_LOCAL) {
			int dont_send;

			dont_send = arp_ignore(in_dev, sip, tip);
			if (!dont_send && IN_DEV_ARPFILTER(in_dev))
				dont_send = arp_filter(sip, tip, dev);
			if (!dont_send) {
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);
				if (n) {
					arp_send_dst(ARPOP_REPLY, ETH_P_ARP,
						     sip, dev, tip, sha,
						     dev->dev_addr, sha,
						     reply_dst);
					neigh_release(n);
				}
			}
			goto out_consume_skb;
		} else if (IN_DEV_FORWARD(in_dev)) {
			/*
			 * arp_project
			 *
			 * Ignore proxy ARP if 'ignore_proxy_arp' is enabled.
			 */
			if (arp_project_enable && ignore_proxy_arp) {
				pr_info_ratelimited(ARP_PROJECT
					"%s: Ignoring proxy ARP...\n",
					__func__);
				goto out_consume_skb;
			}

			if (addr_type == RTN_UNICAST  &&
			    (arp_fwd_proxy(in_dev, dev, rt) ||
			     arp_fwd_pvlan(in_dev, dev, rt, sip, tip) ||
			     (rt->dst.dev != dev &&
			      pneigh_lookup(&arp_tbl, net, &tip, dev)))) {
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);
				if (n)
					neigh_release(n);

				if (NEIGH_CB(skb)->flags & LOCALLY_ENQUEUED ||
				    skb->pkt_type == PACKET_HOST ||
				    NEIGH_VAR(in_dev->arp_parms, PROXY_DELAY) == 0) {
					arp_send_dst(ARPOP_REPLY, ETH_P_ARP,
						     sip, dev, tip, sha,
						     dev->dev_addr, sha,
						     reply_dst);
				} else {
					pneigh_enqueue(&arp_tbl,
						       in_dev->arp_parms, skb);
					goto out_free_dst;
				}
				goto out_consume_skb;
			}
		}
	}

	/* Update our ARP tables */

	n = __neigh_lookup(&arp_tbl, &sip, dev, 0);

	addr_type = -1;
	if (n || arp_accept(in_dev, sip)) {
		is_garp = arp_is_garp(net, dev, &addr_type, arp->ar_op,
				      sip, tip, sha, tha);
	}

	if (arp_accept(in_dev, sip)) {
		/* Unsolicited ARP is not accepted by default.
		   It is possible, that this option should be enabled for some
		   devices (strip is candidate)
		 */
		if (!n &&
		    (is_garp ||
		     (arp->ar_op == htons(ARPOP_REPLY) &&
		      (addr_type == RTN_UNICAST ||
		       (addr_type < 0 &&
			/* postpone calculation to as late as possible */
			inet_addr_type_dev_table(net, dev, sip) ==
				RTN_UNICAST)))))
			n = __neigh_lookup(&arp_tbl, &sip, dev, 1);
	}

	if (n) {
		int state = NUD_REACHABLE;
		int override;

		/* If several different ARP replies follows back-to-back,
		   use the FIRST one. It is possible, if several proxy
		   agents are active. Taking the first reply prevents
		   arp trashing and chooses the fastest router.
		 */
		override = time_after(jiffies,
				      n->updated +
				      NEIGH_VAR(n->parms, LOCKTIME)) ||
			   is_garp;

		/* Broadcast replies and request packets
		   do not assert neighbour reachability.
		 */
		if (arp->ar_op != htons(ARPOP_REPLY) ||
		    skb->pkt_type != PACKET_HOST)
			state = NUD_STALE;
		neigh_update(n, sha, state,
			     override ? NEIGH_UPDATE_F_OVERRIDE : 0, 0);
		neigh_release(n);
	}

out_consume_skb:
	consume_skb(skb);

out_free_dst:
	dst_release(reply_dst);
	return NET_RX_SUCCESS;

out_free_skb:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static void parp_redo(struct sk_buff *skb)
{
	arp_process(dev_net(skb->dev), NULL, skb);
}

static int arp_is_multicast(const void *pkey)
{
	return ipv4_is_multicast(*((__be32 *)pkey));
}

/*
 *	Receive an arp request from the device layer.
 */

static int arp_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
{
	enum skb_drop_reason drop_reason;
	const struct arphdr *arp;

	/* do not tweak dropwatch on an ARP we will ignore */
	if (dev->flags & IFF_NOARP ||
	    skb->pkt_type == PACKET_OTHERHOST ||
	    skb->pkt_type == PACKET_LOOPBACK)
		goto consumeskb;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto out_of_mem;

	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  */
	drop_reason = pskb_may_pull_reason(skb, arp_hdr_len(dev));
	if (drop_reason != SKB_NOT_DROPPED_YET)
		goto freeskb;

	arp = arp_hdr(skb);
	if (arp->ar_hln != dev->addr_len || arp->ar_pln != 4) {
		drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
		goto freeskb;
	}

	memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));

	return NF_HOOK(NFPROTO_ARP, NF_ARP_IN,
		       dev_net(dev), NULL, skb, dev, NULL,
		       arp_process);

consumeskb:
	consume_skb(skb);
	return NET_RX_SUCCESS;
freeskb:
	kfree_skb_reason(skb, drop_reason);
out_of_mem:
	return NET_RX_DROP;
}

/*
 *	User level interface (ioctl)
 */

static struct net_device *arp_req_dev_by_name(struct net *net, struct arpreq *r,
					      bool getarp)
{
	struct net_device *dev;

	if (getarp)
		dev = dev_get_by_name_rcu(net, r->arp_dev);
	else
		dev = __dev_get_by_name(net, r->arp_dev);
	if (!dev)
		return ERR_PTR(-ENODEV);

	/* Mmmm... It is wrong... ARPHRD_NETROM == 0 */
	if (!r->arp_ha.sa_family)
		r->arp_ha.sa_family = dev->type;

	if ((r->arp_flags & ATF_COM) && r->arp_ha.sa_family != dev->type)
		return ERR_PTR(-EINVAL);

	return dev;
}

static struct net_device *arp_req_dev(struct net *net, struct arpreq *r)
{
	struct net_device *dev;
	struct rtable *rt;
	__be32 ip;

	if (r->arp_dev[0])
		return arp_req_dev_by_name(net, r, false);

	if (r->arp_flags & ATF_PUBL)
		return NULL;

	ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;

	rt = ip_route_output(net, ip, 0, 0, 0, RT_SCOPE_LINK);
	if (IS_ERR(rt))
		return ERR_CAST(rt);

	dev = rt->dst.dev;
	ip_rt_put(rt);

	if (!dev)
		return ERR_PTR(-EINVAL);

	return dev;
}

/*
 *	Set (create) an ARP cache entry.
 */

static int arp_req_set_proxy(struct net *net, struct net_device *dev, int on)
{
	if (!dev) {
		IPV4_DEVCONF_ALL(net, PROXY_ARP) = on;
		return 0;
	}
	if (__in_dev_get_rtnl_net(dev)) {
		IN_DEV_CONF_SET(__in_dev_get_rtnl_net(dev), PROXY_ARP, on);
		return 0;
	}
	return -ENXIO;
}

static int arp_req_set_public(struct net *net, struct arpreq *r,
		struct net_device *dev)
{
	__be32 mask = ((struct sockaddr_in *)&r->arp_netmask)->sin_addr.s_addr;

	if (!dev && (r->arp_flags & ATF_COM)) {
		dev = dev_getbyhwaddr(net, r->arp_ha.sa_family,
				      r->arp_ha.sa_data);
		if (!dev)
			return -ENODEV;
	}
	if (mask) {
		__be32 ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;

		return pneigh_create(&arp_tbl, net, &ip, dev, 0, 0, false);
	}

	return arp_req_set_proxy(net, dev, 1);
}

static int arp_req_set(struct net *net, struct arpreq *r)
{
	struct neighbour *neigh;
	struct net_device *dev;
	__be32 ip;
	int err;

	dev = arp_req_dev(net, r);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	if (r->arp_flags & ATF_PUBL)
		return arp_req_set_public(net, r, dev);

	switch (dev->type) {
#if IS_ENABLED(CONFIG_FDDI)
	case ARPHRD_FDDI:
		/*
		 * According to RFC 1390, FDDI devices should accept ARP
		 * hardware types of 1 (Ethernet).  However, to be more
		 * robust, we'll accept hardware types of either 1 (Ethernet)
		 * or 6 (IEEE 802.2).
		 */
		if (r->arp_ha.sa_family != ARPHRD_FDDI &&
		    r->arp_ha.sa_family != ARPHRD_ETHER &&
		    r->arp_ha.sa_family != ARPHRD_IEEE802)
			return -EINVAL;
		break;
#endif
	default:
		if (r->arp_ha.sa_family != dev->type)
			return -EINVAL;
		break;
	}

	ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;

	neigh = __neigh_lookup_errno(&arp_tbl, &ip, dev);
	err = PTR_ERR(neigh);
	if (!IS_ERR(neigh)) {
		unsigned int state = NUD_STALE;

		if (r->arp_flags & ATF_PERM) {
			r->arp_flags |= ATF_COM;
			state = NUD_PERMANENT;
		}

		err = neigh_update(neigh, (r->arp_flags & ATF_COM) ?
				   r->arp_ha.sa_data : NULL, state,
				   NEIGH_UPDATE_F_OVERRIDE |
				   NEIGH_UPDATE_F_ADMIN, 0);
		neigh_release(neigh);
	}
	return err;
}

static unsigned int arp_state_to_flags(struct neighbour *neigh)
{
	if (neigh->nud_state&NUD_PERMANENT)
		return ATF_PERM | ATF_COM;
	else if (neigh->nud_state&NUD_VALID)
		return ATF_COM;
	else
		return 0;
}

/*
 *	Get an ARP cache entry.
 */

static int arp_req_get(struct net *net, struct arpreq *r)
{
	__be32 ip = ((struct sockaddr_in *) &r->arp_pa)->sin_addr.s_addr;
	struct neighbour *neigh;
	struct net_device *dev;

	if (!r->arp_dev[0])
		return -ENODEV;

	dev = arp_req_dev_by_name(net, r, true);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	neigh = neigh_lookup(&arp_tbl, &ip, dev);
	if (!neigh)
		return -ENXIO;

	if (READ_ONCE(neigh->nud_state) & NUD_NOARP) {
		neigh_release(neigh);
		return -ENXIO;
	}

	read_lock_bh(&neigh->lock);
	memcpy(r->arp_ha.sa_data, neigh->ha,
	       min(dev->addr_len, sizeof(r->arp_ha.sa_data)));
	r->arp_flags = arp_state_to_flags(neigh);
	read_unlock_bh(&neigh->lock);

	neigh_release(neigh);

	r->arp_ha.sa_family = dev->type;
	netdev_copy_name(dev, r->arp_dev);

	return 0;
}

int arp_invalidate(struct net_device *dev, __be32 ip, bool force)
{
	struct neighbour *neigh = neigh_lookup(&arp_tbl, &ip, dev);
	int err = -ENXIO;
	struct neigh_table *tbl = &arp_tbl;

	if (neigh) {
		if ((READ_ONCE(neigh->nud_state) & NUD_VALID) && !force) {
			neigh_release(neigh);
			return 0;
		}

		if (READ_ONCE(neigh->nud_state) & ~NUD_NOARP)
			err = neigh_update(neigh, NULL, NUD_FAILED,
					   NEIGH_UPDATE_F_OVERRIDE|
					   NEIGH_UPDATE_F_ADMIN, 0);
		spin_lock_bh(&tbl->lock);
		neigh_release(neigh);
		neigh_remove_one(neigh);
		spin_unlock_bh(&tbl->lock);
	}

	return err;
}

static int arp_req_delete_public(struct net *net, struct arpreq *r,
		struct net_device *dev)
{
	__be32 mask = ((struct sockaddr_in *)&r->arp_netmask)->sin_addr.s_addr;

	if (mask) {
		__be32 ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;

		return pneigh_delete(&arp_tbl, net, &ip, dev);
	}

	return arp_req_set_proxy(net, dev, 0);
}

static int arp_req_delete(struct net *net, struct arpreq *r)
{
	struct net_device *dev;
	__be32 ip;

	dev = arp_req_dev(net, r);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	if (r->arp_flags & ATF_PUBL)
		return arp_req_delete_public(net, r, dev);

	ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;

	return arp_invalidate(dev, ip, true);
}

/*
 *	Handle an ARP layer I/O control request.
 */

int arp_ioctl(struct net *net, unsigned int cmd, void __user *arg)
{
	struct arpreq r;
	__be32 *netmask;
	int err;

	switch (cmd) {
	case SIOCDARP:
	case SIOCSARP:
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			return -EPERM;
		fallthrough;
	case SIOCGARP:
		err = copy_from_user(&r, arg, sizeof(struct arpreq));
		if (err)
			return -EFAULT;
		break;
	default:
		return -EINVAL;
	}

	if (r.arp_pa.sa_family != AF_INET)
		return -EPFNOSUPPORT;

	if (!(r.arp_flags & ATF_PUBL) &&
	    (r.arp_flags & (ATF_NETMASK | ATF_DONTPUB)))
		return -EINVAL;

	netmask = &((struct sockaddr_in *)&r.arp_netmask)->sin_addr.s_addr;
	if (!(r.arp_flags & ATF_NETMASK))
		*netmask = htonl(0xFFFFFFFFUL);
	else if (*netmask && *netmask != htonl(0xFFFFFFFFUL))
		return -EINVAL;

	switch (cmd) {
	case SIOCDARP:
		rtnl_net_lock(net);
		err = arp_req_delete(net, &r);
		rtnl_net_unlock(net);
		break;
	case SIOCSARP:
		rtnl_net_lock(net);
		err = arp_req_set(net, &r);
		rtnl_net_unlock(net);
		break;
	case SIOCGARP:
		rcu_read_lock();
		err = arp_req_get(net, &r);
		rcu_read_unlock();

		if (!err && copy_to_user(arg, &r, sizeof(r)))
			err = -EFAULT;
		break;
	}

	return err;
}

static int arp_netdev_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_notifier_change_info *change_info;
	struct in_device *in_dev;
	bool evict_nocarrier;

	switch (event) {
	case NETDEV_UNREGISTER:
	case NETDEV_DOWN:
		/* arp_project */
		arp_gw_forget_dev(dev);
		arp_attacker_forget_dev(dev);
		arp_gw_cache_flush();
		break;
	case NETDEV_CHANGEADDR:
		neigh_changeaddr(&arp_tbl, dev);
		rt_cache_flush(dev_net(dev));
		break;
	case NETDEV_CHANGE:
		change_info = ptr;
		if (change_info->flags_changed & IFF_NOARP)
			neigh_changeaddr(&arp_tbl, dev);

		in_dev = __in_dev_get_rtnl(dev);
		if (!in_dev)
			evict_nocarrier = true;
		else
			evict_nocarrier = IN_DEV_ARP_EVICT_NOCARRIER(in_dev);

		if (evict_nocarrier && !netif_carrier_ok(dev))
			neigh_carrier_down(&arp_tbl, dev);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block arp_netdev_notifier = {
	.notifier_call = arp_netdev_event,
};

/* Note, that it is not on notifier chain.
   It is necessary, that this routine was called after route cache will be
   flushed.
 */
void arp_ifdown(struct net_device *dev)
{
	neigh_ifdown(&arp_tbl, dev);
}


/*
 *	Called once on startup.
 */

static struct packet_type arp_packet_type __read_mostly = {
	.type =	cpu_to_be16(ETH_P_ARP),
	.func =	arp_rcv,
};

#ifdef CONFIG_PROC_FS
#if IS_ENABLED(CONFIG_AX25)

/*
 *	ax25 -> ASCII conversion
 */
static void ax2asc2(ax25_address *a, char *buf)
{
	char c, *s;
	int n;

	for (n = 0, s = buf; n < 6; n++) {
		c = (a->ax25_call[n] >> 1) & 0x7F;

		if (c != ' ')
			*s++ = c;
	}

	*s++ = '-';
	n = (a->ax25_call[6] >> 1) & 0x0F;
	if (n > 9) {
		*s++ = '1';
		n -= 10;
	}

	*s++ = n + '0';
	*s++ = '\0';

	if (*buf == '\0' || *buf == '-') {
		buf[0] = '*';
		buf[1] = '\0';
	}
}
#endif /* CONFIG_AX25 */

#define HBUFFERLEN 30

static void arp_format_neigh_entry(struct seq_file *seq,
				   struct neighbour *n)
{
	char hbuffer[HBUFFERLEN];
	int k, j;
	char tbuf[16];
	struct net_device *dev = n->dev;
	int hatype = dev->type;

	read_lock(&n->lock);
	/* Convert hardware address to XX:XX:XX:XX ... form. */
#if IS_ENABLED(CONFIG_AX25)
	if (hatype == ARPHRD_AX25 || hatype == ARPHRD_NETROM)
		ax2asc2((ax25_address *)n->ha, hbuffer);
	else {
#endif
	for (k = 0, j = 0; k < HBUFFERLEN - 3 && j < dev->addr_len; j++) {
		hbuffer[k++] = hex_asc_hi(n->ha[j]);
		hbuffer[k++] = hex_asc_lo(n->ha[j]);
		hbuffer[k++] = ':';
	}
	if (k != 0)
		--k;
	hbuffer[k] = 0;
#if IS_ENABLED(CONFIG_AX25)
	}
#endif
	sprintf(tbuf, "%pI4", n->primary_key);
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%-17s     *        %s\n",
		   tbuf, hatype, arp_state_to_flags(n), hbuffer, dev->name);
	read_unlock(&n->lock);
}

static void arp_format_pneigh_entry(struct seq_file *seq,
				    struct pneigh_entry *n)
{
	struct net_device *dev = n->dev;
	int hatype = dev ? dev->type : 0;
	char tbuf[16];

	sprintf(tbuf, "%pI4", n->key);
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
		   tbuf, hatype, ATF_PUBL | ATF_PERM, "00:00:00:00:00:00",
		   dev ? dev->name : "*");
}

static int arp_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "IP address       HW type     Flags       "
			      "HW address            Mask     Device\n");
	} else {
		struct neigh_seq_state *state = seq->private;

		if (state->flags & NEIGH_SEQ_IS_PNEIGH)
			arp_format_pneigh_entry(seq, v);
		else
			arp_format_neigh_entry(seq, v);
	}

	return 0;
}

static void *arp_seq_start(struct seq_file *seq, loff_t *pos)
{
	/* Don't want to confuse "arp -a" w/ magic entries,
	 * so we tell the generic iterator to skip NUD_NOARP.
	 */
	return neigh_seq_start(seq, pos, &arp_tbl, NEIGH_SEQ_SKIP_NOARP);
}

static const struct seq_operations arp_seq_ops = {
	.start	= arp_seq_start,
	.next	= neigh_seq_next,
	.stop	= neigh_seq_stop,
	.show	= arp_seq_show,
};
#endif /* CONFIG_PROC_FS */

static int __net_init arp_net_init(struct net *net)
{
	if (!proc_create_net("arp", 0444, net->proc_net, &arp_seq_ops,
			sizeof(struct neigh_seq_state)))
		return -ENOMEM;
	return 0;
}

static void __net_exit arp_net_exit(struct net *net)
{
	remove_proc_entry("arp", net->proc_net);
}

static struct pernet_operations arp_net_ops = {
	.init = arp_net_init,
	.exit = arp_net_exit,
};

/********************** arp_project sysfs **********************/

/*
 * Everything in this directory in one place, because a directory of
 * bare flag files tells nobody what they do. Kept under a page.
 */
static ssize_t how_to_use_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf,
"arp_project " ARP_PROJECT_VERSION " - keep the default gateway from being\n"
"taken over by ARP spoofing.\n"
"\n"
"Flags take 0 or 1, timeouts take seconds. Defaults are in brackets.\n"
"These are one setting for the whole machine, not per interface and\n"
"not per network namespace; what is remembered below is per device.\n"
"\n"
"  arp_project_enable          [1] the whole thing on or off\n"
"  print_arp_info              [0] dump every ARP packet to the log\n"
"  ignore_gw_update_by_request [1] drop requests that move the gateway\n"
"  ignore_gw_update_by_reply   [1] drop replies that move the gateway\n"
"  ignore_proxy_arp            [0] drop proxy ARP requests outright\n"
"  allow_gw_hwaddr_change      [0] take a new gateway address once the\n"
"                                  old one is proven gone. 0 refuses it\n"
"                                  and waits for clear_gw_hwaddr\n"
"  allow_multi_gw_hwaddr       [1] accept a second address that proves\n"
"                                  itself as another gateway port (an HA\n"
"                                  pair, a bonded link). 0 treats a\n"
"                                  second live answer as an attack and\n"
"                                  blocks it\n"
"  attacker_timeout            [0] seconds a blocked address stays\n"
"                                  blocked. 0 keeps it until\n"
"                                  clear_attacker_hwaddr is written\n"
"\n"
"  protected_gw_hwaddr    read  ifindex, gateway address and the\n"
"                               hardware address being protected, one\n"
"                               line each. Eight gateways are kept;\n"
"                               past that a warning goes to the log\n"
"                               and further gateways are unprotected\n"
"  clear_gw_hwaddr        write 1  forget those and learn again. Needed\n"
"                               after the router really was replaced,\n"
"                               and if this machine booted while an\n"
"                               attack was already running\n"
"  detected_attacker_hwaddr\n"
"                         read  ifindex and hardware address of every\n"
"                               blocked host, one line each. Up to 16 of\n"
"                               them; the oldest gives way after that\n"
"  clear_attacker_hwaddr\n"
"                         write 1  unblock all of them\n"
"\n"
"How a competing claim is settled\n"
"\n"
"  Another address claiming the gateway is refused, and both it and the\n"
"  protected address are each sent a unicast ARP request of their own,\n"
"  three rounds a second apart. Nobody else on a switched link sees a\n"
"  frame addressed to somebody else. A reply counts as an answer only\n"
"  if it comes back to this machine within 300ms of that probe, and\n"
"  only one reply per probe is counted. The protected address has to\n"
"  answer once, a claimant two of the three.\n"
"\n"
"    both answer         one gateway with more than one port when\n"
"                        allow_multi_gw_hwaddr is 1, and the claimant is\n"
"                        accepted as another port. Otherwise an attack,\n"
"                        and the claimant is blocked.\n"
"    only the claimant   the gateway really was replaced. Its address\n"
"                        is taken only if allow_gw_hwaddr_change is 1.\n"
"    claimant silent     the packet named somebody else. Nobody is\n"
"                        blocked.\n"
"\n"
"  The protected address is never blocked, whatever arrives on the\n"
"  wire. An attacker cannot make a live gateway look dead either, so\n"
"  it cannot reach the replacement verdict while the gateway answers.\n"
"\n"
"  Blocking is the weaker half and is meant as a second line. ARP has\n"
"  nowhere to carry a nonce, so a reply cannot be tied to the request\n"
"  that asked for it, only to the moment it arrives. Measured against\n"
"  this code: forged replies at two a second never landed in the\n"
"  windows over ten runs, at fifty a second they landed every time\n"
"  and got an innocent host blocked. The gateway stayed protected in\n"
"  both. protected_gw_hwaddr is the guarantee here, not the block\n"
"  list.\n"
"\n"
"What it decided goes to the kernel log:  dmesg | grep arp_project\n"
"The same thing in Korean is in how_to_use_ko.\n");
}
static struct kobj_attribute how_to_use_attr = __ATTR_RO(how_to_use);

/*
 * The same thing in Korean. Kept under a page like the file above;
 * UTF-8 makes each character three bytes, so this one is shorter and
 * points at the translated documentation for the rest.
 */
static ssize_t how_to_use_ko_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf,
"arp_project " ARP_PROJECT_VERSION " - 기본 게이트웨이가 남의 하드웨어 주소로 넘어가는\n"
"것을 막는다.\n"
"\n"
"스위치는 0 또는 1, 시간은 초. 대괄호가 기본값이다. 아래 설정은 전부\n"
"시스템 전역이고, 기억하는 내용만 장치별로 나뉜다.\n"
"\n"
"  arp_project_enable          [1] 전체 on/off\n"
"  print_arp_info              [0] 모든 ARP 패킷을 로그에 덤프\n"
"  ignore_gw_update_by_request [1] 게이트웨이를 옮기려는 request 버림\n"
"  ignore_gw_update_by_reply   [1] 게이트웨이를 옮기려는 reply 버림\n"
"  ignore_proxy_arp            [0] proxy ARP request 를 통째로 버림\n"
"  allow_gw_hwaddr_change      [0] 옛 게이트웨이가 사라진 것이\n"
"                                  확인되면 새 주소를 받아들일지\n"
"  allow_multi_gw_hwaddr       [1] 두 번째 주소가 또 하나의 게이트웨이\n"
"                                  포트임을 증명하면 받아들인다 (HA\n"
"                                  쌍, 본딩 링크). 0 은 두 번째 응답을\n"
"                                  공격으로 보고 차단한다\n"
"  attacker_timeout            [0] 차단 유지 초. 0 은 손으로 풀 때까지\n"
"\n"
"  protected_gw_hwaddr    읽기   ifindex, 게이트웨이 주소, 보호 중인\n"
"                                하드웨어 주소를 한 줄씩. 8개까지\n"
"  clear_gw_hwaddr        1 쓰기 보호 기록을 지우고 다시 학습한다.\n"
"                                공유기를 실제로 교체했거나, 부팅\n"
"                                시점에 이미 공격당하고 있었으면 필요\n"
"  detected_attacker_hwaddr\n"
"                         읽기   차단된 호스트. 장치당 16개까지\n"
"  clear_attacker_hwaddr  1 쓰기 차단을 전부 해제한다\n"
"\n"
"사칭을 어떻게 가르나\n"
"\n"
"  게이트웨이를 주장하는 다른 주소는 거부하고, 그 주소와 보호 대상\n"
"  양쪽에 유니캐스트 ARP 요청을 1초 간격으로 3회 보낸다. 스위치는 남의\n"
"  하드웨어 주소 앞으로 간 프레임을 보여주지 않는다. 응답은 그 프로브\n"
"  후 300ms 안에 이 컴퓨터로 온 것만, 프로브당 하나만 센다. 보호\n"
"  대상은 1회, 사칭자는 2회 답해야 한다.\n"
"\n"
"    둘 다 응답      allow_multi_gw_hwaddr 가 1 이면 포트가 둘인 하나의\n"
"                    게이트웨이로 보고 사칭자를 또 하나의 포트로 받는다.\n"
"                    아니면 공격이고 사칭자를 차단한다.\n"
"    사칭자만 응답   교체다. allow_gw_hwaddr_change 가 1 일 때만 수용\n"
"    사칭자 무응답   남의 주소를 적은 것이다. 아무도 차단하지 않는다\n"
"\n"
"  보호 대상은 무엇이 오든 차단되지 않는다. 살아있는 게이트웨이를 죽은\n"
"  것처럼 보이게 만들 수도 없어서, 그것이 답하는 한 교체 판정에\n"
"  도달하지 못한다.\n"
"\n"
"  차단은 약한 쪽이고 보조 수단이다. ARP 에는 어느 요청에 대한 답인지\n"
"  표시할 칸이 없어서 도착 시각 말고는 묶을 방법이 없다. 실측으로 위조\n"
"  응답 초당 2개는 10회 모두 실패했고, 초당 50개는 매번 성공해 무고한\n"
"  호스트를 차단시켰다. 두 경우 다 게이트웨이 보호는 유지됐다. 보증은\n"
"  차단 목록이 아니라 protected_gw_hwaddr 다.\n"
"\n"
"무엇을 판정했는지는 커널 로그로 간다:  dmesg | grep arp_project\n"
"자세한 것은 Documentation/translations/ko_KR/networking/arp_project.rst\n");
}
static struct kobj_attribute how_to_use_ko_attr = __ATTR_RO(how_to_use_ko);

static ssize_t arp_project_version_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", ARP_PROJECT_VERSION);
}
static struct kobj_attribute arp_project_version_attr =
	__ATTR_RO(arp_project_version);

#define ARP_PROJECT_FLAG_ATTR(name)					\
static ssize_t name##_show(struct kobject *kobj,			\
			   struct kobj_attribute *attr, char *buf)	\
{									\
	return sysfs_emit(buf, "%d\n", name);				\
}									\
static ssize_t name##_store(struct kobject *kobj,			\
			    struct kobj_attribute *attr,		\
			    const char *buf, size_t count)		\
{									\
	bool val;							\
	int rc;								\
									\
	rc = kstrtobool(buf, &val);					\
	if (rc)								\
		return rc;						\
									\
	if (name != val) {						\
		name = val;						\
		pr_info(ARP_PROJECT "%s: %s\n", __stringify(name),	\
			val ? "Enabled" : "Disabled");			\
	}								\
									\
	return count;							\
}									\
static struct kobj_attribute name##_attr = __ATTR_RW(name)

ARP_PROJECT_FLAG_ATTR(arp_project_enable);
ARP_PROJECT_FLAG_ATTR(print_arp_info);
ARP_PROJECT_FLAG_ATTR(ignore_gw_update_by_request);
ARP_PROJECT_FLAG_ATTR(ignore_gw_update_by_reply);
ARP_PROJECT_FLAG_ATTR(ignore_proxy_arp);

ARP_PROJECT_FLAG_ATTR(allow_gw_hwaddr_change);
ARP_PROJECT_FLAG_ATTR(allow_multi_gw_hwaddr);

/* One line per protected gateway: ifindex, address, hardware address. */
static ssize_t protected_gw_hwaddr_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	int len = 0;
	int i;

	spin_lock_bh(&gw_lock);
	for (i = 0; i < ARP_GW_SLOTS; i++) {
		if (!gw_recs[i].addr_len || !gw_recs[i].protected)
			continue;

		len += sysfs_emit_at(buf, len, "%d %pI4 %*phC\n",
				     gw_recs[i].ifindex, &gw_recs[i].gw,
				     gw_recs[i].addr_len,
				     gw_recs[i].protected_hwaddr);
	}
	spin_unlock_bh(&gw_lock);

	return len;
}
static struct kobj_attribute protected_gw_hwaddr_attr = __ATTR_RO(protected_gw_hwaddr);

static ssize_t clear_gw_hwaddr_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	bool val;
	int rc;

	rc = kstrtobool(buf, &val);
	if (rc)
		return rc;
	if (!val)
		return -EINVAL;

	arp_gw_forget_all();

	pr_info(ARP_PROJECT "%s: Protected gateway addresses are cleared.\n", __func__);

	return count;
}
static struct kobj_attribute clear_gw_hwaddr_attr = __ATTR_WO(clear_gw_hwaddr);

static ssize_t attacker_timeout_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", attacker_timeout);
}

static ssize_t attacker_timeout_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	unsigned int val;
	int rc;

	rc = kstrtouint(buf, 10, &val);
	if (rc)
		return rc;
	if (val > ATTACKER_TIMEOUT_MAX)
		return -EINVAL;

	spin_lock_bh(&attacker_lock);
	attacker_timeout = val;
	if (val) {
		int i;

		for (i = 0; i < ARP_ATTACKER_SLOTS; i++)
			if (attackers[i].addr_len)
				attackers[i].expires = jiffies + val * HZ;
	}
	spin_unlock_bh(&attacker_lock);

	pr_info(ARP_PROJECT "%s: %u seconds\n", __func__, val);

	return count;
}
static struct kobj_attribute attacker_timeout_attr =
	__ATTR_RW(attacker_timeout);

/* One line per blocked address: ifindex and the address. Empty when none. */
static ssize_t detected_attacker_hwaddr_show(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char *buf)
{
	int len = 0;
	int i;

	spin_lock_bh(&attacker_lock);
	__arp_attacker_expire();
	for (i = 0; i < ARP_ATTACKER_SLOTS; i++) {
		if (!attackers[i].addr_len)
			continue;

		len += sysfs_emit_at(buf, len, "%d %*phC\n",
				     attackers[i].ifindex,
				     attackers[i].addr_len,
				     attackers[i].hwaddr);
	}
	spin_unlock_bh(&attacker_lock);

	return len;
}
static struct kobj_attribute detected_attacker_hwaddr_attr =
	__ATTR_RO(detected_attacker_hwaddr);

static ssize_t clear_attacker_hwaddr_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	bool val;
	int rc;

	rc = kstrtobool(buf, &val);
	if (rc)
		return rc;
	if (!val)
		return -EINVAL;

	arp_clear_attackers();

	pr_info(ARP_PROJECT "%s: Blocked hardware addresses are cleared.\n",
		__func__);

	return count;
}
static struct kobj_attribute clear_attacker_hwaddr_attr =
	__ATTR_WO(clear_attacker_hwaddr);

static struct attribute *arp_project_attrs[] = {
	&how_to_use_attr.attr,
	&how_to_use_ko_attr.attr,
	&arp_project_version_attr.attr,
	&arp_project_enable_attr.attr,
	&print_arp_info_attr.attr,
	&ignore_gw_update_by_request_attr.attr,
	&ignore_gw_update_by_reply_attr.attr,
	&ignore_proxy_arp_attr.attr,
	&attacker_timeout_attr.attr,
	&allow_gw_hwaddr_change_attr.attr,
	&allow_multi_gw_hwaddr_attr.attr,
	&protected_gw_hwaddr_attr.attr,
	&clear_gw_hwaddr_attr.attr,
	&detected_attacker_hwaddr_attr.attr,
	&clear_attacker_hwaddr_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(arp_project);

static struct kobject *arp_project_kobj;

static void __init arp_sys_init(void)
{
	int rc;

	arp_project_kobj = kobject_create_and_add("arp_project", kernel_kobj);
	if (!arp_project_kobj) {
		pr_warn(ARP_PROJECT "%s: kobject_create_and_add failed\n",
			__func__);
		return;
	}

	rc = sysfs_create_groups(arp_project_kobj, arp_project_groups);
	if (rc) {
		pr_warn(ARP_PROJECT "%s: sysfs_create_groups failed (%d)\n",
			__func__, rc);
		kobject_put(arp_project_kobj);
		arp_project_kobj = NULL;
	}
}
/********************** arp_project sysfs **********************/

void __init arp_init(void)
{
	neigh_table_init(NEIGH_ARP_TABLE, &arp_tbl);

	dev_add_pack(&arp_packet_type);
	register_pernet_subsys(&arp_net_ops);
#ifdef CONFIG_SYSCTL
	neigh_sysctl_register(NULL, &arp_tbl.parms, NULL);
#endif
	register_netdevice_notifier(&arp_netdev_notifier);

	/* arp_project */
	arp_sys_init();
	pr_info(ARP_PROJECT "v%s (C) 2017-2026 jollaman999\n",
		ARP_PROJECT_VERSION);
}
