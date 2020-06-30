#include <getopt.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <limits.h>
#include <ip6tables.h>
#include <xtables.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
// #include "ip6tables-multi.h"
// #include "xshared.h"

static const char unsupported_rev[] = " [unsupported revision]";

/* This assumes that mask is contiguous, and byte-bounded. */
static void
print_iface(char letter, const char *iface, const unsigned char *mask,
	    int invert)
{
	unsigned int i;

	if (mask[0] == 0)
		return;

	printf("%s -%c ", invert ? " !" : "", letter);

	for (i = 0; i < IFNAMSIZ; i++) {
		if (mask[i] != 0) {
			if (iface[i] != '\0')
				printf("%c", iface[i]);
		} else {
			/* we can access iface[i-1] here, because
			 * a few lines above we make sure that mask[0] != 0 */
			if (iface[i-1] != '\0')
				printf("+");
			break;
		}
	}
}

/* The ip6tables looks up the /etc/protocols. */
static void print_proto(uint16_t proto, int invert)
{
	if (proto) {
		unsigned int i;
		const char *invertstr = invert ? " !" : "";

		const struct protoent *pent = getprotobynumber(proto);
		if (pent) {
			printf("%s -p %s",
			       invertstr, pent->p_name);
			return;
		}

		for (i = 0; xtables_chain_protos[i].name != NULL; ++i)
			if (xtables_chain_protos[i].num == proto) {
				printf("%s -p %s",
				       invertstr, xtables_chain_protos[i].name);
				return;
			}

		printf("%s -p %u", invertstr, proto);
	}
}

static int print_match_save(const struct xt_entry_match *e,
			const struct ip6t_ip6 *ip)
{
	const char *name = e->u.user.name;
	const int revision = e->u.user.revision;
	struct xtables_match *match, *mt, *mt2;

	match = xtables_find_match(name, XTF_TRY_LOAD, NULL);
	if (match) {
		mt = mt2 = xtables_find_match_revision(name, XTF_TRY_LOAD,
						       match, revision);
		if (!mt2)
			mt2 = match;
		printf(" -m %s", mt2->alias ? mt2->alias(e) : name);

		/* some matches don't provide a save function */
		if (mt && mt->save)
			mt->save(ip, e);
		else if (match->save)
			printf(unsupported_rev);
	} else {
		if (e->u.match_size) {
			fprintf(stderr,
				"Can't find library for match `%s'\n",
				name);
			exit(1);
		}
	}
	return 0;
}

/* Print a given ip including mask if necessary. */
static void print_ip(const char *prefix, const struct in6_addr *ip,
		     const struct in6_addr *mask, int invert)
{
	char buf[51];
	int l = xtables_ip6mask_to_cidr(mask);

	if (l == 0 && !invert)
		return;

	printf("%s %s %s",
		invert ? " !" : "",
		prefix,
		inet_ntop(AF_INET6, ip, buf, sizeof buf));

	if (l == -1)
		printf("/%s", inet_ntop(AF_INET6, mask, buf, sizeof buf));
	else
		printf("/%d", l);
}

/* We want this to be readable, so only print out necessary fields.
 * Because that's the kind of world I want to live in.
 */
void print_rule6(const struct ip6t_entry *e,
		       struct xtc_handle *h, const char *chain, int counters)
{
	const struct xt_entry_target *t;
	const char *target_name;

	/* print counters for iptables-save */
	if (counters > 0)
		printf("[%llu:%llu] ", (unsigned long long)e->counters.pcnt, (unsigned long long)e->counters.bcnt);

	/* print chain name */
	printf("-A %s", chain);

	/* Print IP part. */
	print_ip("-s", &(e->ipv6.src), &(e->ipv6.smsk),
			e->ipv6.invflags & IP6T_INV_SRCIP);

	print_ip("-d", &(e->ipv6.dst), &(e->ipv6.dmsk),
			e->ipv6.invflags & IP6T_INV_DSTIP);

	print_iface('i', e->ipv6.iniface, e->ipv6.iniface_mask,
		    e->ipv6.invflags & IP6T_INV_VIA_IN);

	print_iface('o', e->ipv6.outiface, e->ipv6.outiface_mask,
		    e->ipv6.invflags & IP6T_INV_VIA_OUT);

	print_proto(e->ipv6.proto, e->ipv6.invflags & XT_INV_PROTO);

#if 0
	/* not definied in ipv6
	 * FIXME: linux/netfilter_ipv6/ip6_tables: IP6T_INV_FRAG why definied? */
	if (e->ipv6.flags & IPT_F_FRAG)
		printf("%s -f",
		       e->ipv6.invflags & IP6T_INV_FRAG ? " !" : "");
#endif

	if (e->ipv6.flags & IP6T_F_TOS)
		printf("%s -? %d",
		       e->ipv6.invflags & IP6T_INV_TOS ? " !" : "",
		       e->ipv6.tos);

	/* Print matchinfo part */
	if (e->target_offset) {
		IP6T_MATCH_ITERATE(e, print_match_save, &e->ipv6);
	}

	/* print counters for iptables -R */
	if (counters < 0)
		printf(" -c %llu %llu", (unsigned long long)e->counters.pcnt, (unsigned long long)e->counters.bcnt);

	/* Print target name and targinfo part */
	target_name = ip6tc_get_target(e, h);
	t = ip6t_get_target((struct ip6t_entry *)e);
	if (t->u.user.name[0]) {
		const char *name = t->u.user.name;
		const int revision = t->u.user.revision;
		struct xtables_target *target, *tg, *tg2;

		target = xtables_find_target(name, XTF_TRY_LOAD);
		if (!target) {
			fprintf(stderr, "Can't find library for target `%s'\n",
				name);
			exit(1);
		}

		tg = tg2 = xtables_find_target_revision(name, XTF_TRY_LOAD,
							target, revision);
		if (!tg2)
			tg2 = target;
		printf(" -j %s", tg2->alias ? tg2->alias(t) : target_name);

		if (tg && tg->save)
			tg->save(&e->ipv6, t);
		else if (target->save)
			printf(unsupported_rev);
		else {
			/* If the target size is greater than xt_entry_target
			 * there is something to be saved, we just don't know
			 * how to print it */
			if (t->u.target_size !=
			    sizeof(struct xt_entry_target)) {
				fprintf(stderr, "Target `%s' is missing "
						"save function\n",
					name);
				exit(1);
			}
		}
	} else if (target_name && (*target_name != '\0'))
#ifdef IP6T_F_GOTO
		printf(" -%c %s", e->ipv6.flags & IP6T_F_GOTO ? 'g' : 'j', target_name);
#else
		printf(" -j %s", target_name);
#endif

	printf("\n");
}
