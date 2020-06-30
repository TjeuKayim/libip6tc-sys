#include "libiptc/libip6tc.h"
#include "libiptc/libiptc.h"
#include "linux/netfilter/xt_bpf.h"
#include "linux/netfilter/xt_NFQUEUE.h"
#include "linux/netfilter/xt_CT.h"
#include "linux/netfilter/xt_comment.h"
#include "linux/netfilter_ipv6/ip6t_hl.h"
#undef _IP6T_HL_H //FIXME: hack fix for uppercase and lowercase conflict
#include "linux/netfilter_ipv6/ip6t_HL.h"
#include "linux/netfilter_ipv4/ipt_ttl.h"
#undef _IPT_TTL_H
#include "linux/netfilter_ipv4/ipt_TTL.h"

// #include "xtables.h"
#include "ip6tables.h"
