#include <netinet/ip.h>
#include <xtables.h>
#include <libiptc/libip6tc.h>
// #include <iptables/internal.h>
void print_rule6(const struct ip6t_entry *e, struct xtc_handle *h, const char *chain, int counters);
