#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>

struct route_table_entry *get_best_route(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len)
{
	struct route_table_entry *best_entry = NULL;

	for (int i = 0; i < rtable_len; i++)
	{
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix)
		{

			if (best_entry == NULL)
				best_entry = &rtable[i];
			else if (ntohl(best_entry->mask) < ntohl(rtable[i].mask))
			{
				best_entry = &rtable[i];
			}
		}
	}

	return best_entry;
}

struct arp_table_entry *get_mac_entry(uint32_t ip_dest, struct arp_table_entry *arp_table, int arp_table_len)
{
	for (int i = 0; i < arp_table_len; i++)
	{
		if (arp_table[i].ip == ip_dest)
		{
			return &arp_table[i];
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// declaring and allocating memory for the rtable
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	int rtable_len = read_rtable(argv[1], rtable);

	// declaring and allocating memory for the ARP table
	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * 1000);
	int arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		printf("\nSunt inainte de if ");
		if (ntohs(eth_hdr->ether_type) == 0x0800)
		{
			printf("Ajung in if ");
			// getting the ip_header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// doing the checksum verification
			uint16_t aux_check_h = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			if (aux_check_h != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
			{
				continue;
			}
			printf("Trec de checksum ");

			// handle the ttl field
			uint8_t aux_ttl_h = ip_hdr->ttl;
			printf(" %d ", aux_ttl_h);
			if (aux_ttl_h < 2)
			{
				// TODO: send ICMP message
				continue;
			}
			else
				aux_ttl_h -= 1;
			ip_hdr->ttl = aux_ttl_h;
			printf(" %d ", ip_hdr->ttl);
			printf("trec de ttl ");

			// search the next hop in the rtable
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rtable_len);
			if (best_route == NULL)
			{
				// TODO: send the ICMP package
				continue;
			}
			printf("%x\n", ntohl(best_route->next_hop));
			printf("trec de next hop");

			// update the checksum
			ip_hdr->check = 0;
			aux_check_h = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
			ip_hdr->check = htons(aux_check_h);

			printf("%x", ip_hdr->check);

			// update the ethernet header

			// get the next_hop MAC
			struct arp_table_entry *nexthop_mac = get_mac_entry(best_route->next_hop, arp_table, arp_table_len);
			printf("%x %x %x %x %x %x", nexthop_mac->mac[0], nexthop_mac->mac[1], nexthop_mac->mac[2], nexthop_mac->mac[3], nexthop_mac->mac[4], nexthop_mac->mac[5]);

			// source address
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, nexthop_mac->mac, sizeof(eth_hdr->ether_dhost));

			//send the package
			send_to_link(best_route->interface, buf, len);
		}
	}
	free(rtable);
	free(arp_table);
}
