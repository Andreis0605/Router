#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>
#include "trie.h"

struct route_table_entry *get_best_route(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len)
{
	struct route_table_entry *best_entry = NULL;

	for (int i = 0; i < rtable_len; i++)
	{
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix)
		{
			return &rtable[i];
		}
	}

	return best_entry;
}

struct arp_table_entry *get_mac_entry(uint32_t ip_dest, struct arp_table_entry *arp_table, int arp_table_len)
{
	if (arp_table_len == 0)
		return NULL;

	for (int i = 0; i < arp_table_len; i++)
	{
		if (arp_table[i].ip == ip_dest)
		{
			return &arp_table[i];
		}
	}

	return NULL;
}

// function that compares 2 rtable entries
int compare_rtable_entry(const void *x, const void *y)
{
	struct route_table_entry *entry_x = (struct route_table_entry *)x;
	struct route_table_entry *entry_y = (struct route_table_entry *)y;

	if (entry_x->mask < entry_y->mask)
		return 1;
	if (entry_x->mask > entry_y->mask)
		return -1;

	if (entry_x->prefix < entry_y->prefix)
		return 1;
	if (entry_x->prefix > entry_y->prefix)
		return -1;

	return 0;
}

// function for sending an ICMP packet when destination is unreachable
void send_ICMP_dest_unreach(struct ether_header *dropped_ether_header, struct iphdr *dropped_ip_header, int dropped_interface)
{
	char *buf = malloc(sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	void *payload = (buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	// solving the ethernet header
	memcpy(eth_hdr->ether_dhost, dropped_ether_header->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, dropped_ether_header->ether_dhost, 6);
	eth_hdr->ether_type = htons(0x0800);

	// solving the ip field
	// if error use memcpy
	ip_hdr->ihl = 5;
	ip_hdr->version = 4;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = ntohs(2 * sizeof(ip_hdr) + sizeof(icmp_hdr) + 8);
	ip_hdr->id = 1;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = 1;
	ip_hdr->check = 0;
	ip_hdr->saddr = dropped_ip_header->daddr; // not true, maybe change to get_interface_ip
	ip_hdr->daddr = dropped_ip_header->saddr;

	// solve the icmp field
	icmp_hdr->type = 3;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;

	// copy the data for the payload
	memcpy(payload, dropped_ip_header, sizeof(struct iphdr)); // ip of dropped packet
	memcpy(payload + sizeof(struct iphdr), dropped_ip_header + sizeof(struct iphdr), 8);

	// calculate the checksum
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(ip_hdr)));
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(icmp_hdr)));

	// send packet
	send_to_link(dropped_interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8);

	free(buf);
}

// function for sending an ICMP packet when ttl reaches 0
void send_ICMP_ttl_exceded(struct ether_header *dropped_ether_header, struct iphdr *dropped_ip_header, int dropped_interface)
{
	char *buf = malloc(sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	void *payload = (buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	// solving the ethernet header
	memcpy(eth_hdr->ether_dhost, dropped_ether_header->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, dropped_ether_header->ether_dhost, 6);
	eth_hdr->ether_type = htons(0x0800);

	// solving the ip field
	// if error use memcpy
	ip_hdr->ihl = 5;
	ip_hdr->version = 4;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = ntohs(2 * sizeof(ip_hdr) + sizeof(icmp_hdr) + 8);
	ip_hdr->id = 1;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = 1;
	ip_hdr->check = 0;
	ip_hdr->saddr = dropped_ip_header->daddr; // not true, maybe change to get_interface_ip
	ip_hdr->daddr = dropped_ip_header->saddr;

	// solve the icmp field
	icmp_hdr->type = 11;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;

	// copy the data for the payload
	memcpy(payload, dropped_ip_header, sizeof(struct iphdr)); // ip of dropped packet
	memcpy(payload + sizeof(struct iphdr), dropped_ip_header + sizeof(struct iphdr), 8);

	// calculate the checksum
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(ip_hdr)));
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(icmp_hdr)));

	// send packet
	send_to_link(dropped_interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8);

	free(buf);
}

void send_arp_request(uint32_t searched_ip, int found_interface)
{
	// alocate memory for the packet
	char *buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// solve the ethernet header
	memset(eth_hdr->ether_dhost, 255, 6);
	get_interface_mac(found_interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(0x0806);

	// solve the arp header
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	get_interface_mac(found_interface, arp_hdr->sha);
	arp_hdr->spa = get_interface_ip(found_interface);
	memset(arp_hdr->tha, 0, 6);
	arp_hdr->tpa = searched_ip;

	send_to_link(found_interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));

	free(buf);
}

void send_arp_reply(struct ether_header *received_eth_header, struct arp_header *received_arp_header, int received_interface)
{
	char *buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// solve the ethernet header
	memcpy(eth_hdr->ether_dhost, received_eth_header->ether_shost, 6);
	get_interface_mac(received_interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(0X0806);

	// solve the arp_header
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(2);
	get_interface_mac(received_interface, arp_hdr->sha);
	arp_hdr->spa = get_interface_ip(received_interface);
	memcpy(arp_hdr->tha, received_arp_header->sha, 6);
	arp_hdr->tpa = received_arp_header->spa;

	send_to_link(received_interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));

	free(buf);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// declaring and allocating memory for the rtable
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	int rtable_len = read_rtable(argv[1], rtable);

	// sort the rtable
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_rtable_entry);

	// declaring and allocating memory for the ARP table
	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * 1000);
	int arp_table_len = 0;

	// initialize the queue for the packets that dont find their ip
	queue waiting_to_be_sent_packet = queue_create();
	queue waiting_to_be_sent_len = queue_create();

	// auxiliary queue for the arp protocol operations
	queue aux_queue_buf = queue_create();
	queue aux_queue_len = queue_create();

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		// printf("%02X\n", get_interface_ip(interface));

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		printf("%02x\n", ntohs(eth_hdr->ether_type));
		fflush(NULL);

		if (ntohs(eth_hdr->ether_type) == 0x0800)
		{

			//  getting the ip_header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			if (ip_hdr->protocol == 1 && ip_hdr->daddr == get_interface_ip(interface))
			{
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				if (icmp_hdr->type == 8)
				{
					// switching the ethernet header;
					uint8_t mac_aux[6];
					memcpy(mac_aux, eth_hdr->ether_shost, 6);
					memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
					memcpy(eth_hdr->ether_dhost, mac_aux, 6);

					// switching the ipv4 header
					uint32_t aux_addr;
					aux_addr = ip_hdr->saddr;
					ip_hdr->saddr = ip_hdr->daddr;
					ip_hdr->daddr = aux_addr;

					// modify the ICMP type
					icmp_hdr->type = 0;

					// recalculate the checksums
					ip_hdr->check = 0;
					ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

					// send the package
					send_to_link(interface, buf, len);
				}
				else
				{
					uint16_t aux_check_h = ntohs(ip_hdr->check);
					ip_hdr->check = 0;
					if (aux_check_h != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
					{
						continue;
					}

					// handle the ttl field
					uint8_t aux_ttl_h = ip_hdr->ttl;
					if (aux_ttl_h < 2)
					{
						send_ICMP_ttl_exceded(eth_hdr, ip_hdr, interface);
						continue;
					}
					else
						aux_ttl_h -= 1;
					ip_hdr->ttl = aux_ttl_h;

					// search the next hop in the rtable
					struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rtable_len);
					if (best_route == NULL)
					{
						send_ICMP_dest_unreach(eth_hdr, ip_hdr, interface);
						continue;
					}

					// update the checksum
					ip_hdr->check = 0;
					aux_check_h = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
					ip_hdr->check = htons(aux_check_h);

					// update the ethernet header

					// get the next_hop MAC
					struct arp_table_entry *nexthop_mac = get_mac_entry(best_route->next_hop, arp_table, arp_table_len);
					if (nexthop_mac == NULL)
					{
						printf("Nu am gasit MAC in Arp_table1\n");
						// we dont know the MAC of the next hop

						// make a copy of the packet and the len
						char *aux_buf = malloc(len);
						int *aux_len = malloc(sizeof(int));

						memcpy(aux_buf, buf, len);
						aux_len[0] = len;

						// add the packet in a list for when we receive an arp packet
						queue_enq(waiting_to_be_sent_packet, aux_buf);
						queue_enq(waiting_to_be_sent_len, aux_len);

						// send the arp request
						send_arp_request(best_route->next_hop, best_route->interface);
						continue;
					}

					// source address
					get_interface_mac(best_route->interface, eth_hdr->ether_shost);
					memcpy(eth_hdr->ether_dhost, nexthop_mac->mac, sizeof(eth_hdr->ether_dhost));

					// send the package
					send_to_link(best_route->interface, buf, len);
				}
			}
			else
			{
				// doing the checksum verification
				uint16_t aux_check_h = ntohs(ip_hdr->check);
				ip_hdr->check = 0;
				if (aux_check_h != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
				{
					continue;
				}

				// handle the ttl field
				uint8_t aux_ttl_h = ip_hdr->ttl;
				// printf(" %d ", aux_ttl_h);
				if (aux_ttl_h < 2)
				{
					// TODO: send ICMP message
					send_ICMP_ttl_exceded(eth_hdr, ip_hdr, interface);
					continue;
				}
				else
					aux_ttl_h -= 1;
				ip_hdr->ttl = aux_ttl_h;

				// search the next hop in the rtable
				struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rtable_len);
				if (best_route == NULL)
				{
					// TODO: send the ICMP package
					send_ICMP_dest_unreach(eth_hdr, ip_hdr, interface);
					continue;
				}
				// printf("%x\n", ntohl(best_route->next_hop));
				// printf("trec de next hop");

				// update the checksum
				ip_hdr->check = 0;
				aux_check_h = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
				ip_hdr->check = htons(aux_check_h);

				// printf("%x", ip_hdr->check);

				// update the ethernet header

				// get the next_hop MAC
				struct arp_table_entry *nexthop_mac = get_mac_entry(best_route->next_hop, arp_table, arp_table_len);
				if (nexthop_mac == NULL)
				{
					printf("Nu am gasit MAC in Arp_table2\n");

					char *aux_buf = malloc(len);
					int *aux_len = malloc(sizeof(int));

					memcpy(aux_buf, buf, len);
					aux_len[0] = len;

					// add the packet in a list for when we receive an arp packet
					queue_enq(waiting_to_be_sent_packet, aux_buf);
					queue_enq(waiting_to_be_sent_len, aux_len);

					// send the arp request
					send_arp_request(best_route->next_hop, best_route->interface);
					continue;
				}
				// printf("%x %x %x %x %x %x", nexthop_mac->mac[0], nexthop_mac->mac[1], nexthop_mac->mac[2], nexthop_mac->mac[3], nexthop_mac->mac[4], nexthop_mac->mac[5]);

				// source address
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, nexthop_mac->mac, sizeof(eth_hdr->ether_dhost));

				// send the package
				send_to_link(best_route->interface, buf, len);
			}
		}
		else
		{
			printf("Primesc un packet arp\n");
			fflush(NULL);
			// handle the arp packet
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			uint8_t aux_mac[6];
			get_interface_mac(interface, aux_mac);

			// somebody asking for my MAC adress
			if (arp_hdr->op == htons(1) && arp_hdr->tpa == get_interface_ip(interface))
			{
				send_arp_reply(eth_hdr, arp_hdr, interface);
				continue;
			}

			// get a reply for a previous request
			if (arp_hdr->op == htons(2) && arp_hdr->tpa == get_interface_ip(interface))
			{
				printf("Am primit un arp reply\n");
				fflush(NULL);
				// add the response to the ARP_table
				memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, 6);
				arp_table[arp_table_len].ip = arp_hdr->spa;
				arp_table_len++;

				printf("Scriu in arp_table\n");
				fflush(NULL);

				// iterate through the queue of packets

				while (!queue_empty(waiting_to_be_sent_packet))
				{
					// get the packet from the waiting queue
					char *buf = queue_deq(waiting_to_be_sent_packet);
					int *buf_len = queue_deq(waiting_to_be_sent_len);

					printf("Merge dequeue si imi da %p si len %u\n", buf, *buf_len);
					fflush(NULL);

					// get the headers
					struct ether_header *eth_hdr_buf = (struct ether_header *)buf;
					struct iphdr *ip_hdr_buf = (struct iphdr *)(buf + sizeof(struct ether_header));

					printf("Merge sa iau headerele\n");
					fflush(NULL);

					printf("%02x\n", ntohl(ip_hdr_buf->daddr));
					fflush(NULL);

					// get the interface for the packet
					struct route_table_entry *best_route = get_best_route(ip_hdr_buf->daddr, rtable, rtable_len);

					printf("Gasesc best route care e %p\n", best_route);
					fflush(NULL);

					// recalculate the checksum
					ip_hdr_buf->check = 0;
					uint16_t aux_check_h = checksum((uint16_t *)ip_hdr_buf, sizeof(struct iphdr));
					ip_hdr_buf->check = htons(aux_check_h);

					printf("Trec de checksum\n");
					fflush(NULL);

					// get the MAC of the destination
					struct arp_table_entry *nexthop_mac = get_mac_entry(best_route->next_hop, arp_table, arp_table_len);
					if (nexthop_mac == NULL)
					{
						// if not found, keep waiting for an arp reply
						queue_enq(aux_queue_buf, buf);
						queue_enq(aux_queue_len, buf_len);
						continue;
					}

					printf("Trec de gasirea MACului\n");
					fflush(NULL);

					// write the mac addresses
					get_interface_mac(best_route->interface, eth_hdr_buf->ether_shost);
					memcpy(eth_hdr_buf->ether_dhost, nexthop_mac->mac, sizeof(eth_hdr_buf->ether_dhost));

					// send the package
					send_to_link(best_route->interface, buf, *buf_len); // this is not ok
				}

				printf("Trec e primul while\n");
				fflush(NULL);

				// spill the aux_queue in the main queue
				while (!queue_empty(aux_queue_buf))
				{
					char *buf2 = queue_deq(aux_queue_buf);
					int *buf_len2 = queue_deq(aux_queue_len);
					queue_enq(waiting_to_be_sent_packet, buf2);
					queue_enq(waiting_to_be_sent_len, buf_len2);
				}
			}
		}
	}
	free(rtable);
	free(arp_table);
}