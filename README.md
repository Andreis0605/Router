# Mentiune: Implementarea temei pleaca de la implementari ale laboratorului 4
# Tema 1: ROUTER

## General

> I solve all the thask of the homework(100p on the local checker). In the following sections I will explain the API that I defined and the implementation of each task.

## The API

-  `struct route_table_entry *get_best_rtable_entry(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len)`

>Function that returns that returns the best match in a routing table for a given IPv4 address or NULL if there is no match. 

- `void bsearch_rtable(int left, int right, int *best_pos, uint32_t ip_dest, struct route_table_entry *rtable)`

>Function that uses binary search in order to find the best match in the given routing table. The result is returned as an index in the best_pos parameter. If no match is found, the value of best_pos is not moified.

- `int compare_rtable_entry(const void *x, const void *y)`

>Function used as a comparator for sorting the routing table. It sorts the routing table entries first by the length of the mask, and, if the masks are equal, by prefix.

- `struct arp_table_entry *get_arp_table_entry(uint32_t ip_dest, struct arp_table_entry *arp_table, int arp_table_len)`

>Function that returns an entry in the arp table for a given ip or NULL if there is no entry that matches the ip or the table is empty

- `void send_arp_request(uint32_t searched_ip, int found_interface)`

>Function that sends an ARP request in order to find the MAC address of the next hop for the given IP. Sends the message on the found_interface, which must be determined before by searching in the routing table. 

- `void send_arp_reply(struct ether_header *received_eth_header, struct arp_header *received_arp_header, int received_interface)`

>Function that sends an ARP reply when receiving an ARP request. Uses the data from the received Ethernet and ARP headers and builds a new packet that gets send on the interface that received the request. 

- `void send_ICMP_dest_unreach(struct ether_header *dropped_ether_header, struct iphdr *dropped_ip_header, int dropped_interface)`

>Function that sends an ICMP message when a received packet can not be routed using the routing table. It uses the dropped packet headers to build a new ICMP packet with the message Destination unreachable. Then sends it on the interface that received the dropped packet.

- `void send_ICMP_ttl_exceded(struct ether_header *dropped_ether_header, struct iphdr *dropped_ip_header, int dropped_interface)`

>Function that sends an ICMP message when a received packets time to live is 0 or 1. It uses the dropped packet headers to build a new ICMP packet with the message Time exceded. Then sends it on the interface that received the dropped packet.

## Task implementation

### IPv4 packet routing

>When the router receives an IPv4 packet, it first checks if the packet is for it. If it is, the router starts processing it(more on that in the ICMP section). If not, it starts the routing process. First, the router checks if the checksum of the packet is correct. If not, it drops the packet. After that, it checks the TTL of the packet. If it is less that 2, the router drops the packet and sends an ICMP Time exceded message. If not, it updates the TTL field. After this,the router searches in the routing table for the interface that the packet will be forwadet to. If no entry in the routing table matches the IP of the destination it sends an ICMP Destination unreachable error message and drops the packet. After this, the program recalculates the checksum of the IPv4 packet. The last step is to get the MAC address of the next hop. The router searches the ARP table. If an entry that matches the IP is found, write the address in the Ethernet header and send the packet. If no match is found, add the pachet in a queue and send an ARP request in order to find the MAC of the next hop.

### Efficient Longest Prefix Match

>The router first reads the routing table from the given file. After that it sorts the routing table by the following criteria: descening by mask, and, if two masks are equal, ascending by prefix. When the program wants to find a match for a given IPv4 address, it uses a binary search that does not stop at the first match, and continues the seach. If a new match is found, it is guaranteed to be better than the previous one.

### ARP protocol
>
>>The ARP protocol is used to determine the MAC address of the next hop. When we need to send a packet, first we look for a MAC address in the ARP table. If no entry matches the IP of the next hop, we add the current packet in a queue and broadcast an ARP request on the interface determined earlier in the routing process(see IPv4 packet routing section). When we receive an ARP reply, we write the information in the ARP table and then we iterate through the queue with the packets waiting to be send (the implementation uses two queues: one for the packet itself and one for the length of the packet). If we find a packet that was waiting for that specific MAC address, we write it in the Eternet header and send it.
>
>>When receiving an ARP request, the router checks if the request was send for it. If this was the case, it sends an ARP reply with the information that the other device asked for(the MAC address of one of the interfaces of the router).

### ICMP protocol

> The router sends three diffrent types of ICMP messages
>
> - Time exception: send when the TTL of an IPv4 packet is 0 or 1 (send by calling the send_ICMP_ttl_exceded function).
> - Destination unreachable: send by when there is no entry in the routing table that matches the destination address of an IPv4 packet (send by send_ICMP_dest_unreach function).
> - Echo reply: send when the router receives an Echo request ICMP packet (send the Echo request packet back with the type, checksums and source and destination addresses modifed).
