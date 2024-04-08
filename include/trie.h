#ifndef TRIE
#define TRIE

#include "lib.h"

// struct for anode in trie
typedef struct trie_node
{
    struct route_table_entry *best_match;
    struct trie_node *left_0, *right_1;

} trie_node;

// initialize a node
void init_node_trie(trie_node *node);

#endif