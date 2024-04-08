#include <stdio.h>
#include <stdlib.h>

#include "lib.h"
#include "trie.h"

void init_node_trie(trie_node *node)
{
    node->best_match = NULL;
    node->left_0 = NULL;
    node->right_1 = NULL;
}

void generate_trie(struct route_table_entry *rtable, int rtable_len, trie_node *root)
{
    // initialize the first node in the trie
    root = malloc(sizeof(trie_node));
    init_node_trie(root);

    trie_node *aux_trie_node;
    uint32_t bit;
    //int direction;

    for (int i = 0; i < rtable_len; i++)
    {
        // pointer to the current node
        //trie_node *current = root;

        // iterate through the bits of the prefix
        for (int i = 31; i >= 0; i--)
        {
            bit = 1 << i;

            if ((bit & rtable[i].mask) != 0)
            {
                //direction = ((bit & rtable[i].prefix) == 0) ? 0 : 1;
            }
        }
    }
}