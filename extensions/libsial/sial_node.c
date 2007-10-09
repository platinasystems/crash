/*
 * Copyright 2001 Silicon Graphics, Inc. All rights reserved.
 */
/*
	These function are use to allocate a new node.
	It's a layer between the type specific functions and the parser.
*/
#include "sial.h"
#include <setjmp.h>

/*
	Allocate a new node structure
*/
node_t*
sial_newnode()
{
node_t*n;

	n = (node_t*) sial_calloc(sizeof(node_t));
	TAG(n);
	return n;
}

void
sial_free_siblings(node_t*ni)
{
	while(ni) {

		node_t*next=ni->next;

		NODE_FREE(ni);

		ni=next;
	}
}

/*
	This function is called du ring compile time
	to exevaluate constant expression, like sizeof() and
	array sizes and enum constant.
*/
value_t *
sial_exenode(node_t*n)
{
value_t *v;
int *exval;
jmp_buf exitjmp;
void *sa;
srcpos_t p;

	sial_curpos(&n->pos, &p);
	sa=sial_setexcept();

	if(!setjmp(exitjmp)) {

		sial_pushjmp(J_EXIT, &exitjmp, &exval);
		v=NODE_EXE(n);
		sial_rmexcept(sa);
		sial_popjmp(J_EXIT);

	} else {

		sial_rmexcept(sa);
		return 0;

	}
	sial_curpos(&p, 0);
	return v;
}
