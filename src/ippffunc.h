/* $Id: ippf.h,v 1.1 2007/08/13 17:55:33 swp Exp $ */

#ifndef __ippf_h__
#define __ippf_h__

#include <sys/cdefs.h>

struct ippf;

__BEGIN_DECLS
struct ippf *	ippf_create(FILE *);
struct ippf *	ippf_create_str(char const *);
void 		ippf_destroy(struct ippf *);
int		ippf_calc(struct ippf *, int, in_addr_t, int, in_addr_t, int);
__END_DECLS

#endif
