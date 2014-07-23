#ifndef _INP2011_H
#define	_INP2011_H

/* 01Sep2011, Maiko (VE4KLM), function prototypes - newinp.c module */

extern int inp_rif_recv (struct mbuf*, struct ax25_cb*);
extern int inp_l3rtt (char*);
extern int inp_l3rtt_recv (char*, struct ax25_cb*, struct mbuf*);

#endif	/* end of _INP2011_H */

