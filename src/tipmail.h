#ifndef _TIPMAIL_H
#define _TIPMAIL_H
  
#ifdef __TURBOC__
static
#endif
struct tipcb {
    struct tipcb *next;
    struct proc *proc;
    struct proc *in;
    struct iface *iface;
    struct timer timer;
    int (*rawsave) __ARGS((struct iface *,struct mbuf *));
    int s;
    int echo;
    int asy_dev;
    unsigned default_timeout;
    unsigned timeout;
    char firstwarn;
    char chk_modem_cd;
    char raw;
} *Tiplist;
#define NULLTIP (struct tipcb *)0
  
  
int tipstart __ARGS((int argc,char *argv[],void *p));
int tip0 __ARGS((int argc,char *argv[],void *p));
int telnet0 __ARGS((int argc,char *argv[],void *p));
int telnet1 __ARGS((int argc,char *argv[],void *p));
  
#endif /* _TIPMAIL_H */
