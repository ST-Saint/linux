#ifndef __NLKERN_H_
#define __NLKERN_H_

#include <linux/types.h>

extern int send_usrmsg(char *pbuf, uint16_t len);
extern int awid_netlink_register(void);
extern void awid_netlink_unregister(void);

#endif // __NLKERN_H_
