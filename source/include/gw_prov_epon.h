/** @file gw_prov_epon.h
 *  @brief This file defines the apis which are called
 *    by the gateway provisioning application during initialization.
 */
 
#ifndef _GW_GWPROV_EPON_H_
#define _GW_GWPROV_EPON_H_
	
#ifdef FEATURE_SUPPORT_RDKLOG
char *pComponentName = NULL;
#endif

typedef enum
{
    IpProvModeNone = 0,
    IpProvModeIpv4Only=1,
    IpProvModeIpv6Only=2,
    IpProvModeDualStack=3,
    IpProvModeHonor=4,
    IpProvModeIpv4DualStack=5,
    IpProvModeIpv6DualStack=6
} EPON_IpProvMode;

typedef enum
{
    EPON_OPER_NONE = 0,
    EPON_OPER_IPV6_UP,
    EPON_OPER_IPV6_DOWN,
    EPON_OPER_IPV4_UP,
    EPON_OPER_IPV4_DOWN
} EPON_IpProvStatus;

#endif
