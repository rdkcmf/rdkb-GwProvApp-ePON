/** @file gw_prov_epon.h
 *  @brief This file defines the apis which are called
 *    by the gateway provisioning application during initialization.
 */
 
#ifndef _GW_GWPROV_EPON_H_
#define _GW_GWPROV_EPON_H_
	

typedef enum
{
    IpProvModeNone = 0,
    IpProvModeIpv6Only,
    IpProvModeDualStack,
    IpProvModeHonor
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
