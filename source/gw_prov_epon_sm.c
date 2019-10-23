/* 
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/*#######################################################################
#   Copyright [2015] [ARRIS Corporation]
#
#   Licensed under the Apache License, Version 2.0 (the \"License\");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an \"AS IS\" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#######################################################################*/

#ifndef _GW_PROV_EPON_SM_C_
#define _GW_PROV_EPON_SM_C_

/*! \file gw_prov_epon_sm.c
    \brief gw epon provisioning
*/

/**************************************************************************/
/*      INCLUDES:                                                         */
/**************************************************************************/
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ruli.h>
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include <pthread.h>
#include "stdbool.h"
#include "gw_prov_epon.h"

/**************************************************************************/
/*      LOCAL VARIABLES:                                                  */
/**************************************************************************/
static int sysevent_fd;
static token_t sysevent_token;
static int sysevent_fd_gs;
static token_t sysevent_token_gs;
static pthread_t sysevent_tid;
static int erouter_reset_count;
static time_t xconfGetSettings_call_time = 0;

#define INFO  0
#define WARNING  1
#define ERROR 2

#ifdef FEATURE_SUPPORT_RDKLOG
#include "ccsp_trace.h"
const char compName[25]="LOG.RDK.GWPEPON";
#define DEBUG_INI_NAME  "/etc/debug.ini"
#define GWPROVEPONLOG(x, ...) { if((x)==(INFO)){CcspTraceInfo((__VA_ARGS__));}else if((x)==(WARNING)){CcspTraceWarning((__VA_ARGS__));}else if((x)==(ERROR)){CcspTraceError((__VA_ARGS__));} }
#else
#define GWPROVEPONLOG(x, ...) {fprintf(stderr, "GwProvEponLog<%s:%d> ", __FUNCTION__, __LINE__);fprintf(stderr, __VA_ARGS__);}
#endif

//Note: By Moving this headerfile inclusion to "INCLUDES:" block, may run into build issues
#include "mso_mgmt_hal.h"

#if 0
#define IF_WANBRIDGE "erouter0"
#endif

#define _DEBUG 1
#define THREAD_NAME_LEN 16 //length is restricted to 16 characters, including the terminating null byte

/**************************************************************************/
/*      LOCAL FUNCTIONS:                                                  */
/**************************************************************************/
static void GWPEpon_StartIPProvisioning();
static void GWPEpon_StopIPProvisioning();
static void GWPEpon_ProcessIPProvisioning(EPON_IpProvMode routerIpModeOverride, int update_db);
static void GWPEpon_ProcessXconfGwProvMode();
static void GWPEpon_ProcessLanWanReconnect();
static int GWPEpon_ProcessLanWanConnect(EPON_IpProvStatus status);
static int GWPEpon_ProcessIpv4Down(void);
static int GWPEpon_ProcessIpv6Down(void);
static void GWPEpon_ProcessIpv4Timeoffset();
static void GWPEpon_ProcessIpv6Timeoffset();
static void GWPEpon_SetWanTimeoffset(int time_offset);
static int GWPEpon_hexToInt(char s[]);
static int GWPEpon_SysCfgSetInt(const char *name, int int_value);
static int GWPEpon_SysCfgGetInt(const char *name);
static int GWPEpon_SysCfgGetStr(const char *name, unsigned char *out_value, int outbufsz);
static int GWPEpon_SysCfgSetStr(const char *name, unsigned char *str_value);

/**************************************************************************/
/*! \fn int SetProvisioningStatus();
 **************************************************************************
 *  \brief Set Epon Provisioing Status
 *  \return 0
**************************************************************************/
static void SetProvisioningStatus(EPON_IpProvStatus status)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__)

    const char * ip_status[] = { "None", "Ipv6", "NoIpv6", "Ipv4", "NoIpv4"};
    unsigned  char value[20];
    value[0] = '\0' ;

    int gw_prov_status = 0;
    gw_prov_status = GWPEpon_SyseventGetInt("gw_prov_status");

    if (gw_prov_status < 0)
		gw_prov_status = 0;
	
    switch(status)
    {
        case EPON_OPER_IPV6_UP:
            gw_prov_status |= 0x00000001;
        break;

        case EPON_OPER_IPV6_DOWN:
            gw_prov_status &= ~(0x00000001);
        break;

        case EPON_OPER_IPV4_UP:
            gw_prov_status |= 0x00000002;
        break;

        case EPON_OPER_IPV4_DOWN:
            gw_prov_status &= ~(0x00000002);
        break;

        case EPON_OPER_NONE:
            gw_prov_status = 0x00000000;
        break;

        default:
        break;
    }

    if (gw_prov_status & 0x00000001)
    {
        strcat(value, ip_status[EPON_OPER_IPV6_UP]);
    }
    else
    {
        strcat(value, ip_status[EPON_OPER_IPV6_DOWN]);
    }

    if (gw_prov_status & 0x00000002)
    {
        strcat(value, ip_status[EPON_OPER_IPV4_UP]);
    }
    else
    {
        strcat(value, ip_status[EPON_OPER_IPV4_DOWN]);
    }

    GWPEpon_SyseventSetInt("gw_prov_status",gw_prov_status);
    GWPROVEPONLOG(INFO, "gw_prov_status_str=%s\n",value)
    //TODO:To be added in EPON gateway provisiong data model
    GWPEpon_SyseventSetStr("gw_prov_status_str", value, sizeof(value));
    GWPEpon_SyseventSetStr("dhcp_server-restart", "1", sizeof("1"));

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__)
}

static void GWPEpon_StartIPv4Service()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    FILE *fp = NULL;

    if ((fp = fopen("/tmp/.start_ipv4", "r")) == NULL)
    {
        system("touch /tmp/.start_ipv4");
        system("systemctl restart udhcp.service");
    }
    else
       fclose(fp);	
		
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_StopIPv4Service()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    FILE *fp = NULL;

    if ((fp = fopen("/tmp/.start_ipv4", "r")) != NULL)
    {
        if(fp)
           fclose(fp);
		
        system("rm /tmp/.start_ipv4"); 
        system("systemctl stop udhcp.service");
        GWPEpon_ProcessIpv4Down();
    }
		
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_StartIPv6Service()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    FILE *fp = NULL;

    if ((fp = fopen("/tmp/.start_ipv6", "r")) == NULL)
    {
        system("touch /tmp/.start_ipv6");
        system("systemctl restart dibbler.service");
    }
    else
       fclose(fp);	
		
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_StopIPv6Service()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    FILE *fp = NULL;

    if ((fp = fopen("/tmp/.start_ipv6", "r")) != NULL)
    {
        if(fp)
           fclose(fp);
		
        system("rm /tmp/.start_ipv6"); 
        system("systemctl stop dibbler.service");
        GWPEpon_ProcessIpv6Down();
    }
		
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

EPON_IpProvMode GWPEpon_GetRouterIpMode()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__)
		
    unsigned char router_ip_mode[20];
    int outbufsz = sizeof(router_ip_mode);
    EPON_IpProvMode mode=IpProvModeHonor;

    router_ip_mode[0]='\0';
    GWPEpon_SysCfgGetStr("router_ip_mode_override", router_ip_mode, outbufsz);
    GWPROVEPONLOG(INFO, "router_ip_mode_override :%s\n", router_ip_mode);
    if (strcmp (router_ip_mode, "Honor") == 0)
    {
        mode=IpProvModeHonor;
    }	
    if (strcmp (router_ip_mode, "Dual Stack") == 0)
    {
        mode=IpProvModeDualStack;
    }
    if (strcmp (router_ip_mode, "IPv6 only") == 0)
    {
        mode=IpProvModeIpv6Only;
    }
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
		
    return mode;
}

static int GWPEpon_XconfGetSettings(void)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    unsigned char out_value[20];
    int outbufsz = sizeof(out_value);
    out_value[0] = '\0';

    // Make sure we don't call /usr/ccsp/xf3_xconfGetSettings.sh back to back which can cause some
    // synchronization issues
    if (xconfGetSettings_call_time != 0 && time(NULL) < (xconfGetSettings_call_time + 10))
    {
        GWPROVEPONLOG(INFO, "%s Not getting xconf configuration parameter due to another running\n",__FUNCTION__);
    }
    else
    {
        int retval = GWPEpon_SyseventGetStr("xconf_gs_status", out_value,outbufsz);
        if(retval < 0)
        {
            GWPROVEPONLOG(INFO, "%s Getting xconf configuration parameter\n",__FUNCTION__);
            system("sh /usr/ccsp/xf3_xconfGetSettings.sh &");
            xconfGetSettings_call_time = time(NULL);
        }
        else
        {
            GWPROVEPONLOG(INFO, "%s xconf_gs_status=%s\n",__FUNCTION__,out_value);
        }
    }
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

/**************************************************************************/
/*! \fn int GWPEpon_ProcessIfDown();
 **************************************************************************
 *  \brief If Down - Exit
 *  \return 0
**************************************************************************/
static int GWPEpon_ProcessIfDown(void)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    GWPEpon_StopIPProvisioning();

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

/**************************************************************************/
/*! \fn int GWPEpon_ProcessIfUp
 **************************************************************************
 *  \brief If up
 *  \return 0
**************************************************************************/
static int GWPEpon_ProcessIfUp(void)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    GWPEpon_StartIPProvisioning();

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

/**************************************************************************/
/*! \fn int GWPEpon_ProcessIpv4Down();
 **************************************************************************
 *  \brief IPv4 WAN Side Routing - Exit
 *  \return 0
**************************************************************************/
static int GWPEpon_ProcessIpv4Down(void)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    SetProvisioningStatus(EPON_OPER_IPV4_DOWN);
    GWPEpon_ProcessLanWanConnect(EPON_OPER_IPV4_DOWN);	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

/**************************************************************************/
/*! \fn int GWPEpon_ProcessIpv4Up
 **************************************************************************
 *  \brief IPv4 WAN Side Routing
 *  \return 0
**************************************************************************/
static int GWPEpon_ProcessIpv4Up(void)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    SetProvisioningStatus(EPON_OPER_IPV4_UP);
    GWPEpon_ProcessLanWanConnect(EPON_OPER_IPV4_UP);	
    GWPEpon_XconfGetSettings();
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

/**************************************************************************/
/*! \fn int GWPEpon_ProcessIpV6Down()
 **************************************************************************
 *  \brief IPv6 WAN Side Routing - Exit
 *  \return 0
**************************************************************************/
static int GWPEpon_ProcessIpv6Down(void)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    SetProvisioningStatus(EPON_OPER_IPV6_DOWN);
    GWPEpon_ProcessLanWanConnect(EPON_OPER_IPV6_DOWN);	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

/**************************************************************************/
/*! \fn int GWPEpon_ProcessIpV6Up()
 **************************************************************************
 *  \brief IPv6 WAN Side Routing
 *  \return 0
**************************************************************************/
static int GWPEpon_ProcessIpv6Up(void)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    SetProvisioningStatus(EPON_OPER_IPV6_UP);
    GWPEpon_ProcessLanWanConnect(EPON_OPER_IPV6_UP);		
    GWPEpon_XconfGetSettings();
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int IsValidIpPrefMode(EPON_IpProvMode mode)
{
    int retval = 0;
    if (mode != IpProvModeNone) 
    {
        if ((mode == IpProvModeIpv6Only) || (mode == IpProvModeDualStack) || 
            (mode == IpProvModeIpv4DualStack) || (mode == IpProvModeIpv6DualStack))
        {
            retval = 1;
        }
    }

    return retval;	
}

static int GWPEpon_ProcessWANIpPref()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    EPON_IpProvMode curRouterIpMode = (EPON_IpProvMode) GWPEpon_SyseventGetInt("cur_router_ip_mode");

    if (curRouterIpMode == IpProvModeHonor)
    {    	
        int val = 0;
        EPON_IpProvMode wan6_ippref = IpProvModeNone;
        EPON_IpProvMode wan4_ippref = IpProvModeNone;
        EPON_IpProvMode routerIpMode = IpProvModeNone;
    
        val = GWPEpon_SyseventGetInt("wan6_ippref");
        if (val > 0)
            wan6_ippref = (EPON_IpProvMode) val;
		
        GWPROVEPONLOG(INFO, "wan6_ippref=%d\n",wan6_ippref);
		
        val = GWPEpon_SyseventGetInt("wan4_ippref");
        if (val > 0)
            wan4_ippref = (EPON_IpProvMode) val;
		
        GWPROVEPONLOG(INFO, "wan4_ippref=%d\n",wan4_ippref);

        if(IsValidIpPrefMode(wan4_ippref))
            routerIpMode = wan4_ippref;
		
        if(IsValidIpPrefMode(wan6_ippref))
            routerIpMode = wan6_ippref;
	
        GWPROVEPONLOG(INFO, "ippref routerIpMode=%d\n",routerIpMode);

        if (routerIpMode != IpProvModeNone)
            GWPEpon_ProcessIPProvisioning(routerIpMode, 0);
    }
    else
    {
        GWPROVEPONLOG(INFO, "curRouterIpMode=%d, Ignoring iprpef ...\n",curRouterIpMode);
    }
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int GWPEpon_ProcessLanWanConnect(EPON_IpProvStatus status)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    unsigned char out_val[20];
    int outbufsz = sizeof(out_val);		
    int factory_mode = GWPEpon_SysCfgGetInt("factory_mode");

    if(factory_mode)
        GWPEpon_SysCfgGetStr("gw_prov_mode", out_val, outbufsz);
    else
        GWPEpon_SyseventGetStr("cur_gw_prov_mode", out_val, outbufsz);
	
    if (!factory_mode && (strcmp(out_val, "provisioned") == 0))
    {       
        int ipv6_lan_wan_connect = GWPEpon_SyseventGetInt("ipv6_lan_wan_connect");
        if (ipv6_lan_wan_connect < 0)
            ipv6_lan_wan_connect=0;
     
        int ipv4_lan_wan_connect = GWPEpon_SyseventGetInt("ipv4_lan_wan_connect");
        if (ipv4_lan_wan_connect < 0)
            ipv4_lan_wan_connect=0;
     
        switch(status)
        {
            case EPON_OPER_IPV6_UP:
            GWPROVEPONLOG(INFO, "processing IPv6 LanWanConnect\n");	
                //if(!ipv6_lan_wan_connect)
                    system("sh /usr/ccsp/lan_handler.sh ipv6_lan_wan_connect");
     			
            break;
         
            case EPON_OPER_IPV6_DOWN:        			

                GWPROVEPONLOG(INFO, "processing IPv6 LanWanDisconnect\n");	
                //if(ipv6_lan_wan_connect)
                    system("sh /usr/ccsp/lan_handler.sh ipv6_lan_wan_disconnect");
     			
            break;
         
            case EPON_OPER_IPV4_UP:
     
     	      GWPROVEPONLOG(INFO, "processing IPv4 LanWanConnect\n");	
                //if(!ipv4_lan_wan_connect)
                    system("sh /usr/ccsp/lan_handler.sh ipv4_lan_wan_connect");
     
            break;
     
            case EPON_OPER_IPV4_DOWN:
     
     	      GWPROVEPONLOG(INFO, "processing IPv4 LanWanDisconnect\n");	
                //if(ipv4_lan_wan_connect)
                    system("sh /usr/ccsp/lan_handler.sh ipv4_lan_wan_disconnect");
     
            break;
         
            default:
            break;
         }
    }
    else
    {
       GWPROVEPONLOG(WARNING,"Refusing to allow LAN ACCESS to WAN on gw_prov_mode:%s factory_mode:%d\n",out_val,factory_mode);
    }
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int GWPEpon_ProcessDHCPStart()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
		
    system("sh /usr/ccsp/lan_handler.sh dhcp_restart"); 
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int GWPEpon_ProcessEthEnable()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
		
    system("sh /usr/ccsp/lan_handler.sh eth_enable");
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int GWPEpon_ProcessEthDisable()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
		
    system("sh /usr/ccsp/lan_handler.sh eth_disable");
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int GWPEpon_ProcessLanEth0ToXHS()
{

	GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    system("sh /usr/ccsp/lan_handler.sh eth3_to_xhs");
	GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
	return 0;
}
static int GWPEpon_ProcessLanEth0ToLocalNetwork()
{

	GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    system("sh /usr/ccsp/lan_handler.sh eth3_to_local");
	GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
	return 0;
}
static int GWPEpon_ProcessPNM_Status()
{
	FILE *fp;
	char buffer[512]={0};
	char *str = NULL;
	GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    system("sh /usr/ccsp/lan_handler.sh init");
    system("dmcli eRT getv Device.Bridging.Bridge.2.Port.2.Enable >> /tmp/XHSport.txt");//XHS port true or false?
	fp = fopen("/tmp/XHSport.txt","r");
    if (fp != NULL)
    {
       fread(buffer,512,1,fp);
       fclose(fp);
       str = strstr(buffer,"value");
       if (str != NULL)
       {
    	   if( str[7] == 't') // true
    	   {
    		   GWPEpon_SyseventSetStr("multinet-syncMembers","2", 0);
    	   }
       }
    }
	GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
	return 0;
}

static int GWPEpon_ProcessMoCAEnable()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
		
    system("sh /usr/ccsp/lan_handler.sh moca_enable");
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int GWPEpon_ProcessMoCADisable()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
		
    system("sh /usr/ccsp/lan_handler.sh moca_disable");
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int GWPEpon_ProcessWlEnable()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
		
    system("sh /usr/ccsp/lan_handler.sh wl_enable");
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int GWPEpon_ProcessWlDisable()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
		
    system("sh /usr/ccsp/lan_handler.sh wl_disable");
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}


static int GWPEpon_ProcessXconfRouterIpMode()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    int factory_mode = GWPEpon_SysCfgGetInt("factory_mode");
    if (factory_mode)
    {
        EPON_IpProvMode routerIpModeOverride = GWPEpon_GetRouterIpMode();
        EPON_IpProvMode curRouterIpMode = (EPON_IpProvMode) GWPEpon_SyseventGetInt("cur_router_ip_mode");

        if(routerIpModeOverride != curRouterIpMode) {
            GWPEpon_ProcessIPProvisioning(routerIpModeOverride, 1);
        }
        GWPEpon_SysCfgSetInt("factory_mode", 0);
        GWPEpon_ProcessLanWanReconnect();
    }
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

#define RETURN_OK   0
static int GWPEpon_ProcessXconfPoDSeed()
{
    unsigned char out_val[45];
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    GWPEpon_SysCfgGetStr("pod_seed", out_val, sizeof(out_val));
    if ( mso_set_pod_seed(out_val) == RETURN_OK )
    {
        GWPEpon_SysCfgSetStr("pod_seed","");
    }
    xconfGetSettings_call_time = 0;
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static int GWPEpon_ProcessXconfDstAdj()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    GWPEpon_ProcessIpv4Timeoffset();
    GWPEpon_ProcessIpv6Timeoffset();
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return 0;
}

static void GWPEpon_ProcessLanWanReconnect()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
	
    int gw_prov_status = 0;
    gw_prov_status = GWPEpon_SyseventGetInt("gw_prov_status");
	
    if (gw_prov_status & 0x00000001)
        GWPEpon_ProcessLanWanConnect(EPON_OPER_IPV6_UP);
    else
        GWPEpon_ProcessLanWanConnect(EPON_OPER_IPV6_DOWN);

    if (gw_prov_status & 0x00000002)
        GWPEpon_ProcessLanWanConnect(EPON_OPER_IPV4_UP);
    else
        GWPEpon_ProcessLanWanConnect(EPON_OPER_IPV4_DOWN);
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessXconfGwProvMode()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    unsigned char out_val[20];
    int factory_mode = GWPEpon_SysCfgGetInt("factory_mode");

    if(factory_mode)
    {
        GWPEpon_SysCfgGetStr("gw_prov_mode", out_val, sizeof(out_val));
        GWPEpon_SyseventSetStr("cur_gw_prov_mode", out_val, 0);
    }	
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessBridgeModeEnable()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    system("sh /usr/ccsp/lan_handler.sh bridge_mode_enable");
    system("systemctl restart dibbler.service");
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessBridgeModeDisable()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    system("sh /usr/ccsp/lan_handler.sh bridge_mode_disable");
    system("systemctl restart dibbler.service");
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessFirewallRestart()
{
GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
   system("sh /usr/ccsp/lan_handler.sh firewall_restart");
GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessGreRestart(char * val)
{
   char cmd[512];
GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
   sprintf(cmd, "sh /etc/utopia/service.d/service_xfinity_hotspot.sh xfinity-hotspot-restart");
   system(cmd);
GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessTSIP(char *name, char *val)
{
    char cmd[512];
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    sprintf(cmd, "sh /etc/utopia/service.d/service_ipv4.sh %s %s", name, val);
    system(cmd);

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessRIPD(char *name, char *val)
{
    char cmd[512];
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    sprintf(cmd, "sh /etc/utopia/service.d/service_routed.sh %s %s", name, val);
    system(cmd);

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessIpv6Timezone()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessIpv4Timezone()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    unsigned char timezone_hex[30], timezone_ascii[30];
    int vallen = sizeof(timezone_hex);
    unsigned int ch;
    int i, j;
    timezone_hex[0]='\0';
    if ((GWPEpon_SyseventGetStr("ipv6-timeoffset", timezone_hex, vallen) < 0) && 
                     (GWPEpon_SyseventGetStr("ipv6_timezone", timezone_hex, vallen) < 0))
    {
       timezone_hex[0]='\0';
       if (GWPEpon_SyseventGetStr("ipv4_timezone", timezone_hex, vallen) < 0) {
           GWPROVEPONLOG(INFO, "Timezone does not exists\n");
           strcpy(timezone_ascii, "UTC");
       }
       else {
           for(i=0, j=0; sscanf((const char*)&timezone_hex[i], "%2x", &ch) == 1; i += 2)
           {
               timezone_ascii[j++] = ch; 
           }
           timezone_ascii[j] = 0;
       }
       unsigned char cmdLine[50];
       sprintf(cmdLine, "timedatectl set-timezone UTC");    /* no offset */
       system(cmdLine);
    }
    else
    {
        GWPROVEPONLOG(INFO, "Ignore ipv4-timezone as ipv6-timezone or ipv6-timeoffset  exists\n");
    }

    memset(timezone_hex, 0, vallen);
    GWPEpon_SyseventGetStr("ipv4_timezone", timezone_hex, vallen-1);
    if ( timezone_hex[0] )
    {
       unsigned char cmdLine[256];
       sprintf(cmdLine, "dmcli eRT setv Device.Time.LocalTimeZone string %s", timezone_hex);
       system(cmdLine);
    }
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessIpv4Timeoffset()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    int ipv4_time_offset;
    unsigned char value[20];
    int vallen = sizeof(value);
    value[0]='\0';
		
    if (GWPEpon_SyseventGetStr("ipv4_timezone", value, vallen) < 0)
    {
        value[0]='\0';
        if ((GWPEpon_SyseventGetStr("ipv6-timeoffset", value, vallen) < 0) && 
                     (GWPEpon_SyseventGetStr("ipv6_timezone", value, vallen) < 0))
        {
            GWPROVEPONLOG(INFO, "Apply ipv4-timeoffset\n");
    
            value[0]='\0';
            if (GWPEpon_SyseventGetStr("ipv4-timeoffset", value, vallen) < 0)
            {
                GWPROVEPONLOG(WARNING, "ipv4-timeoffset does not exists\n");
            }
            else
            {
                ipv4_time_offset = atoi(value + 1); //Ignore 1st char "@" (e.g. "@-18000")
                GWPEpon_SetWanTimeoffset(ipv4_time_offset);  
            }
        }
        else 
        {
            GWPROVEPONLOG(INFO, "Ignore ipv4-timeoffset as ipv6_timezone/ipv6-timeoffset already applied\n");
        } 
    }
    else
    {
        GWPROVEPONLOG(INFO, "Ignore ipv4-timeoffset as ipv4-timezone exists\n");
    }

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessIpv6Timeoffset()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    int ipv6_time_offset;
    unsigned char value[20];
    int vallen = sizeof(value);	
    value[0]='\0';

    if (GWPEpon_SyseventGetStr("ipv6_timezone", value, vallen) < 0)
    {
        value[0]='\0';
        GWPROVEPONLOG(INFO, "ipv6_timezone does not exists\n");   
        if (GWPEpon_SyseventGetStr("ipv6-timeoffset", value, vallen) < 0)
        {
            GWPROVEPONLOG(WARNING, "ipv6-timeoffset does not exists\n");
        }
        else 
        {
            ipv6_time_offset = GWPEpon_hexToInt(value); 
            GWPROVEPONLOG(INFO, "Apply ipv6-timeoffset\n");   
            GWPEpon_SetWanTimeoffset(ipv6_time_offset);
        }
    }
    else
        GWPROVEPONLOG(INFO, "Ignore ipv6-timeoffset as ipv6-timezone exists\n");

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}


static void GWPEpon_ProcessLanRestart()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    system("sh /usr/ccsp/lan_handler.sh lan_restart");
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessLanStop()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    system("sh /usr/ccsp/lan_handler.sh lan_stop");
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessLanStatus()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    system("sh /usr/ccsp/lan_handler.sh lan_status");
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessForwardingRestart()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    system("sh /usr/ccsp/lan_handler.sh forwarding_restart");
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_SetWanTimeoffset(int time_offset)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
    char timezone[20];
    char dstValue[5];
    GWPEpon_SysCfgGetStr("dst_adj", dstValue, sizeof(dstValue));
    if (strcmp(dstValue, "On") == 0) 
    {
        GWPROVEPONLOG(INFO, "Applying timeoffset with DST:On\n");
        time_offset += 3600; //DST adjustment
        switch(time_offset) 
        {
            case -14400:
                strcpy(timezone, "EST5EDT");
            break;
            case -18000:
                strcpy(timezone, "CST6CDT");
            break;
            case -21600:
                strcpy(timezone, "MST7MDT");
            break;
            case -25200:
                strcpy(timezone, "PST8PDT");
            break;
            case -32400:
                strcpy(timezone, "HST");
            break;
            default:
                GWPROVEPONLOG(WARNING, "Invalid timezone, setting time zone to UTC\n");
                strcpy(timezone, "UTC");
            break;
        }
    }
    else 
    {
        GWPROVEPONLOG(INFO, "Applying timeoffset with DST:Off\n");
        switch(time_offset) 
        {
            case -18000:
                strcpy(timezone, "EST5EDT");
            break;
            case -21600:
                strcpy(timezone, "CST6CDT");
            break;
            case -25200:
                strcpy(timezone, "MST7MDT");
            break;
            case -28800:
                strcpy(timezone, "PST8PDT");
            break;
            case -36000:
                strcpy(timezone, "HST");
            break;
            default:
                GWPROVEPONLOG(WARNING, "Invalid timezone, setting time zone to UTC\n");
                strcpy(timezone, "UTC");
            break;
        }
    }
    GWPEpon_SyseventSetStr("ipv4_timezone", timezone, 0);
    unsigned char cmdLine[256];
    sprintf(cmdLine, "dmcli eRT setv Device.Time.LocalTimeZone string %s", timezone);
    system(cmdLine);
    sprintf(cmdLine, "timedatectl set-timezone UTC");    /* no offset */
    system(cmdLine);
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static int GWPEpon_hexToInt(char s[])
{
    int hexdigit, i, num;
    bool inputIsValid;
    i=0;

    if(s[i] == '0') {
        ++i;
        if(s[i] == 'x' || s[i] == 'X'){
            ++i;
        }
    }

    num = 0;
    inputIsValid = true;
    for(; inputIsValid == true; ++i) {
        if(s[i] >= '0' && s[i] <= '9') {
            hexdigit = s[i] - '0';
        } else if(s[i] >= 'a' && s[i] <= 'f') {
            hexdigit = s[i] - 'a' + 10;
        } else if(s[i] >= 'A' && s[i] <= 'F') {
            hexdigit = s[i] - 'A' + 10;
        } else {
            inputIsValid = false;
        }

        if(inputIsValid == true) {
            num = 16 * num + hexdigit;
        }
    }

    return num;
}

/**************************************************************************/
/*! \fn static STATUS GWPEpon_SyseventGetInt
 **************************************************************************
 *  \brief Get sysevent Integer Value
 *  \return int/-1
 **************************************************************************/
int GWPEpon_SyseventGetInt(const char *name)
{
   unsigned char out_value[20];
   int outbufsz = sizeof(out_value);

   sysevent_get(sysevent_fd_gs, sysevent_token_gs, name, out_value,outbufsz);
   if(out_value[0] != '\0')
   {
      return atoi(out_value);
   }
   else
   {
      GWPROVEPONLOG(INFO, "sysevent_get failed\n")
      return -1;
   }
}

/**************************************************************************/
/*! \fn static STATUS GWPEpon_SyseventSetInt
 **************************************************************************
 *  \brief Set sysevent Integer Value
 *  \return 0:success, <0: failure
 **************************************************************************/
int GWPEpon_SyseventSetInt(const char *name, int int_value)
{
   unsigned char value[20];
   sprintf(value, "%d", int_value);

   return sysevent_set(sysevent_fd_gs, sysevent_token_gs, name, value, sizeof(value));
}

int GWPEpon_SyseventGetStr(const char *name, unsigned char *out_value, int outbufsz)
{
    sysevent_get(sysevent_fd_gs, sysevent_token_gs, name, out_value, outbufsz);
    if(out_value[0] != '\0')
        return 0;		
    else
        return -1;		
}

int GWPEpon_SyseventSetStr(const char *name, unsigned char *value, int bufsz)
{
    return sysevent_set(sysevent_fd_gs, sysevent_token_gs, name, value, bufsz);
}


/**************************************************************************/
/*! \fn static STATUS GWP_SysCfgGetInt
 **************************************************************************
 *  \brief Get Syscfg Integer Value
 *  \return int/-1
 **************************************************************************/
static int GWPEpon_SysCfgGetInt(const char *name)
{
   unsigned char out_value[20];
   int outbufsz = sizeof(out_value);

   if (!syscfg_get(NULL, name, out_value, outbufsz))
   {
      return atoi(out_value);
   }
   else
   {
      GWPROVEPONLOG(INFO, "syscfg_get failed\n")
      return -1;
   }
}

/**************************************************************************/
/*! \fn static STATUS GWP_SysCfgSetInt
 **************************************************************************
 *  \brief Set Syscfg Integer Value
 *  \return 0:success, <0: failure
 **************************************************************************/
static int GWPEpon_SysCfgSetInt(const char *name, int int_value)
{
   unsigned char value[20];
   int retval=0;
   sprintf(value, "%d", int_value);
   retval = syscfg_set(NULL, name, value);
   syscfg_commit();

   return retval;
}

static int GWPEpon_SysCfgGetStr(const char *name, unsigned char *out_value, int outbufsz)
{
   return syscfg_get(NULL, name, out_value, outbufsz);
}

static int GWPEpon_SysCfgSetStr(const char *name, unsigned char *str_value)
{
   return syscfg_set(NULL, name, str_value);
}

/**************************************************************************/
/*! \fn static void GWPEpon_StopIPProvisioning
 **************************************************************************
 *  \brief Stop EPON IP Provisioning
 *  \return 0
 **************************************************************************/
static void GWPEpon_StopIPProvisioning()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);
	
    GWPEpon_StopIPv4Service();
    GWPEpon_StopIPv6Service();

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

/**************************************************************************/
/*! \fn static void GWPEpon_StartIPProvisioning
 **************************************************************************
 *  \brief Start EPON IP Provisioning
 *  \return 0
 **************************************************************************/
static void GWPEpon_StartIPProvisioning()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    int factory_mode = GWPEpon_SysCfgGetInt("factory_mode");
    EPON_IpProvMode routerIpModeOverride = IpProvModeHonor;
	
    if (factory_mode) //First IP Initialization (Factory reset or Factory unit)
    {  
        GWPROVEPONLOG(INFO, "In factory mode IP Initialization\n");
        routerIpModeOverride = IpProvModeHonor;
    }
    else
    {
        GWPROVEPONLOG(INFO, "In Subsequent IP Initialization\n");
        routerIpModeOverride = GWPEpon_GetRouterIpMode();
    }

    unsigned char out_val[20];
    GWPEpon_SysCfgGetStr("gw_prov_mode", out_val, sizeof(out_val));
    GWPEpon_SyseventSetStr("cur_gw_prov_mode", out_val, 0);

    GWPEpon_ProcessIPProvisioning(routerIpModeOverride, 1);
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
}

static void GWPEpon_ProcessIPProvisioning(EPON_IpProvMode routerIpMode, int update_db)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__);

    if(update_db)	
        GWPEpon_SyseventSetInt("cur_router_ip_mode", (int) routerIpMode);	
	
    GWPROVEPONLOG(INFO, "routerIpMode=%d\n", routerIpMode);

    if (routerIpMode == IpProvModeIpv6Only)
    {
        GWPEpon_StartIPv6Service();
        GWPEpon_StopIPv4Service();		
    }
    else if( (routerIpMode == IpProvModeDualStack) || (routerIpMode == IpProvModeIpv4DualStack) || (routerIpMode == IpProvModeIpv6DualStack))
    {
        GWPEpon_StartIPv6Service();
        GWPEpon_StartIPv4Service();
    }
    else if(routerIpMode == IpProvModeHonor)
    {
        GWPEpon_StartIPv6Service();
        GWPEpon_StartIPv4Service();
    }
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__)
}

/**************************************************************************/
/*! \fn void *GWPEpon_sysevent_handler(void *data)
 **************************************************************************
 *  \brief Function to process sysevent event
 *  \return 0
**************************************************************************/
static void *GWPEpon_sysevent_handler(void *data)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__)

    async_id_t epon_ifstatus_asyncid;
    async_id_t ipv4_status_asyncid;
    async_id_t ipv6_status_asyncid;
    async_id_t wan4_ippref_asyncid;
    async_id_t wan6_ippref_asyncid;
    async_id_t ipv6_ippref_asyncid;
    async_id_t ipv4_timeoffset_asyncid;
    async_id_t ipv6_timeoffset_asyncid;	
    async_id_t lan_restart_connect_asyncid;
    async_id_t dhcp_server_status_asyncid;
    async_id_t eth_status_asyncid;
    async_id_t moca_status_asyncid;
    async_id_t wl_status_asyncid;
    async_id_t xconf_router_ip_mode_asyncid;
    async_id_t xconf_pod_seed_asyncid;
    async_id_t xconf_dst_adj_asyncid;
    async_id_t xconf_gw_prov_mode_asyncid;
    async_id_t bridge_mode_asyncid;
    async_id_t firewall_restart_asyncid;
    async_id_t ipv4_timezone_asyncid;
    async_id_t ipv6_timezone_asyncid;
    async_id_t lan_restart_asyncid;
    async_id_t lan_stop_asyncid;
    async_id_t lan_status_asyncid;
    async_id_t forwarding_restart_asyncid;
    async_id_t dhcpv6_server_asyncid;
    async_id_t pnm_status_asyncid;
    async_id_t multinet_syncMembers_asyncid;
    async_id_t gre_restart_asyncid;
    async_id_t gre_forceRestart_asyncid;

    /* TSIP event ids */
    async_id_t tsip_sync_asyncid;
    async_id_t tsip_stop_asyncid;
    async_id_t tsip_resync_asyncid;
    async_id_t tsip_resync_asn_asyncid;

    /* RIPD/Zebra event ids */
    async_id_t wan_status_asyncid;
    async_id_t dhcpv6_option_changed_asyncid;
    async_id_t ripd_restart_asyncid;
    async_id_t zebra_restart_asyncid;
    async_id_t staticroute_restart_asyncid;

    static unsigned char firstBoot=1;

    sysevent_set_options(sysevent_fd, sysevent_token, "epon_ifstatus", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "epon_ifstatus", &epon_ifstatus_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "ipv4-status", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv4-status",  &ipv4_status_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "wan4_ippref", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "wan4_ippref",  &wan4_ippref_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "ipv4-timeoffset", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv4-timeoffset",  &ipv4_timeoffset_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "ipv6-status", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv6-status",  &ipv6_status_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "wan6_ippref", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "wan6_ippref",  &wan6_ippref_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "ipv6-timeoffset", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv6-timeoffset",  &ipv6_timeoffset_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "dhcp_server-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "dhcp_server-restart",  &dhcp_server_status_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "eth_enabled", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "eth_enabled",  &eth_status_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "moca_enabled", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "moca_enabled",  &moca_status_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "wl_enabled", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "wl_enabled",  &wl_status_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "xconf_router_ip_mode", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "xconf_router_ip_mode",  &xconf_router_ip_mode_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "xconf_pod_seed", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "xconf_pod_seed",  &xconf_pod_seed_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "xconf_dst_adj", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "xconf_dst_adj",  &xconf_dst_adj_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "xconf_gw_prov_mode", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "xconf_gw_prov_mode",  &xconf_gw_prov_mode_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "bridge_mode", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "bridge_mode",  &bridge_mode_asyncid);

    sysevent_set_options(sysevent_fd_gs, sysevent_token, "gw_prov_status", TUPLE_FLAG_EVENT);
    sysevent_set_options(sysevent_fd_gs, sysevent_token, "gw_prov_status_str", TUPLE_FLAG_EVENT);
    sysevent_set_options(sysevent_fd_gs, sysevent_token, "cur_gw_prov_mode", TUPLE_FLAG_EVENT);
    sysevent_set_options(sysevent_fd_gs, sysevent_token, "cur_router_ip_mode", TUPLE_FLAG_EVENT);
	
    sysevent_set_options(sysevent_fd, sysevent_token, "firewall-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "firewall-restart",  &firewall_restart_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "ipv4_timezone", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv4_timezone",  &ipv4_timezone_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "ipv6_timezone", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv6_timezone",  &ipv6_timezone_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "lan-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "lan-restart",  &lan_restart_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "lan-stop", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "lan-stop",  &lan_stop_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "lan-status", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "lan-status",  &lan_status_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "forwarding-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "forwarding-restart",  &forwarding_restart_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "dhcpv6s_server", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "dhcpv6s_server",  &dhcpv6_server_asyncid);

    //sysevent_set_options(sysevent_fd, sysevent_token, "pnm-status", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "pnm-status",&pnm_status_asyncid);

    sysevent_set_options(sysevent_fd, sysevent_token, "multinet-syncMembers", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "multinet-syncMembers",  &multinet_syncMembers_asyncid);
    
    sysevent_set_options(sysevent_fd, sysevent_token, "gre-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "gre-restart",  &gre_restart_asyncid);
    
    sysevent_set_options(sysevent_fd, sysevent_token, "gre-forceRestart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "gre-forceRestart",  &gre_forceRestart_asyncid);

    /* True Static IP events */
    sysevent_set_options    (sysevent_fd, sysevent_token, "ipv4-sync_tsip_all", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv4-sync_tsip_all",  &tsip_sync_asyncid);
    sysevent_set_options    (sysevent_fd, sysevent_token, "ipv4-stop_tsip_all", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv4-stop_tsip_all",  &tsip_stop_asyncid);
    sysevent_set_options    (sysevent_fd, sysevent_token, "ipv4-resync_tsip", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv4-resync_tsip",  &tsip_resync_asyncid);
    sysevent_set_options    (sysevent_fd, sysevent_token, "ipv4-resync_tsip_asn", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv4-resync_tsip_asn",  &tsip_resync_asn_asyncid);

    /* Route events to start ripd and zebra */
    sysevent_set_options    (sysevent_fd, sysevent_token, "lan-status", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "lan-status",  &lan_status_asyncid);
    sysevent_set_options    (sysevent_fd, sysevent_token, "wan-status", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "wan-status",  &wan_status_asyncid);
    sysevent_set_options    (sysevent_fd, sysevent_token, "dhcpv6_option_changed", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "dhcpv6_option_changed",  &dhcpv6_option_changed_asyncid);
    sysevent_set_options    (sysevent_fd, sysevent_token, "ripd-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ripd-restart",  &ripd_restart_asyncid);
    sysevent_set_options    (sysevent_fd, sysevent_token, "zebra-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "zebra-restart",  &zebra_restart_asyncid);
    sysevent_set_options    (sysevent_fd, sysevent_token, "staticroute-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "staticroute-restart",  &staticroute_restart_asyncid);

   for (;;)
   {
        unsigned char name[25], val[42];
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
        async_id_t getnotification_asyncid;

        if (firstBoot)
        {
           /* In case we missed an event notification before the thread starts */
           strcpy(name,"epon_ifstatus");
           err = GWPEpon_SyseventGetStr(name, val, vallen);
           firstBoot = 0;

           if (strcmp(val, "down")==0)
	 	continue;
        }
        else
           err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_asyncid);

        if (err)
        {
           GWPROVEPONLOG(ERROR, "sysevent_getnotification failed with error: %d\n", err)
        }
        else
        {
            GWPROVEPONLOG(WARNING, "received notification event %s\n", name)

            if (strcmp(name, "epon_ifstatus")==0)
            {
                if (strcmp(val, "up")==0)
                {
                    GWPEpon_ProcessIfUp();

                    erouter_reset_count += 1;
                    GWPEpon_SyseventSetInt("erouter_reset_count", erouter_reset_count);
                    GWPROVEPONLOG(INFO, "erouter_reset_count=%d\n",erouter_reset_count)
                }
                else if (strcmp(val, "down")==0)
                {
                    GWPEpon_ProcessIfDown();
		    GWPEpon_SyseventSetStr("wan-status", "stopped", sizeof("stopped"));      //XF3-5230
                }
            }
            else if (strcmp(name, "ipv4-status")==0)
            {
                if (strcmp(val, "up")==0)
                {
                    GWPEpon_ProcessIpv4Up();
                }
                else if (strcmp(val, "down")==0)
                {
                    GWPEpon_ProcessIpv4Down();
                }
            }
            else if (strcmp(name, "ipv6-status")==0)
            {
                if (strcmp(val, "up")==0)
                {
                    GWPEpon_ProcessIpv6Up();
                }
                else
                {
                    GWPEpon_ProcessIpv6Down();
                }
            }
            else if (strcmp(name, "wan4_ippref")==0)
            {
                GWPEpon_ProcessWANIpPref();            
            }
            else if (strcmp(name, "wan6_ippref")==0)
            {
                GWPEpon_ProcessWANIpPref();           
            }		
            else if (strcmp(name, "ipv4-timeoffset")==0)
            {
                GWPEpon_ProcessIpv4Timeoffset();
            }
            else if (strcmp(name, "ipv6-timeoffset")==0)
            {
                GWPEpon_ProcessIpv6Timeoffset();
            }
            else if ( (strcmp(name, "dhcp_server-restart")==0) || (strcmp(name, "dhcpv6s_server")==0) )
            {
                GWPEpon_ProcessDHCPStart();
            }
           else if (strcmp(name, "eth_enabled")==0)
            {
                if (strcmp(val, "1")==0)
                {
                    GWPEpon_ProcessEthEnable();
                }
                else if (strcmp(val, "0")==0)
                {
                    GWPEpon_ProcessEthDisable();
                }
            }
            else if (strcmp(name, "moca_enabled")==0)
            {
                if (strcmp(val, "1")==0)
                {
                    GWPEpon_ProcessMoCAEnable();
                }
                else if (strcmp(val, "0")==0)
                {
                    GWPEpon_ProcessMoCADisable();
                }
            }
            else if (strcmp(name, "wl_enabled")==0)
            {
                if (strcmp(val, "1")==0)
                {
                    GWPEpon_ProcessWlEnable();
                }
                else if (strcmp(val, "0")==0)
                {
                    GWPEpon_ProcessWlDisable();
                }
            }
            else if (strcmp(name, "xconf_router_ip_mode")==0)
            {
                if (strcmp(val, "1")==0)
                {
                    GWPEpon_ProcessXconfRouterIpMode();
                }
            }
            else if (strcmp(name, "xconf_pod_seed")==0)
            {
                if (strcmp(val, "1")==0)
                {
                    GWPEpon_ProcessXconfPoDSeed();
                }
            }
            else if (strcmp(name, "xconf_dst_adj")==0)
            {
                if (strcmp(val, "1")==0)
                {
                    GWPEpon_ProcessXconfDstAdj();
                }
            }
            else if (strcmp(name, "xconf_gw_prov_mode")==0)
            {
                if (strcmp(val, "1")==0)
                {
                    GWPEpon_ProcessXconfGwProvMode();
                }
            }
            else if (strcmp(name, "bridge_mode")==0)
            {
                if (strcmp(val, "0")==0)
                {
                    GWPEpon_ProcessBridgeModeDisable();
                }
                else
                {
                    GWPEpon_ProcessBridgeModeEnable();
                }
            }
            else if (strcmp(name, "firewall-restart")==0)
            {
                GWPEpon_ProcessFirewallRestart();
            }
            else if (strcmp(name, "gre-restart")==0 || strcmp(name, "gre-forceRestart")==0)
            {
                GWPEpon_ProcessGreRestart(val);
            }
            else if (strcmp(name, "ipv4_timezone") == 0)
            {
                GWPEpon_ProcessIpv4Timezone();
            }
            else if (strcmp(name, "ipv6_timezone") == 0)
            {
                GWPEpon_ProcessIpv6Timezone();
            }
            else if ((strcmp(name, "lan-status") == 0 ||
                     strcmp(name, "wan-status") == 0) &&
                     strcmp(val, "started") == 0)
            {
                int restartFirewall = 0;
                // When lan-status and wan-status started, only call functions when both are started
                // or bad things will happen
                do
                {
                    unsigned char lan_status[20];
                    unsigned char wan_status[20];
                    
                    // Make sure lan-status is started first...
                    lan_status[0] = '\0';
                    if (GWPEpon_SyseventGetStr("lan-status", lan_status, sizeof(lan_status)) < 0)
                    {
                        break;
                    }
                    
                    if (strcmp(lan_status, "started") != 0)
                    {
                        break;
                    }
                    
                    // Make sure wan-status is started second...
                    wan_status[0] = '\0';
                    if (GWPEpon_SyseventGetStr("wan-status", wan_status, sizeof(wan_status)) < 0)
                    {
                        break;
                    }
                    
                    if (strcmp(wan_status, "started") != 0)
                    {
                        break;
                    }

                    GWPEpon_ProcessRIPD("wan-status", "started");
                    restartFirewall = 1;
                } while (0);

                if (strcmp(name, "lan-status") == 0)
                {
                     GWPEpon_ProcessLanStatus();
                }
                
                if (restartFirewall == 1)
                {
                    GWPEpon_ProcessFirewallRestart();
                }
            }
            else if (strcmp(name, "lan-restart") == 0)
            {
                if (strcmp(val, "1")==0)
                {
                    GWPEpon_ProcessLanRestart();
                }
            }
            else if (strcmp(name, "lan-stop") == 0)
            {
	        GWPEpon_ProcessLanStop();
            }
            else if (strcmp(name, "forwarding-restart") == 0)
            {
	        GWPEpon_ProcessForwardingRestart();
            }
            else if (strcmp(name, "pnm-status") == 0)
            {
             	if (strcmp(val, "up")==0)
                 {
                     GWPEpon_ProcessPNM_Status();
                 }
            }
             else if (strcmp(name, "multinet-syncMembers") == 0)
            {
             	if (strcmp(val, "2")==0) //So we can switch the port instantly from UI request
             	{
             	   GWPEpon_ProcessLanEth0ToXHS();
             	}
             	else
             	{
                    GWPEpon_ProcessLanEth0ToLocalNetwork();
             	}
            }
            /* Process tsip events */
            else if (strcmp(name, "ipv4-sync_tsip_all") == 0 ||
                     strcmp(name, "ipv4-stop_tsip_all") == 0 ||
                     strcmp(name, "ipv4-resync_tsip") == 0 ||
                     strcmp(name, "ipv4-resync_tsip_asn") == 0)
            {
                 GWPEpon_ProcessTSIP(name, val);
            }
            /* Process RIPD/Zebra events */
            else if (strcmp(name, "lan-status") == 0 ||
                     strcmp(name, "wan-status") == 0 ||
                     strcmp(name, "dhcpv6_option_changed") == 0 ||
                     strcmp(name, "ripd-restart") == 0 ||
                     strcmp(name, "zebra-restart") == 0 ||
                     strcmp(name, "staticroute-restart") == 0)
            {
                GWPEpon_ProcessRIPD(name, val);
                if (strcmp(name, "lan-status") == 0)
                {
                     GWPEpon_ProcessLanStatus();
                }
            }
            else
            {
               GWPROVEPONLOG(WARNING, "undefined event %s \n",name)
            }			
        }
    }

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__)
}


static void  notifySysEvents()
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__)

    if (GWPEpon_SysCfgGetInt("dhcp_server_enabled") == 1)
    {
        GWPEpon_SyseventSetStr("dhcp_server-restart", "1", 0);
    }	

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__)
}

static void GWPEpon_SetDefaults()
{
    unsigned char buf[10];
    unsigned char out_val[20];
    int outbufsz = sizeof(out_val);
    int update_db = 0;
	
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__)

    //Set default syscfg entries
    if (GWPEpon_SysCfgGetInt("factory_mode") < 0)
    {
        GWPROVEPONLOG(INFO, "setting default factory mode to 1\n");
        GWPEpon_SysCfgSetInt("factory_mode", 1);
    }

    if(GWPEpon_SysCfgGetInt("factory_mode") == 1)
    {
        GWPEpon_SysCfgSetStr("router_ip_mode_override", "Honor");
        GWPEpon_SysCfgSetStr("pod_seed", "Interface disabled");    
        GWPEpon_SysCfgSetStr("dst_adj", "Off");
        GWPEpon_SysCfgSetStr("gw_prov_mode", "de-provisioned");
    }
    else
    {
        out_val[0]='\0';
        if(GWPEpon_SysCfgGetStr("pod_seed", out_val, outbufsz))
        {
            GWPROVEPONLOG(INFO, "setting default PoD seed to Interface disabled\n");
            GWPEpon_SysCfgSetStr("pod_seed", "Interface disabled");
            update_db = 1;
        }
    
        out_val[0]='\0';
        if(GWPEpon_SysCfgGetStr("router_ip_mode_override", out_val, outbufsz))
        {
            GWPROVEPONLOG(INFO, "setting default router IP mode override to Honor\n");
            GWPEpon_SysCfgSetStr("router_ip_mode_override", "Honor");
            update_db = 1;
        }
    
        out_val[0]='\0';
        if(GWPEpon_SysCfgGetStr("dst_adj", out_val, outbufsz))
        {
            GWPROVEPONLOG(INFO, "setting default dst_adj to Off\n");
            GWPEpon_SysCfgSetStr("dst_adj", "Off");
            update_db = 1;
        }
    
        out_val[0]='\0';
        if (GWPEpon_SysCfgGetStr("gw_prov_mode", out_val, outbufsz))
        {
            GWPROVEPONLOG(INFO, "setting default gw prov mode to de-provisioned\n");
            GWPEpon_SysCfgSetStr("gw_prov_mode", "de-provisioned");
            update_db = 1;
        }    
    }

    if(update_db)
        syscfg_commit();

    //Set default sysevent entries
    buf[0]='\0';
    if (GWPEpon_SyseventGetStr("epon_ifstatus", buf, sizeof(buf)) < 0)
    {
        GWPEpon_SyseventSetStr("epon_ifstatus", "up", 0);
    }
	
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__)
}

static bool GWPEpon_Register_sysevent()
{
    bool status = false;
    const int max_retries = 6;
    int retry = 0;
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__)

    do
    {
        sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "gw_prov_epon", &sysevent_token);
        if (sysevent_fd < 0)
        {
            GWPROVEPONLOG(ERROR, "gw_prov_epon failed to register with sysevent daemon\n");
            status = false;
        }
        else
        {  
            GWPROVEPONLOG(INFO, "gw_prov_epon registered with sysevent daemon successfully\n");
            status = true;
        }
        
        //Make another connection for gets/sets
        sysevent_fd_gs = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "gw_prov_epon-gs", &sysevent_token_gs);
        if (sysevent_fd_gs < 0)
        {
            GWPROVEPONLOG(ERROR, "gw_prov_epon-gs failed to register with sysevent daemon\n");
            status = false;
        }
        else
        {
            GWPROVEPONLOG(INFO, "gw_prov_epon-gs registered with sysevent daemon successfully\n");
            status = true;
        }

        if(status == false) {
        	system("/usr/bin/syseventd");
                sleep(5);
        }
    }while((status == false) && (retry++ < max_retries));


    if (status != false)
       GWPEpon_SetDefaults();

    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__);
    return status;
}

static int GWPEpon_Init()
{
    int status = 0;
    int thread_status = 0;
    char thread_name[THREAD_NAME_LEN];
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__)

    if (GWPEpon_Register_sysevent() == false)
    {
        GWPROVEPONLOG(ERROR, "GWPEpon_Register_sysevent failed\n")
        status = -1;
    }
    else 
    {
        GWPROVEPONLOG(INFO, "GWPEpon_Register_sysevent Successful\n")
    
        thread_status = pthread_create(&sysevent_tid, NULL, GWPEpon_sysevent_handler, NULL);
        if (thread_status == 0)
        {
            GWPROVEPONLOG(INFO, "GWPEpon_sysevent_handler thread created successfully\n");

            memset( thread_name, '\0', sizeof(char) * THREAD_NAME_LEN );
            strcpy( thread_name, "GWPEponsysevent");

            if (pthread_setname_np(sysevent_tid, thread_name) == 0)
                GWPROVEPONLOG(INFO, "GWPEpon_sysevent_handler thread name %s set successfully\n", thread_name)
            else
                GWPROVEPONLOG(ERROR, "%s error occured while setting GWPEpon_sysevent_handler thread name\n", strerror(errno))
                
            sleep(5);
        }
        else
        {
            GWPROVEPONLOG(ERROR, "%s error occured while creating GWPEpon_sysevent_handler thread\n", strerror(errno))
            status = -1;
        }
    }
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__)
    return status;
}

static bool checkIfAlreadyRunning(const char* name)
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__)
    bool status = true;
	
    FILE *fp = fopen("/tmp/.gwprovepon.pid", "r");
    if (fp == NULL) 
    {
        GWPROVEPONLOG(ERROR, "File /tmp/.gwprovepon.pid doesn't exist\n")
        FILE *pfp = fopen("/tmp/.gwprovepon.pid", "w");
        if (pfp == NULL) 
        {
            GWPROVEPONLOG(ERROR, "Error in creating file /tmp/.gwprovepon.pid\n")
        }
        else
        {
            pid_t pid = getpid();
            fprintf(pfp, "%d", pid);
            fclose(pfp);
        }
        status = false;
    }
    else
    {
        fclose(fp);
    }
    GWPROVEPONLOG(INFO, "Exiting from %s\n",__FUNCTION__)
    return status;
}

static void daemonize(void) 
{
    GWPROVEPONLOG(INFO, "Entering into %s\n",__FUNCTION__)
    int fd;
    switch (fork()) {
    case 0:
      	GWPROVEPONLOG(ERROR, "In child pid=%d\n", getpid())
        break;
    case -1:
    	// Error
    	GWPROVEPONLOG(ERROR, "Error daemonizing (fork)! %d - %s\n", errno, strerror(errno))
    	exit(0);
    	break;
    default:
     	GWPROVEPONLOG(ERROR, "In parent exiting\n")
    	_exit(0);
    }

    //create new session and process group
    if (setsid() < 0) {
        GWPROVEPONLOG(ERROR, "Error demonizing (setsid)! %d - %s\n", errno, strerror(errno))
    	exit(0);
    }    

#ifndef  _DEBUG
    //redirect fd's 0,1,2 to /dev/null     
    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }
#endif	
}


/**************************************************************************/
/*! \fn int main(int argc, char *argv)
 **************************************************************************
 *  \brief Init and run the Provisioning process
 *  \param[in] argc
 *  \param[in] argv
 *  \return Currently, never exits
 **************************************************************************/
int main(int argc, char *argv[])
{
    int status = 0;
    const int max_retries = 6;
    int retry = 0;

#ifdef FEATURE_SUPPORT_RDKLOG
    pComponentName = compName;
    rdk_logger_init(DEBUG_INI_NAME);
#endif

    GWPROVEPONLOG(INFO, "Started gw_prov_epon\n")

    daemonize();

    if (checkIfAlreadyRunning(argv[0]) == true)
    {
        GWPROVEPONLOG(ERROR, "Process %s already running\n", argv[0])
        status = 1;
    }
    else
    {    
        while((syscfg_init() != 0) && (retry++ < max_retries))
        {
            GWPROVEPONLOG(ERROR, "syscfg init failed. Retry<%d> ...\n", retry)
            sleep(5);
        }

        if (retry < max_retries)
        {
            GWPROVEPONLOG(INFO, "syscfg init successful\n")

            if (GWPEpon_Init() != 0)
            {
                GWPROVEPONLOG(ERROR, "GWPEpon Initialization failed\n")
                status = 1;
            }
            else
            {
                GWPROVEPONLOG(INFO, "GwProvEpon initialization completed\n")
                notifySysEvents();
                //wait for sysevent_tid thread to terminate
                pthread_join(sysevent_tid, NULL);
                
                GWPROVEPONLOG(INFO,"sysevent_tid thread terminated\n")
            }
        }
        else
        {
            GWPROVEPONLOG(ERROR, "syscfg init failed permanently\n")
            status = 1;
        }
	GWPROVEPONLOG(INFO, "gw_prov_epon app terminated\n")
    }
    return status;
}
#endif
