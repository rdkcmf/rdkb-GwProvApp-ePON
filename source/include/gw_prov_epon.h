/*##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
#######################################################################
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
