##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_LDFLAGS = -lsysevent
AM_LDFLAGS += -lsyscfg
AM_LDFLAGS += -lhal_msomgmt
AM_CFLAGS += -I$(top_srcdir)/hal/include -I=/usr/include/ccsp

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu
bin_PROGRAMS = gw_prov_epon
gw_prov_epon_CPPFLAGS = -I/var/tmp/pc-rdkb/include $(CPPFLAGS) -I$(srcdir)/include -I$(top_srcdir)/../hal/include
gw_prov_epon_SOURCES = gw_prov_epon_sm.c
gw_prov_epon_LDFLAGS = -lsysevent -lsyscfg -lhal_msomgmt -lccsp_common -lsecure_wrapper

