/*
 * Copyright (c) 2001 Mark Fullmer and The Ohio State University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      $Id: ftpaths.h.in,v 1.9 2003/11/11 16:49:14 maf Exp $
 */

#ifndef FTPATHS_H
#define FTPATHS_H

#define FT_PATH_CFG_MAP             "/usr/local/netflow/var/cfg/map.cfg"
#define FT_PATH_CFG_TAG             "/usr/local/netflow/var/cfg/tag.cfg"
#define FT_PATH_CFG_FILTER          "/usr/local/netflow/var/cfg/filter.cfg"
#define FT_PATH_CFG_STAT            "/usr/local/netflow/var/cfg/stat.cfg"
#define FT_PATH_CFG_MASK            "/usr/local/netflow/var/cfg/mask.cfg"
#define FT_PATH_CFG_XLATE           "/usr/local/netflow/var/cfg/xlate.cfg"

#define FT_PATH_SYM_IP_PROT         "/usr/local/netflow/var/sym/ip-prot.sym"
#define FT_PATH_SYM_IP_TYPE         "/usr/local/netflow/var/sym/ip-type.sym"
#define FT_PATH_SYM_TCP_PORT        "/usr/local/netflow/var/sym/tcp-port.sym"
#define FT_PATH_SYM_ASN             "/usr/local/netflow/var/sym/asn.sym"
#define FT_PATH_SYM_TAG             "/usr/local/netflow/var/sym/tag.sym"

#endif /* FTPATHS_H */
