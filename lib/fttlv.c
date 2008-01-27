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
 *      $Id: fttlv.c,v 1.6 2003/02/13 02:38:43 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

/*
 * function: fttlv_enc_uint32
 *
 * encode a uint32_t TLV into buf
 *  buf        buffer to encode to
 *  buf_size   available bytes in buf
 *  flip       swap byte order
 *  t          TLV type
 *  v          TLV value
 *
 * returns: -1 if buffer is not large enough, else bytes used.
*/
int fttlv_enc_uint32(void *buf, int buf_size, int flip, uint16_t t, uint32_t v)
{
  uint16_t len;

  if (buf_size < 8)
    return -1;

  len = 4;

  if (flip) {
    SWAPINT16(t);
    SWAPINT16(len);
    SWAPINT32(v);
  }

  bcopy(&t, buf, 2);
  buf = (char*)buf + 2;
  
  bcopy(&len, buf, 2);
  buf = (char*)buf + 2;
  
  bcopy(&v, buf, 4);

  return 8;

} /* fttlv_enc_uint32 */

/*
 * function: fttlv_enc_uint16
 *
 * encode a uint16_t TLV into buf
 *  buf        buffer to encode to
 *  buf_size   available bytes in buf
 *  flip       swap byte order
 *  t          TLV type
 *  v          TLV value
 *
 * returns: -1 if buffer is not large enough, else bytes used.
*/
int fttlv_enc_uint16(void *buf, int buf_size, int flip, uint16_t t, uint16_t v)
{
  uint16_t len;

  if (buf_size < 6)
    return -1;

  len = 2;

  if (flip) {
    SWAPINT16(t);
    SWAPINT16(len);
    SWAPINT16(v);
  }

  bcopy(&t, buf, 2);
  buf = (char*)buf + 2;
  
  bcopy(&len, buf, 2);
  buf = (char*)buf + 2;
  
  bcopy(&v, buf, 2);

  return 6;

} /* fttlv_enc_uint16_t */

/*
 * function: fttlv_enc_uint8
 *
 * encode a uint8_t TLV into buf
 *  buf        buffer to encode to
 *  buf_size   available bytes in buf
 *  flip       swap byte order
 *  t          TLV type
 *  v          TLV value
 *
 * returns: -1 if buffer is not large enough, else bytes used.
*/
int fttlv_enc_uint8(void *buf, int buf_size, int flip, uint16_t t, uint8_t v)
{
  uint16_t len;

  if (buf_size < 5)
    return -1;

  len = 1;

  if (flip) {
    SWAPINT16(t);
    SWAPINT16(len);
  }

  bcopy(&t, buf, 2);
  buf = (char*)buf + 2;

  bcopy(&len, buf, 2);
  buf = (char*)buf + 2;
  
  bcopy(&v, buf, 1);

  return 5;

} /* fttlv_enc_uint8 */

/*
 * function: fttlv_enc_str
 *
 * encode a C string TLV into buf
 *  buf        buffer to encode to
 *  buf_size   available bytes in buf
 *  flip       swap byte order
 *  t          TLV type
 *  v          TLV value
 *
 * returns: -1 if buffer is not large enough, else bytes used.
*/
int fttlv_enc_str(void *buf, int buf_size, int flip, uint16_t t, char *v)
{
  uint16_t len, len2;

  len = len2 = strlen(v)+1;

  if (buf_size < 4+len)
    return -1;

  if (flip) {
    SWAPINT16(t);
    SWAPINT16(len);
  }

  bcopy(&t, buf, 2);
  buf = (char*)buf + 2;

  bcopy(&len, buf, 2);
  buf = (char*)buf + 2;

  bcopy(v, buf, len);

  return 4+len2;

} /* fttlv_enc_str */


/*
 * function: fttlv_enc_ifname
 *
 * encode a ftmap_ifname TLV into buf
 *  buf        buffer to encode to
 *  buf_size   available bytes in buf
 *  flip       swap byte order
 *  t          TLV type
 *  ip         ip address
 *  ifIndex    ifIndex
 *  name       interface name
 *
 * returns: -1 if buffer is not large enough, else bytes used.
 */
int fttlv_enc_ifname(void *buf, int buf_size, int flip, uint16_t t,
  uint32_t ip, uint16_t ifIndex, char *name)
{
  uint16_t len, len2;
  int n;

  n = strlen(name)+1;

  len = len2 = n+2+4;

  if (flip) {
    SWAPINT16(t);
    SWAPINT16(len);
    SWAPINT32(ip);
    SWAPINT16(ifIndex);
  }

  if (buf_size < 4+len)
    return -1;

  bcopy(&t, buf, 2);
  buf = (char*)buf + 2;
  
  bcopy(&len, buf, 2);
  buf = (char*)buf + 2;
  
  bcopy(&ip, buf, 4);
  buf = (char*)buf + 2;
  
  bcopy(&ifIndex, buf, 2);
  buf = (char*)buf + 2;
  
  bcopy(name, buf, n);

  return 4+len2;

} /* fttlv_enc_ifname */

/*
 * function: fttlv_enc_ifalias
 *
 * encode a ftmap_ifalias TLV into buf
 *  buf          buffer to encode to
 *  buf_size     available bytes in buf
 *  flip         swap byte order
 *  t            TLV type
 *  ip           ip address
 *  ifIndex_list list of ifIndexes
 *  entries      # of entries in ifIndex_list
 *  name         alias name
 *
 * returns: -1 if buffer is not large enough, else bytes used.
 */
int fttlv_enc_ifalias(void *buf, int buf_size, int flip, uint16_t t,
  uint32_t ip, uint16_t *ifIndex_list, uint16_t entries, char *name)
{
  uint16_t len, len2;
  int n,i,esize;

  n = strlen(name)+1;
  esize = (entries*2);

  len = len2 = n+2+4+esize;

  if (buf_size < 4+len)
    return -1;

  if (flip) {
    SWAPINT16(t);
    SWAPINT16(len);
    SWAPINT32(ip);
    for (i = 0; i < entries; ++i) {
      SWAPINT16(ifIndex_list[i]);
    }
    SWAPINT16(entries);
  }

  bcopy(&t, buf, 2);
  buf = (char*)buf + 2;
  
  bcopy(&len, buf, 2);
  buf = (char*)buf + 2;
	  
  bcopy(&ip, buf, 4);
  buf = (char*)buf + 2;

  bcopy(&entries, buf, 2);
  buf = (char*)buf + 2;

  bcopy(ifIndex_list, buf, esize);
  buf = (char*)buf + esize;
  
  bcopy(name, buf, n);

  return 4+len2;

} /* fttlv_enc_ifalias */

