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
 *      $Id: ftio.c,v 1.47 2003/02/24 00:51:47 maf Exp $
 */

#include "ftinclude.h"
#include "ftlib.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <syslog.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <zlib.h>

#if HAVE_MMAP
 #include <sys/types.h>
 #include <sys/mman.h>
 #include <sys/stat.h>
#endif

int readn(register int fd, register void *ptr, register int nbytes);

/*
 * function: ftio_init
 *
 * Initialize an ftio structure, allocating r/w buffers, zlib, etc.
 * On READ the header is consumed.
 *
 * flags:  FT_IO_FLAG_READ    - setup ftio for reading
 *         FT_IO_FLAG_WRITE   - setup ftio for writing
 *         FT_IO_FLAG_ZINIT   - used with FT_IO_FLAG_WRITE to signal
 *                              future use of compression.
 *         FT_IO_FLAG_NO_SWAP - used with FT_IO_FLAG_WRITE.  Normally
 *                              ftio_write() expects the record in
 *                              host format, and will return it in
 *                              host format.  This will disable the
 *                              swap operation to maximize performance
 *                              in certain cases.
 *         FT_IO_FLAG_MMAP    - use mmap() for reading flows
 *
 * ftio_close() must be called on the stream to free resources
 * and flush buffers on WRITE.
 *
 * returns: < 0 error
 *          >= 0 ok
 */
int ftio_init(struct ftio *ftio, int fd, int flag)
{
  int i, ret;
  struct stat sb;
  struct ftver ftv;

  bzero(ftio, sizeof (struct ftio));

  ftio->fd = fd;

  ret = -1;

  if (flag & FT_IO_FLAG_READ) {

#if HAVE_MMAP

    if (flag & FT_IO_FLAG_MMAP) {

      if (fstat(ftio->fd, &sb) < 0) {
         fterr_warn("stat()");
         goto ftio_init_out;
      }

      ftio->mr_size = sb.st_size;

      if ((ftio->mr = mmap((caddr_t)0L, ftio->mr_size, PROT_READ|PROT_WRITE,
         MAP_PRIVATE,
         ftio->fd, (off_t)0L)) == MAP_FAILED) {
         fterr_warn("mmap()");
         goto ftio_init_out;
      }

      ftio->flags |= FT_IO_FLAG_MMAP;

    } /* FT_IO_FLAG_MMAP */

#endif /* HAVE_MMAP */

    /* load header */
    if (ftiheader_read(ftio->fd, &ftio->fth) < 0) {
      fterr_warnx("ftiheader_read(): failed");
      goto ftio_init_out;
    }

    if (flag & FT_IO_FLAG_MMAP) {
      ftio->d_start = ftio->fth.enc_len;
      ftio->d_end = sb.st_size;
    }

    /* verify stream version */
    if ((ftio->fth.s_version != 1) && (ftio->fth.s_version != 3)) {
      fterr_warnx("Unsupported stream version %d", (int)ftio->fth.s_version);
      goto ftio_init_out;
    }
  
    /* backwards compatability hack */
    if ((ftio->fth.s_version == 1) && (ftio->fth.d_version == 65535))
      ftio->fth.d_version = 1;

    /* alloc z_buf if compression set and not using mmap */
    if (!(ftio->flags & FT_IO_FLAG_MMAP)) {
      if (ftio->fth.flags & FT_HEADER_FLAG_COMPRESS) {
        if (!(ftio->z_buf = (char*)malloc(FT_Z_BUFSIZE))) {
          fterr_warn("malloc()");
          goto ftio_init_out;
        }
      }
    }
  
    /* calculate record size */
    if ((ftio->rec_size = ftio_rec_size(ftio)) < 0) {
      fterr_warnx("Unsupported record type (ftio_rec_size_");
      goto ftio_init_out;
    }

    /* calculate FT_XFIELD* */
    if ((ftio->xfield = ftio_xfield(ftio)) == -1) {
      fterr_warnx("Unsupported record type (ftio_xfield)");
      goto ftio_init_out;
    }
  
    /* set byte swap function */
    if (!(ftio->swapf = ftio_rec_swapfunc(ftio))) {
      goto ftio_init_out;
    }

    /* get byte for fields */
    ftio_get_ver(ftio, &ftv);
    fts3rec_compute_offsets(&ftio->fo, &ftv);

    /* 
     * alloc d_buf -- 1 for compressed or strems, many for uncompressed
     */

    if (ftio->fth.flags & FT_HEADER_FLAG_COMPRESS)
      i = ftio->rec_size;
    else
      i = FT_D_BUFSIZE;

    if ((ftio->fth.flags & FT_HEADER_FLAG_COMPRESS) ||
        (!(ftio->flags & FT_IO_FLAG_MMAP))) {
      if (!(ftio->d_buf = (char*)malloc(i))) {
        fterr_warn("malloc()");
        goto ftio_init_out;
      }
    }
  
    /* initialize zlib and set zlib initialized flag */
    if (ftio->fth.flags & FT_HEADER_FLAG_COMPRESS) {
  
      ftio->zs.zalloc = (alloc_func)0;
      ftio->zs.zfree = (free_func)0;
      ftio->zs.opaque = (voidpf)0;
  
      if (inflateInit(&ftio->zs) != Z_OK) {
        fterr_warnx("inflateInit(): failed");
        goto ftio_init_out;
      }
  
      ftio->flags |= FT_IO_FLAG_ZINIT;

#ifdef HAVE_MMAP
 
      if (flag & FT_IO_FLAG_MMAP) {

        ftio->zs.avail_in = sb.st_size - ftio->fth.enc_len;
        ftio->zs.next_in = (Bytef*)ftio->mr+ftio->fth.enc_len;

      }

#endif /* HAVE_MMAP */

      ftio->zs.avail_out = ftio->rec_size;
      ftio->zs.next_out = (Bytef*)ftio->d_buf;

    }

    /* mark stream for reading */
    ftio->flags |= FT_IO_FLAG_READ;

    /* flags always valid */
    ftio->fth.fields |= FT_FIELD_HEADER_FLAGS;
  
    ret = 0;

  } else if (flag & FT_IO_FLAG_WRITE) {

#if BYTE_ORDER == LITTLE_ENDIAN
    ftio->fth.byte_order = FT_HEADER_LITTLE_ENDIAN;
#endif /* LITTLE_ENDIAN */

#if BYTE_ORDER == BIG_ENDIAN
    ftio->fth.byte_order = FT_HEADER_BIG_ENDIAN;
#endif /* BIG_ENDIAN */

    /* alloc z_buf if compression set */
    if (flag & FT_IO_FLAG_ZINIT) {

      if (!(ftio->z_buf = (char*)malloc(FT_Z_BUFSIZE))) {
        fterr_warn("malloc()");
        goto ftio_init_out;
      }

      ftio->zs.zalloc = (alloc_func)0;
      ftio->zs.zfree = (free_func)0;
      ftio->zs.opaque = (voidpf)0;

      if (deflateInit(&ftio->zs, ftio->z_level) != Z_OK) {
        fterr_warnx("deflateInit(): failed");
        goto ftio_init_out;
      }

      ftio->flags |= FT_IO_FLAG_ZINIT;
      ftio->fth.flags |= FT_HEADER_FLAG_COMPRESS;

      ftio->zs.next_out = (Bytef*)ftio->z_buf;
      ftio->zs.avail_out = FT_Z_BUFSIZE;

    /* no compression */
    } else {

      if (!(ftio->d_buf = (char*)malloc(FT_D_BUFSIZE))) {
        fterr_warn("malloc()");
        goto ftio_init_out;
      }

      ftio->d_end = FT_D_BUFSIZE;

    }

    /* mark stream for writing */
    ftio->flags |= FT_IO_FLAG_WRITE;

    /* flags field always valid */
    ftio->fth.fields |= FT_FIELD_HEADER_FLAGS;

    /* preserve FT_IO_FLAG_NO_SWAP */
    if (flag & FT_IO_FLAG_NO_SWAP)
      ftio->flags |= FT_IO_FLAG_NO_SWAP;

    ret = 0;

  } /* write */
  
ftio_init_out:
  
  if (ret) {

    if (ftio->z_buf)
      free (ftio->z_buf);

    if (ftio->d_buf)
      free (ftio->d_buf);

    if (ftio->flags & FT_IO_FLAG_ZINIT)
      inflateEnd(&ftio->zs);

#if HAVE_MMAP

    if (ftio->mr)
      munmap(ftio->mr, (size_t)ftio->mr_size);

#endif /* HAVE_MMAP */

  } /* error */

  return ret;
}

/*
 * function: ftio_set_z_level
 *
 * Set the zlib compression level for a ftio stream.
 */
void ftio_set_z_level(struct ftio *ftio, int z_level)
{

  ftio->fth.fields |= FT_FIELD_HEADER_FLAGS;

  if ((ftio->fth.flags & FT_HEADER_FLAG_COMPRESS) && (!z_level)) {
    fterr_warnx("Compression can not be disabled");
    return;
  }
  
  if ((!(ftio->fth.flags & FT_HEADER_FLAG_COMPRESS)) && (z_level)) {
    fterr_warnx("Compression can not be enabled");
    return;
  }

  ftio->z_level = z_level;

  if (z_level) 
    if (deflateParams(&ftio->zs, ftio->z_level, Z_DEFAULT_STRATEGY) != Z_OK)
      fterr_warnx("deflateParams(): failed");

}
 

/*
 * function: ftio_set_flows_count
 *
 * Set the # of flows for a ftio stream header
 */
void ftio_set_flows_count(struct ftio *ftio, u_int32 n)
{
  ftio->fth.fields |= FT_FIELD_FLOW_COUNT;
  ftio->fth.flows_count = n;
}

/*
 * function: ftio_set_streaming
 *
 * Set the streaming flag for a ftio stream
 */
void ftio_set_streaming(struct ftio *ftio, int flag)
{
  ftio->fth.fields |= FT_FIELD_HEADER_FLAGS;

  if (flag)
    ftio->fth.flags |= FT_HEADER_FLAG_STREAMING;
  else
    ftio->fth.flags &= ~FT_HEADER_FLAG_STREAMING;
}

/*
 * function: ftio_set_preloaded
 *
 * Set the streaming preloaded for a ftio stream
 */
void ftio_set_preloaded(struct ftio *ftio, int flag)
{
  ftio->fth.fields |= FT_FIELD_HEADER_FLAGS;

  if (flag)
    ftio->fth.flags |= FT_HEADER_FLAG_PRELOADED;
  else
    ftio->fth.flags &= ~FT_HEADER_FLAG_PRELOADED;
}

/*
 * function: ftio_set_ver
 *
 * Set the version information for a ftio stream
 */
int ftio_set_ver(struct ftio *ftio, struct ftver *ver)
{

  ftio->fth.fields |= FT_FIELD_EX_VER;

  if (ver->d_version == 8) {
    ftio->fth.fields |= FT_FIELD_AGG_VER;
    ftio->fth.fields |= FT_FIELD_AGG_METHOD;
  }

  ftio->fth.d_version = ver->d_version;
  ftio->fth.s_version = ver->s_version;
  ftio->fth.agg_method = ver->agg_method;
  ftio->fth.agg_version = ver->agg_version;

  /* calculate record size */
  if ((ftio->rec_size = ftio_rec_size(ftio)) < 0) {
    fterr_warnx("Unsupported record type");
    ftio->fth.d_version = 0;
    return -1;
  }

  /* set byte swap function */
  if (!(ftio->swapf = ftio_rec_swapfunc(ftio))) {
    return -1;
  }

  return 0;

}

/*
 * function: ftio_set_byte_order
 *
 * Set the byte order for a ftio stream
 */
void ftio_set_byte_order(struct ftio *ftio, int byte_order)
{
  ftio->fth.fields |= FT_FIELD_HEADER_FLAGS;
  ftio->fth.byte_order = byte_order;
}

/*
 * function: ftio_set_debug
 *
 * Set the debug level for a ftio stream
 */
void ftio_set_debug(struct ftio *ftio, int debug)
{
  ftio->debug = debug;
}

/*
 * function: ftio_set_comment
 *
 * Set the header comment for a ftio stream
 */
int ftio_set_comment(struct ftio *ftio, char *comment)
{

  if (!comment)
    return 0;

  if (ftio->fth.comments)
    free(ftio->fth.comments);

  if (!(ftio->fth.comments = (char*)malloc(strlen(comment)+1))) {
    fterr_warn("malloc()");
    return -1;
  }
  strcpy(ftio->fth.comments, comment);
  ftio->fth.fields |= FT_FIELD_COMMENTS;
  return 0;
}

/*
 * function: ftio_set_cap_hostname
 *
 * Set the header capture hostname for a ftio stream
 */
int ftio_set_cap_hostname(struct ftio *ftio, char *hostname)
{

  if (!hostname)
    return 0;

  if (ftio->fth.cap_hostname)
    free(ftio->fth.cap_hostname);

  if (!(ftio->fth.cap_hostname = (char*)malloc(strlen(hostname)+1))) {
    fterr_warn("malloc()");
  }
  strcpy(ftio->fth.cap_hostname, hostname);
  ftio->fth.fields |= FT_FIELD_CAP_HOSTNAME;
  return 0;
}

/*
 * function: ftio_set_corrupt
 *
 * Set the corrupt flows header field
 */
void ftio_set_corrupt(struct ftio *ftio, u_int32 n)
{
  ftio->fth.fields |= FT_FIELD_PKT_CORRUPT;
  ftio->fth.pkts_corrupt = n;
}

/*
 * function: ftio_set_lost
 *
 * Set the lost flows header field
 */
void ftio_set_lost(struct ftio *ftio, u_int32 n)
{
  ftio->fth.fields |= FT_FIELD_FLOW_LOST;
  ftio->fth.flows_lost = n;
}

/*
 * function: ftio_set_reset
 *
 * Set the reset sequence header field
 */
void ftio_set_reset(struct ftio *ftio, u_int32 n)
{
  ftio->fth.fields |= FT_FIELD_SEQ_RESET;
  ftio->fth.seq_reset = n;
}


/*
 * function: ftio_set_xip
 *
 * Set the exporter ip header field
 */
void ftio_set_xip(struct ftio *ftio, u_int32 ip)
{
  ftio->fth.fields |= FT_FIELD_EXPORTER_IP;
  ftio->fth.exporter_ip = ip;
}

/*
 * function: ftio_set_cap_time
 *
 * Set the header time for a ftio stream
 */
void ftio_set_cap_time(struct ftio *ftio, u_int32 start, u_int32 end)
{
  ftio->fth.fields |= FT_FIELD_CAP_START;
  ftio->fth.fields |= FT_FIELD_CAP_END;
  ftio->fth.cap_start = start;
  ftio->fth.cap_end = end;
}

/*
 * function: ftio_set_cap_time_start
 *
 * Set the header time for a ftio stream
 */
void ftio_set_cap_time_start(struct ftio *ftio, u_int32 start)
{
  ftio->fth.fields |= FT_FIELD_CAP_START;
  ftio->fth.cap_start = start;
}

/*
 * function: ftio_get_ver
 *
 * Get the version from a ftio stream
 */
void ftio_get_ver(struct ftio *ftio, struct ftver *ver)
{
  ver->d_version = ftio->fth.d_version;
  ver->s_version = ftio->fth.s_version;
  ver->agg_method = ftio->fth.agg_method;
  ver->agg_version = ftio->fth.agg_version;
}

time_t ftio_uint32_to_time_t(u_int32 val) {
  return (time_t) val;
}

/*
 * function: ftio_get_stime
 *
 * Get the starting time from a ftio stream
 */
u_int32 ftio_get_cap_start(const struct ftio *ftio)
{
  return ftio->fth.cap_start;
}

time_t ftio_get_cap_start_time_t(const struct ftio *ftio) {
  return ftio_uint32_to_time_t(ftio_get_cap_start(ftio));
}

/*
 * function: ftio_get_etime
 *
 * Get the ending time from a ftio stream
 */
u_int32 ftio_get_cap_end(const struct ftio *ftio)
{
  return ftio->fth.cap_end;
}

time_t ftio_get_cap_end_time_t(const struct ftio *ftio) {
  return ftio_uint32_to_time_t(ftio_get_cap_end(ftio));
}

/*
 * function: ftio_get_rec_total
 *
 * Get the total records processed from a ftio stream
 */
u_int64 ftio_get_rec_total(struct ftio *ftio)
{
  return ftio->rec_total;
}

/*
 * function: ftio_get_flows_count
 *
 * Get the total records processed from a ftio stream
 */
u_int32 ftio_get_flows_count(struct ftio *ftio)
{
  return ftio->fth.flows_count;
}


/*
 * function: ftio_get_debug
 *
 * Get the debug level from a ftio stream
 */
int ftio_get_debug(struct ftio *ftio)
{
  return ftio->debug;
}

/*
 * function: ftio_get_cap_hostname
 *
 * Get the header hostname from a ftio stream
 */
char *ftio_get_hostname(struct ftio *ftio)
{
  return ftio->fth.cap_hostname;
}

/*
 * function: ftio_get_comment
 *
 * Get the header comment from a ftio stream
 */
char *ftio_get_comment(struct ftio *ftio)
{
  return ftio->fth.comments;
}

/*
 * function ftio_get_corrupt
 *
 * Get header corrupt flows from a ftio stream
*/
u_int32 ftio_get_corrupt(struct ftio *ftio)
{
  return ftio->fth.pkts_corrupt;
}

/*
 * function ftio_get_lost
 *
 * Get header lost flows from a ftio stream
*/
u_int32 ftio_get_lost(struct ftio *ftio)
{
  return ftio->fth.flows_lost;
}

/*
 * function: ftio_close
 *
 * Free resources allocated with ftio_init()
 * Flush any non empty buffers if stream was initialized for WRITE
 * close file descriptor
 *
 * returns: <0   error
 *          >= 0 okay
 */
int ftio_close(struct ftio *ftio)
{
  int ret, err, n, nbytes;

  ret = -1;
  nbytes = 0;

  if (ftio->fth.fields & FT_FIELD_COMMENTS)
    free(ftio->fth.comments);

  if (ftio->fth.fields & FT_FIELD_CAP_HOSTNAME)
    free(ftio->fth.cap_hostname);

  if (ftio->fth.ftmap)
    ftmap_free(ftio->fth.ftmap);

  if (ftio->flags & FT_IO_FLAG_READ) {

    if (ftio->flags & FT_IO_FLAG_ZINIT)
      inflateEnd(&ftio->zs);

    if (ftio->z_buf)
      free (ftio->z_buf);

    if (ftio->d_buf)
      free (ftio->d_buf);

#if HAVE_MMAP

    if (ftio->mr)
      munmap(ftio->mr, (size_t)ftio->mr_size);

#endif /* HAVE_MMAP */

  } else if (ftio->flags & FT_IO_FLAG_WRITE) {

    /* compression enabled? */
    if (ftio->flags & FT_IO_FLAG_ZINIT) {

      ftio->zs.avail_in = 0;
        
      while (1) {

        err = deflate(&ftio->zs, Z_FINISH);

        /* if done compressing, do final write to disk */
        if (err == Z_STREAM_END)
          break;
    
        /* if anything other than Z_OK, then it's an error */
        if (err != Z_OK) {
          fterr_warnx("deflate(): failed");
          goto ftio_close_out;
        }   
    
        /* need to flush */
        if (!ftio->zs.avail_out) {

          n = writen(ftio->fd, ftio->z_buf, FT_Z_BUFSIZE);

          if (n < 0) {
            fterr_warn("writen()");
            goto ftio_close_out;
          }
  
          if (n == 0) {
            fterr_warnx("writen(): EOF");
            goto ftio_close_out;
          }

          nbytes += n;

          ftio->zs.next_out = (Bytef*)ftio->z_buf;
          ftio->zs.avail_out = FT_Z_BUFSIZE;

        } else
          break;
      } /* while 1 */

      n = writen(ftio->fd, ftio->z_buf, FT_Z_BUFSIZE-ftio->zs.avail_out);

      if (n < 0) {
        fterr_warn("writen()");
        goto ftio_close_out;
      }
  
      if (n == 0) {
        fterr_warnx("writen(): EOF");
        goto ftio_close_out;
      }

      nbytes += n;

      ret = 0;

    /* no compression */
    } else {

      if (ftio->d_start) {

        n = writen(ftio->fd, ftio->d_buf, ftio->d_start);

        if (n < 0) {
          fterr_warn("writen()");
          goto ftio_close_out;
        }
  
        if (n == 0) {
          fterr_warnx("writen(): EOF");
          goto ftio_close_out;
        }

        ftio->d_start = 0;

        nbytes += n;

        ret = 0;

      } /* buffer not empty */

      ret = 0;

    } /* compression */

  } /* io stream enabled for write */


ftio_close_out:

  if (ftio->flags & FT_IO_FLAG_WRITE) {

    if (ftio->flags & FT_IO_FLAG_ZINIT) {

      deflateEnd(&ftio->zs);
      ftio->flags &= ~FT_IO_FLAG_ZINIT;
      free(ftio->z_buf);

    } else {

      free (ftio->d_buf);

    }

  } /* FT_IO_FLAG_WRITE */

  /* don't lose error condition if close() is a success */
  if (ret < 0)
    ret = close(ftio->fd);
  else
    close(ftio->fd);

  /* no error and writing? then return bytes written */
  if ((ftio->flags & FT_IO_FLAG_WRITE) && (ret >= 0))
    ret = nbytes;

  return ret;
  
} /* ftio_close */

/*
 * function: ftio_zstat_print
 *
 * Print resources utilization associated with ftio zlib usage
 *
 * returns: <0   error
 *          >= 0 okay
 */
void ftio_zstat_print(struct ftio *ftio, FILE *std)
{

  double d;

  d = ((double)ftio->zs.total_out) / ((double)ftio->zs.total_in);
  fprintf(std, "compression: total_in=%lu total_out=%lu  %3.3f:1\n",
    ftio->zs.total_in, ftio->zs.total_out, d);

}

/*
 * function: ftio_read
 *
 * Return the next fts3rec_* in the ftio stream, or 0L for EOF
 *
 * Record is returned in host byte order
 *
 * Stream must be first initialized with ftio_init() 
 *
 */
void *ftio_read(struct ftio *ftio)
{

  int n, err;
  void *ret;
  struct fts1rec_compat *compat;
  u_int32 bleft, boff;

  ret = (void*)0L;

#if HAVE_MMAP
  /* mmap enabled? */
  if (ftio->flags & FT_IO_FLAG_MMAP) {

    /* compressed ? */
    if (ftio->fth.flags & FT_HEADER_FLAG_COMPRESS) {

      /* EOF? */
      if (!ftio->zs.avail_in)
        goto ftio_read_out;

      err = inflate(&ftio->zs, Z_SYNC_FLUSH);

      if ((err != Z_OK) && (err != Z_STREAM_END)) {
        fterr_warnx("inflate(): failed");
        goto ftio_read_out;
      }

      /* if avail_out == 0, then a full record was inflated -- return it */
      if (!ftio->zs.avail_out) {

        /* XXX check for interrupt record */

        /* reset zlib for next call */
        ftio->zs.avail_out = ftio->rec_size;
        ftio->zs.next_out = (Bytef*)ftio->d_buf;

        ret = (void*)ftio->d_buf;
        goto ftio_read_out;

      } else {

        /* should never happen - partial decode */
        if (ftio->zs.avail_out != ftio->rec_size)
          fterr_warnx("Warning, partial inflated record before EOF");

        /* signal EOF to caller */
        goto ftio_read_out;

      } /* ftio->zs.avail_out */

    /* not compressed */
    } else {

      /* bytes left */
      bleft = ftio->d_end - ftio->d_start;

      /* enough bytes in d_buf to return a record? */
      if (bleft >= ftio->rec_size) {
        boff = ftio->d_start;
        ftio->d_start += ftio->rec_size;

        ret = (char*)ftio->mr+boff;
        goto ftio_read_out;
      }

      /* signal EOF? */
      if (!bleft)
        goto ftio_read_out;

      /* shouldn't happen */
      fterr_warnx("Warning, partial record before EOF");
      goto ftio_read_out;

    } /* not compressed and mmap */

  } /* mmap */

#endif /* HAVE_MMAP */

  /* processed compressed stream */
  if (ftio->fth.flags & FT_HEADER_FLAG_COMPRESS) {

    while (1) {

      /*
       * if the inflate buffer is empty, perform a read()
      */

      if (!ftio->zs.avail_in) {

        n = read(ftio->fd, (char*)ftio->z_buf, FT_Z_BUFSIZE);

        /* EOF and inflate buffer is empty -- done. */
        if (!n) {

          /*
           * check for partial record inflated.  This would never
           * happen on a uncorrupted stream
           */
          if (ftio->zs.avail_out != ftio->rec_size)
            fterr_warnx("Warning, partial inflated record before EOF");

          /* signal EOF to caller */
          goto ftio_read_out;

        }

        /* read error -- done. */
        if (n == -1) {
          fterr_warn("read()");
          goto ftio_read_out;
        }

        ftio->zs.avail_in = n;
        ftio->zs.next_in = (Bytef*)ftio->z_buf;

      } /* if inflate buffer empty */

      /*
       * inflate stream, attempt to get a record
       */

      err = inflate(&ftio->zs, Z_SYNC_FLUSH);

      if ((err != Z_OK) && (err != Z_STREAM_END)) {
        fterr_warnx("inflate(): failed");
        goto ftio_read_out;
      }

      /* if avail_out == 0, then a full record was inflated -- return it */
      if (!ftio->zs.avail_out) {

        /* XXX check for interrupt record */

        /* reset zlib for next call */
        ftio->zs.avail_out = ftio->rec_size;
        ftio->zs.next_out = (Bytef*)ftio->d_buf;

        ret = (void*)ftio->d_buf;
        goto ftio_read_out;

      } /* bytes available for inflate */
    } /* while 1 */
  } /* compressed stream */

  /*
   * uncompressed stream 
   */

  /*
   * if there are not enough bytes between the start pointer and the end
   * of d_buf for a full record, perform a read()
   */

  /* while(1) loop to optimize for normal case of returning bytes from d_buf */
  while (1) {

    bleft = ftio->d_end - ftio->d_start;

    /* enough bytes in d_buf to return a record? */
    if (bleft >= ftio->rec_size) {

      boff = ftio->d_start;
      ftio->d_start += ftio->rec_size;

      /* XXX check for interrupt record */
      /* ftio_interrupt(ftio); */
      /* continue */

      ret = (char*)ftio->d_buf+boff;
      goto ftio_read_out;

    /* no, perform a read() to try for more */
    } else {

      /* move trailing partial record to top of buffer */
      if (bleft)
        bcopy(ftio->d_buf+ftio->d_start, ftio->d_buf, bleft);

      ftio->d_end = bleft;
      ftio->d_start = 0;

      n = read(ftio->fd, (char*)ftio->d_buf+ftio->d_end,
        FT_D_BUFSIZE - ftio->d_end);

      /* read failed? */
      if (n < 0) {
        fterr_warn("read()");
        goto ftio_read_out;
      }

      /* eof? */
      if (n == 0) {
        if (ftio->d_start)
          fterr_warnx("Warning, partial record before EOF");
        goto ftio_read_out;
      }

      ftio->d_end += n;

    } /* need a read() */
  } /* while 1 */

ftio_read_out:

  if (ret) {

      /* fix byte ordering */
#if BYTE_ORDER == BIG_ENDIAN
      if (ftio->fth.byte_order == FT_HEADER_LITTLE_ENDIAN)
        ftio->swapf((void*)ret);
#endif /* BYTE_ORDER == BIG_ENDIAN */
  
#if BYTE_ORDER == LITTLE_ENDIAN
      if (ftio->fth.byte_order == FT_HEADER_BIG_ENDIAN)
        ftio->swapf((void*)ret);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

    /* increment total records processed */
    ftio->rec_total ++;

    /*
     * backwards compatability hack.  Map the stream version 1 into
     * a stream version 2 
     */
    if (ftio->fth.s_version == 1) {

      if (ftio->fth.d_version == 1) {

        compat = ret;

        ftio->compat_v1.sysUpTime = 0;
        ftio->compat_v1.unix_secs = compat->unix_secs;
        ftio->compat_v1.unix_nsecs = compat->unix_msecs * 1000000;
        ftio->compat_v1.srcaddr = compat->srcaddr;
        ftio->compat_v1.dstaddr = compat->dstaddr;
        ftio->compat_v1.nexthop = compat->nexthop;
        ftio->compat_v1.input = compat->input;
        ftio->compat_v1.output = compat->output;
        ftio->compat_v1.dPkts = compat->dPkts;
        ftio->compat_v1.dOctets = compat->dOctets;
        ftio->compat_v1.Last = compat->Last;
        ftio->compat_v1.First = compat->First;
        ftio->compat_v1.srcport = compat->srcport;
        ftio->compat_v1.dstport = compat->dstport;
        ftio->compat_v1.prot = compat->prot;
        ftio->compat_v1.tos = compat->tos;
        ftio->compat_v1.tcp_flags = compat->flags;

        ret = (void*)&ftio->compat_v1;

      } else if (ftio->fth.d_version == 5) {

        compat = ret;

        ftio->compat_v5.sysUpTime = 0;
        ftio->compat_v5.unix_secs = compat->unix_secs;
        ftio->compat_v5.unix_nsecs = compat->unix_msecs * 1000000;
        ftio->compat_v5.srcaddr = compat->srcaddr;
        ftio->compat_v5.dstaddr = compat->dstaddr;
        ftio->compat_v5.nexthop = compat->nexthop;
        ftio->compat_v5.input = compat->input;
        ftio->compat_v5.output = compat->output;
        ftio->compat_v5.dPkts = compat->dPkts;
        ftio->compat_v5.dOctets = compat->dOctets;
        ftio->compat_v5.Last = compat->Last;
        ftio->compat_v5.First = compat->First;
        ftio->compat_v5.srcport = compat->srcport;
        ftio->compat_v5.dstport = compat->dstport;
        ftio->compat_v5.prot = compat->prot;
        ftio->compat_v5.tos = compat->tos;
        ftio->compat_v5.tcp_flags = compat->flags;
        ftio->compat_v5.src_as = compat->src_as;
        ftio->compat_v5.dst_as = compat->dst_as;
        ftio->compat_v5.src_mask = compat->src_mask;
        ftio->compat_v5.dst_mask = compat->dst_mask;

        ret = (void*)&ftio->compat_v5;

      } /* v5 compat */
    } /* need compat hack */

  } /* ret is set */

  return ret;

}

/*
 * function: ftio_write_header
 *
 * A ftio stream consists of a header and n records.  ftio_write_header()
 * must be called before ftio_write() to output the header portion of
 * the stream
 *
 * Stream must be first initialized with ftio_init() 
 *
 * returns: <0   error
 *          >= 0 okay
 *
 */
int ftio_write_header(struct ftio *ftio)
{
  struct ftheader_gen head_gen;
  struct ftmap_ifname *ftmin;
  struct ftmap_ifalias *ftmia;
  u_int32 head_off_d;
  int n, ret, restore, flip, len;
  char *enc_buf;

  ret = -1;
  restore = 0;
  enc_buf = (char*)0L;

  /* if this is not the first time, rewind */
  if (ftio->flags & FT_IO_FLAG_HEADER_DONE) {

    if (lseek(ftio->fd, (off_t)0L, SEEK_SET) == -1) {
      fterr_warn("lseek()");
      goto ftio_write_header_out;
    }

    /* flag to seek back to end of file */
    restore = 1;

    /* mark the file as complete.  Assume that the second call to write_header
     * is actually the last
     */
    ftio->fth.flags |= FT_HEADER_FLAG_DONE;

  }

  ftio->fth.magic1 = FT_HEADER_MAGIC1;
  ftio->fth.magic2 = FT_HEADER_MAGIC2;

  ftio->fth.s_version = 3;

  if ((!ftio->fth.d_version) || (!ftio->fth.byte_order)) {
    fterr_warnx("Set d_version and byte_order first");
    goto ftio_write_header_out;
  }

  if (!(ftio->flags & FT_IO_FLAG_WRITE)) {
    fterr_warnx("Stream not initialized for writing");
    goto ftio_write_header_out;
  }

#if BYTE_ORDER == BIG_ENDIAN
    if (ftio->fth.byte_order == FT_HEADER_LITTLE_ENDIAN)
      flip = 1;
    else
      flip = 0;
#endif /* BYTE_ORDER == BIG_ENDIAN */

#if BYTE_ORDER == LITTLE_ENDIAN
    if (ftio->fth.byte_order == FT_HEADER_BIG_ENDIAN)
      flip = 1;
    else
      flip = 0;
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  /* max header size */
  len = FT_IO_MAXHEADER;

  /* allocate encode buffer + extra 4 bytes to guarantee alignment */
  if (!(enc_buf = (char*)malloc(len+4))) {
    fterr_warn("malloc()");
    goto ftio_write_header_out;
  }

  /* clear encode buffer */
  bzero(enc_buf, len+4);

  head_gen.magic1 = ftio->fth.magic1;
  head_gen.magic2 = ftio->fth.magic2;
  head_gen.byte_order = ftio->fth.byte_order;
  head_gen.s_version = ftio->fth.s_version;

  /* encode generic header */
  bcopy(&head_gen, enc_buf, sizeof head_gen);

  /* leave room to encode head_off_d later */
  head_off_d = sizeof head_gen + sizeof head_off_d;

  /*
   * encode each TLV
   */

  if (ftio->fth.fields & FT_FIELD_VENDOR) {
    if ((n = fttlv_enc_uint8(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_VENDOR, ftio->fth.vendor)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_EX_VER) {
    if ((n = fttlv_enc_uint16(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_EX_VER, ftio->fth.d_version)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_AGG_VER) {
    if ((n = fttlv_enc_uint8(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_AGG_VER, ftio->fth.agg_version)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_AGG_METHOD) {
    if ((n = fttlv_enc_uint8(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_AGG_METHOD, ftio->fth.agg_method)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_EXPORTER_IP) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_EXPORTER_IP, ftio->fth.exporter_ip)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_CAP_START) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_CAP_START, ftio->fth.cap_start)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_CAP_END) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_CAP_END, ftio->fth.cap_end)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_HEADER_FLAGS) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_HEADER_FLAGS, ftio->fth.flags)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_ROT_SCHEDULE) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_ROT_SCHEDULE, ftio->fth.rotation)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_FLOW_COUNT) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_FLOW_COUNT, ftio->fth.flows_count)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_FLOW_LOST) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_FLOW_LOST, ftio->fth.flows_lost)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_FLOW_MISORDERED) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_FLOW_MISORDERED, ftio->fth.flows_misordered)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_PKT_CORRUPT) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_PKT_CORRUPT, ftio->fth.pkts_corrupt)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_SEQ_RESET) {
    if ((n = fttlv_enc_uint32(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_SEQ_RESET, ftio->fth.seq_reset)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_CAP_HOSTNAME) {
    if ((n = fttlv_enc_str(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_CAP_HOSTNAME, ftio->fth.cap_hostname)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_COMMENTS) {
    if ((n = fttlv_enc_str(enc_buf+head_off_d, len-head_off_d,
      flip, FT_TLV_COMMENTS, ftio->fth.comments)) < 0)
      goto ftio_write_header_out;
    else
      head_off_d += n;
  }

  if (ftio->fth.fields & FT_FIELD_IF_NAME) {
    FT_LIST_FOREACH(ftmin, &ftio->fth.ftmap->ifname, chain) {
      if ((n = fttlv_enc_ifname(enc_buf+head_off_d, len-head_off_d,
        flip, FT_TLV_IF_NAME, ftmin->ip, ftmin->ifIndex, ftmin->name)) < 0)
        goto ftio_write_header_out;
      else
        head_off_d += n;
    }
  }

  if (ftio->fth.fields & FT_FIELD_IF_ALIAS) {
    FT_LIST_FOREACH(ftmia, &ftio->fth.ftmap->ifalias, chain) {
      if ((n = fttlv_enc_ifalias(enc_buf+head_off_d, len-head_off_d,
        flip, FT_TLV_IF_ALIAS, ftmia->ip, ftmia->ifIndex_list, ftmia->entries,
          ftmia->name)) < 0)
        goto ftio_write_header_out;
      else
        head_off_d += n;
    }
  }

  /* head_off_d must be longword aligned */
  if (head_off_d & 0x00000003)
    head_off_d = (head_off_d & 0xFFFFFFFC) + 4;

  /* if rewriting, ensure header area has not grown or shrunk */
  if (restore) {
    if (head_off_d != ftio->fth.size) {
      fterr_warnx("Header size change during rewrite not supported");
      goto ftio_write_header_out;
    }
  }

  /* byte order of target */
  if (flip)
    SWAPINT32(head_off_d);

  /* encode offset to data */
  bcopy(&head_off_d, enc_buf+sizeof head_gen, sizeof head_off_d);

  /* restore */
  if (flip)
    SWAPINT32(head_off_d);

  n = writen(ftio->fd, enc_buf, head_off_d);

  if (n < 0) {
    fterr_warn("writen()");
    goto ftio_write_header_out;
  }

  if (n == 0) {
    fterr_warnx("writen(): EOF");
    goto ftio_write_header_out;
  }

  /* flag header has been written */
  ftio->flags |= FT_IO_FLAG_HEADER_DONE;

  /* save write size */
  ftio->fth.size = head_off_d;

  ret = n;

ftio_write_header_out:

  if (restore) {

    if (lseek(ftio->fd, (off_t)0L, SEEK_END) == -1) {
      fterr_warn("lseek()");
    }

  }

  if (enc_buf)
    free(enc_buf);

  return ret;

}

/*
 * function: ftio_write
 *
 * Schedule fts3rec_* for output.  ftio_write_header() must be called
 * on a stream before ftio_write().  If ftio_close() is not called
 * records may not be written.
 *
 * Stream must be first initialized with ftio_init() 
 *
 * returns: <0   error
 *          >= 0 okay
 *
 */
int ftio_write(struct ftio *ftio, void *data)
{
  int ret, n, nbytes;

  ret = -1;
  nbytes = 0;
 
  if (!(ftio->flags & FT_IO_FLAG_NO_SWAP)) {
#if BYTE_ORDER == BIG_ENDIAN
    if (ftio->fth.byte_order == FT_HEADER_LITTLE_ENDIAN)
      ftio->swapf((void*)data);
#endif /* BYTE_ORDER == BIG_ENDIAN */

#if BYTE_ORDER == LITTLE_ENDIAN
    if (ftio->fth.byte_order == FT_HEADER_BIG_ENDIAN)
      ftio->swapf((void*)data);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
  }

  /* compressed stream? */
  if (ftio->fth.flags & FT_HEADER_FLAG_COMPRESS) {

    ftio->zs.next_in = (Bytef*)data;
    ftio->zs.avail_in = ftio->rec_size;

    while (1) {

      if (deflate(&ftio->zs, Z_NO_FLUSH) != Z_OK) {
        fterr_warnx("deflate(): failed");
        goto ftio_write_out;
      }

      /* need to flush */
      if (!ftio->zs.avail_out) {

        n = writen(ftio->fd, ftio->z_buf, FT_Z_BUFSIZE);

        if (n < 0) {
          fterr_warn("writen()");
          goto ftio_write_out;
        }

        if (n == 0) {
          fterr_warnx("writen(): EOF");
          goto ftio_write_out;
        }

        ftio->zs.next_out = (Bytef*)ftio->z_buf;
        ftio->zs.avail_out = FT_Z_BUFSIZE;

        nbytes += n;

        ret = 0; /* success */

      } else {

        ret = 0; /* success */
        break;

      }

    } /* deflating */

  /* no, uncompressed stream */

  } else {

    /* flush full buffer */
    if ((ftio->d_start + ftio->rec_size) > ftio->d_end) {

      n = writen(ftio->fd, ftio->d_buf, ftio->d_start);

      if (n < 0) {
        fterr_warn("writen()");
        goto ftio_write_out;
      }

      if (n == 0) {
        fterr_warnx("writen(): EOF");
        goto ftio_write_out;
      }

      ftio->d_start = 0;

      nbytes += n;

    }

    bcopy(data, ftio->d_buf+ftio->d_start, ftio->rec_size);

    ftio->d_start += ftio->rec_size;

    ret = 0; /* success */

  }

ftio_write_out:

  if (!(ftio->flags & FT_IO_FLAG_NO_SWAP)) {
#if BYTE_ORDER == BIG_ENDIAN
    if (ftio->fth.byte_order == FT_HEADER_LITTLE_ENDIAN)
      ftio->swapf((void*)data);
#endif /* BYTE_ORDER == BIG_ENDIAN */

#if BYTE_ORDER == LITTLE_ENDIAN
    if (ftio->fth.byte_order == FT_HEADER_BIG_ENDIAN)
      ftio->swapf((void*)data);
#endif /* BYTE_ORDER == LITTLE_ENDIAN */
  }

  if (ret < 0)
    return ret;
  else
    return nbytes;

} /* ftio_write */

static size_t strftime_tz(char *s, size_t max, const time_t timeval) {
  struct tm tm_struct;

  return strftime(s, max, "%a, %d %b %Y %H:%M:%S %z", localtime_r(&timeval, &tm_struct));
}

static void fprintf_time(FILE *std, char *format, char cc, const time_t timeval) {
  char timebuf[128];

  strftime_tz(timebuf, sizeof(timebuf), timeval);

  fprintf(std, format, cc, timebuf);
}

/*
 * function: ftio_header_print
 *
 * Dump ftio header in readable format
 *
 * Stream must be first initialized with ftio_init() 
 *
 */
void ftio_header_print(struct ftio *ftio, FILE *std, char cc)
{
  struct ftiheader *fth;
  struct ftmap_ifname *ftmin;
  struct ftmap_ifalias *ftmia;
  char agg_ver, agg_method;
  char *agg_name;
  char fmt_buf[32];
  uint32_t flags, fields;
  uint32_t period;
  int n, streaming2;

  fth = &ftio->fth;

  fields = ftio->fth.fields;

  if (fields & FT_FIELD_HEADER_FLAGS)
    flags = ftio->fth.flags;
  else 
    flags = 0;

  streaming2 = (flags & FT_HEADER_FLAG_STREAMING);
  if (flags & FT_HEADER_FLAG_PRELOADED)
    streaming2 = 0;

  if (flags & FT_HEADER_FLAG_STREAMING)
    fprintf(std, "%c\n%c mode:                 streaming\n", cc, cc);
  else
    fprintf(std, "%c\n%c mode:                 normal\n", cc, cc);

  if (flags & FT_HEADER_FLAG_XLATE)
    fprintf(std, "%c translated:           yes\n", cc);

  if (!(flags & FT_HEADER_FLAG_STREAMING))
    if (fields & FT_FIELD_CAP_HOSTNAME)
      fprintf(std, "%c capture hostname:     %s\n", cc, fth->cap_hostname);

  if (!(flags & FT_HEADER_FLAG_STREAMING)) {
    if (fields & FT_FIELD_EXPORTER_IP) {
      fmt_ipv4(fmt_buf, fth->exporter_ip, FMT_JUST_LEFT);
      fprintf(std, "%c exporter IP address:  %s\n", cc, fmt_buf);
    }
  }

  if ((!streaming2) && (fields & FT_FIELD_CAP_START))
    fprintf_time(std, "%c capture start:        %s\n", cc, ftio_get_cap_start_time_t(ftio));

  if (!streaming2) {
    if ((flags & FT_HEADER_FLAG_DONE) || (flags & FT_HEADER_FLAG_PRELOADED)) {
      if (fields & FT_FIELD_CAP_END)
        fprintf_time(std, "%c capture end:          %s\n", cc, ftio_get_cap_end_time_t(ftio));

      if ((fields & FT_FIELD_CAP_END) && (fields & FT_FIELD_CAP_START)) {
        period = fth->cap_end - fth->cap_start;
        fprintf(std, "%c capture period:       %" PRIu32 " seconds\n", cc, period);
      }
    }
  }

  fprintf(std, "%c compress:             %s\n", cc, 
    (flags & FT_HEADER_FLAG_COMPRESS) ? "on" : "off");

  fprintf(std, "%c byte order:           ", cc);
  if (fth->byte_order == FT_HEADER_LITTLE_ENDIAN)
    fprintf(std, "little\n");
  else if (fth->byte_order == FT_HEADER_BIG_ENDIAN)
    fprintf(std, "big\n");
  else
    fprintf(std, "BROKEN\n");

/*
  if (!(flags & FT_HEADER_FLAG_STREAMING))
    fprintf(std, "%c multiple pdu types:   %s\n", cc,
      (fth->flags & FT_HEADER_FLAG_MULT_PDU) ? "yes" : "no");
 */

  fprintf(std, "%c stream version:       %u\n", cc, (int)fth->s_version);

  if (fields & FT_FIELD_EX_VER)
    fprintf(std, "%c export version:       %u\n", cc, (int)fth->d_version);

  if ((fields & FT_FIELD_EX_VER) && (fields & FT_FIELD_AGG_METHOD)) {

    if (fth->d_version == 8) {

      agg_ver = ftio->fth.agg_version;
      agg_method = ftio->fth.agg_method;

      switch (agg_method) {

        case 1:
          agg_name = "AS";
          break;

        case 2:
          agg_name = "Protocol Port";
          break;

        case 3:
          agg_name = "Source Prefix";
          break;

        case 4:
          agg_name = "Destination Prefix";
          break;

        case 5:
          agg_name = "Prefix";
          break;

        case 6:
          agg_name = "Destination";
          break;

        case 7:
          agg_name = "Source Destination";
          break;

        case 8:
          agg_name = "Full Flow";
          break;

        case 9:
          agg_name = "ToS AS";
          break;

        case 10:
          agg_name = "ToS Proto Port";
          break;

        case 11:
          agg_name = "ToS Source Prefix";
          break;

        case 12:
          agg_name = "ToS Destination Prefix";
          break;

        case 13:
          agg_name = "ToS Prefix";
          break;

        case 14:
          agg_name = "ToS Prefix Port";
          break;

        default:
          agg_name = "Unknown";

      } /* switch */

    if (fields & FT_FIELD_AGG_VER)
      fprintf(std, "%c export agg_version:   %u\n", cc, (int)agg_ver);

    fprintf(std, "%c export agg_method:    %u (%s)\n", cc, (int)agg_method,
      agg_name);

    }
  }

  if (!streaming2)
    if (fields & FT_FIELD_FLOW_LOST)
      fprintf(std, "%c lost flows:           %" PRIu32 "\n", cc,
        (uint32_t)fth->flows_lost);

  if (!streaming2)
    if (fields & FT_FIELD_FLOW_MISORDERED)
      fprintf(std,
        "%c misordered flows:     %" PRIu32 "\n", cc, (uint32_t)fth->flows_misordered);

  if (!streaming2)
    if (fields & FT_FIELD_PKT_CORRUPT)
      fprintf(std,
        "%c corrupt packets:      %" PRIu32 "\n", cc, (uint32_t)fth->pkts_corrupt);

  if (!streaming2)
    if (fields & FT_FIELD_SEQ_RESET)
      fprintf(std,
        "%c sequencer resets:     %" PRIu32 "\n", cc, (uint32_t)fth->seq_reset);

  if (fields & FT_FIELD_COMMENTS)
    fprintf(std, "%c comments:             %s\n", cc, fth->comments);
  
  if (!streaming2) {

    if ((flags & FT_HEADER_FLAG_DONE) || (flags & FT_HEADER_FLAG_PRELOADED)) {

      if (fields & FT_FIELD_FLOW_COUNT)
        fprintf(std, "%c capture flows:        %lu\n", cc,
          (unsigned long)fth->flows_count);

    } else
      fprintf(std, "%c note, incomplete flow file\n", cc);
  }

  if (fields & FT_FIELD_IF_NAME) {
    fprintf(std, "%c\n", cc);
    FT_LIST_FOREACH(ftmin, &fth->ftmap->ifname, chain) {
      fmt_ipv4(fmt_buf, ftmin->ip, FMT_JUST_LEFT);
      fprintf(std, "%c ifname %s %d %s\n", cc, fmt_buf, (int)ftmin->ifIndex,
        ftmin->name);
    }
  } /* FT_FIELD_IF_NAME */

  if (fields & FT_FIELD_IF_ALIAS) {
    fprintf(std, "%c\n", cc);
    FT_LIST_FOREACH(ftmia, &fth->ftmap->ifalias, chain) {
      fmt_ipv4(fmt_buf, ftmia->ip, FMT_JUST_LEFT);
      fprintf(std, "%c ifalias %s ", cc, fmt_buf);
      for (n = 0; n < ftmia->entries; ++n)
        fprintf(std, "%d ", (int)ftmia->ifIndex_list[n]);
      fprintf(std, "%s\n", ftmia->name);
    }
  } /* FT_FIELD_IF_ALIAS */

  fprintf(std, "%c\n", cc);

} /* ftio_header_print */

/*
 * function: ftio_rec_swapfunc
 *
 * Return the function required to swap a record.  Used to create
 * jump table based on the d_version and agg_method
 *
 */
void *ftio_rec_swapfunc(struct ftio *ftio)
{

  u_int8 s_ver, d_ver, agg_ver, agg_method;
  void *ret;

  s_ver = ftio->fth.s_version;
  d_ver = ftio->fth.d_version;

  agg_ver = ftio->fth.agg_version;
  agg_method = ftio->fth.agg_method;

  switch (s_ver) {

    case 1:
      ret = fts1rec_swap_compat;
      break;

    case 3:
      switch (ftio->fth.d_version) {

        case 1:
          ret = fts3rec_swap_v1;
          break;

        case 5:
          ret = fts3rec_swap_v5;
          break;

        case 6:
          ret = fts3rec_swap_v6;
          break;

        case 7:
          ret = fts3rec_swap_v7;
          break;

        case 8:
          if (agg_ver != 2) {
            fterr_warnx("Unsupported agg_version %d", (int)agg_ver);
            ret = (void*)0L;
            break;
          }

          switch (agg_method) {

            case 1:
              ret = fts3rec_swap_v8_1;
              break;

            case 2:
              ret = fts3rec_swap_v8_2;
              break;

            case 3:
              ret = fts3rec_swap_v8_3;
              break;

            case 4:
              ret = fts3rec_swap_v8_4;
              break;

            case 5:
              ret = fts3rec_swap_v8_5;
              break;

            case 6:
              ret = fts3rec_swap_v8_6;
              break;

            case 7:
              ret = fts3rec_swap_v8_7;
              break;

            case 8:
              ret = fts3rec_swap_v8_8;
              break;

            case 9:
              ret = fts3rec_swap_v8_9;
              break;

            case 10:
              ret = fts3rec_swap_v8_10;
              break;

            case 11:
              ret = fts3rec_swap_v8_11;
              break;

            case 12:
              ret = fts3rec_swap_v8_12;
              break;

            case 13:
              ret = fts3rec_swap_v8_13;
              break;

            case 14:
              ret = fts3rec_swap_v8_14;
              break;

            default:
              fterr_warnx("Unsupported agg_method %d", (int)agg_method);
              ret = (void*)0L;
              break;

          } /* switch agg_method */
          break;

        case 1005:
          ret = fts3rec_swap_v1005;
          break;

        default:
          fterr_warnx("Unsupported d_version %d", (int)ftio->fth.d_version);
          ret = (void*)0L;
          break;

      } /* switch v8 export */
      break;

    default:
      fterr_warnx("Unsupported s_version %d", (int)s_ver);
      ret = (void*)0L;
      break;

  } /* switch s_version */

  return ret;

}

/*
 * function: ftrec_size
 *
 * Return the size of a fts3rec_* based on the d_version and agg_method
 *
 */
int ftrec_size(struct ftver *ver)
{

  int ret;

  switch (ver->s_version) {

    case 1:
      ret = sizeof (struct fts1rec_compat);
      break;

    case 3:
      switch (ver->d_version) {

        case 1:
          ret = sizeof (struct fts3rec_v1);
          break;

        case 5:
          ret = sizeof (struct fts3rec_v5);
          break;

        case 6:
          ret = sizeof (struct fts3rec_v6);
          break;

        case 7:
          ret = sizeof (struct fts3rec_v7);
          break;

        case 8:
          if (ver->agg_version != 2) {
            fterr_warnx("Unsupported agg_version %d", (int)ver->agg_version);
            ret = -1;
            break;
          }

          switch (ver->agg_method) {

            case 1:
              ret = sizeof (struct fts3rec_v8_1);
              break;

            case 2:
              ret = sizeof (struct fts3rec_v8_2);
              break;

            case 3:
              ret = sizeof (struct fts3rec_v8_3);
              break;

            case 4:
              ret = sizeof (struct fts3rec_v8_4);
              break;

            case 5:
              ret = sizeof (struct fts3rec_v8_5);
              break;

            case 6:
              ret = sizeof (struct fts3rec_v8_6);
              break;

            case 7:
              ret = sizeof (struct fts3rec_v8_7);
              break;

            case 8:
              ret = sizeof (struct fts3rec_v8_8);
              break;

            case 9:
              ret = sizeof (struct fts3rec_v8_9);
              break;

            case 10:
              ret = sizeof (struct fts3rec_v8_10);
              break;

            case 11:
              ret = sizeof (struct fts3rec_v8_11);
              break;

            case 12:
              ret = sizeof (struct fts3rec_v8_12);
              break;

            case 13:
              ret = sizeof (struct fts3rec_v8_13);
              break;

            case 14:
              ret = sizeof (struct fts3rec_v8_14);
              break;

            default:
              fterr_warnx("Unsupported agg_method %d", (int)ver->agg_method);
              ret = -1;
              break;

          } /* switch agg_method */
          break;

        case 1005:
          ret = sizeof (struct fts3rec_v1005);
          break;

        default:
          fterr_warnx("Unsupported d_version %d", (int)ver->d_version);
          ret = -1;
          break;

      } /* switch v8 export */
      break;

    default:
      fterr_warnx("Unsupported s_version %d", (int)ver->s_version);
      ret = -1;
      break;

  } /* switch s_version */

  return ret;

}

/*
 * function: ftrec_xfield
 *
 * Return the FT_XFIELD* based on the d_version and agg_method
 *
 */
u_int64 ftrec_xfield(struct ftver *ver)
{

  u_int64 ret;

   switch (ver->d_version) {

     case 1:
       ret = FT_XFIELD_V1_MASK;
       break;

     case 5:
       ret = FT_XFIELD_V5_MASK;
       break;

     case 6:
       ret = FT_XFIELD_V6_MASK;
       break;

     case 7:
       ret = FT_XFIELD_V7_MASK;
       break;

     case 8:
       if (ver->agg_version != 2) {
         fterr_warnx("Unsupported agg_version %d", (int)ver->agg_version);
         ret = -1;
         break;
       }

       switch (ver->agg_method) {

         case 1:
           ret = FT_XFIELD_V8_1_MASK;
           break;

         case 2:
           ret = FT_XFIELD_V8_2_MASK;
           break;

         case 3:
           ret = FT_XFIELD_V8_3_MASK;
           break;

         case 4:
           ret = FT_XFIELD_V8_4_MASK;
           break;

         case 5:
           ret = FT_XFIELD_V8_5_MASK;
           break;

         case 6:
           ret = FT_XFIELD_V8_6_MASK;
           break;

         case 7:
           ret = FT_XFIELD_V8_7_MASK;
           break;

         case 8:
           ret = FT_XFIELD_V8_8_MASK;
           break;

         case 9:
           ret = FT_XFIELD_V8_9_MASK;
           break;

         case 10:
           ret = FT_XFIELD_V8_10_MASK;
           break;

         case 11:
           ret = FT_XFIELD_V8_11_MASK;
           break;

         case 12:
           ret = FT_XFIELD_V8_12_MASK;
           break;

         case 13:
           ret = FT_XFIELD_V8_13_MASK;
           break;

         case 14:
           ret = FT_XFIELD_V8_14_MASK;
           break;

         default:
           fterr_warnx("Unsupported agg_method %d", (int)ver->agg_method);
           ret = -1;
           break;

       } /* switch agg_method */
       break;

     case 1005:
       ret = FT_XFIELD_V1005_MASK;
       break;

     default:
       fterr_warnx("Unsupported d_version %d", (int)ver->d_version);
       ret = -1;
       break;

   } /* switch v8 export */

  return ret;

} /* ftrec_xfield */

/*
 * function: ftio_xfield
 *
 * Return the FT_XFIELD*
 *
 */
u_int64 ftio_xfield(struct ftio *ftio)
{
  struct ftver ver;

  ver.d_version = ftio->fth.d_version;
  ver.s_version = ftio->fth.s_version;
  ver.agg_method = ftio->fth.agg_method;
  ver.agg_version = ftio->fth.agg_version;

  return ftrec_xfield(&ver);
}

/*
 * function: ftio_rec_size
 *
 * Return the size of a fts3rec_* based on the initialized ftio
 * stream.
 *
 */
int ftio_rec_size(struct ftio *ftio)
{
  struct ftver ver;

  ver.d_version = ftio->fth.d_version;
  ver.s_version = ftio->fth.s_version;
  ver.agg_method = ftio->fth.agg_method;
  ver.agg_version = ftio->fth.agg_version;

  return ftrec_size(&ver);

} /* ftio_rec_size */


/*
 * function: readn
 *
 * read()'s n bytes from fd
 * returns # of butes read, or -1 for error
 */
int readn(register int fd, register void *ptr, register int nbytes)
{

  int nleft, nread;

  nleft = nbytes;
  while (nleft > 0) {
      nread = read(fd, ptr, nleft);
      if (nread < 0)
        return nread;
      else if (nread == 0)
        break;

      nleft -= nread;
      ptr = (char*)ptr + nread;
  }
  return (nbytes - nleft);
} /* readn */


/* From Stevens
 *
 * function: writen
 *
 *  write()'s n bytes to fd.
 *  returns # of bytes written, or -1 for error
 */
int writen(register int fd, register void *ptr, register int nbytes)
{

  int nleft, nwritten;

  nleft = nbytes;
  while (nleft > 0) {
    nwritten = write(fd, ptr, nleft);
    if (nwritten <= 0)
      return(nwritten); /* error */

    nleft -= nwritten;
    ptr = (char*)ptr + nwritten;
  }
  return(nbytes - nleft);
} /* writen */

/*
 * function: ftiheader_read
 *
 * load a ftheader, possibly converting from an older version
 *
 * header is returned in host byte order
 *
 * returns: <0   error
 *          >= 0 okay
 */
int ftiheader_read(int fd, struct ftiheader *ihead)
{
  struct fts1header *h1;
  struct ftheader_gen head_gen;
  struct fttlv tlv;
  struct ftmap_ifname *ftmin;
  struct ftmap_ifalias *ftmia;
  int n, ret, len_read, len_buf, off, flip, left;
  u_int32 ip;
  u_int16 entries, ifIndex, *ifIndex_list;
  u_int32 head_off_d;
  char *dp, *c, *enc_buf;

  ret = -1; 
  enc_buf = (char*)0L;
  ifIndex_list = (u_int16*)0L;
  bzero(ihead, sizeof (struct ftiheader));

  /* read the stream header version area */
  if ((n = readn(fd, (char*)&head_gen, sizeof head_gen)) < 0) {
    fterr_warn("read()");
    goto ftiheader_read_out;
  }

  if (n != sizeof head_gen) {
    fterr_warnx(
      "ftiheader_read(): Warning, short read while loading header top.");
    goto ftiheader_read_out;
  }
        
  /* verify magic */
  if ((head_gen.magic1 != FT_HEADER_MAGIC1) ||   
      (head_gen.magic2 != FT_HEADER_MAGIC2)) {
      fterr_warnx("ftiheader_read(): Warning, bad magic number");
      goto ftiheader_read_out;
  }

#if BYTE_ORDER == BIG_ENDIAN
    if (head_gen.byte_order == FT_HEADER_LITTLE_ENDIAN)
      flip = 1;
    else
      flip = 0;
#endif /* BYTE_ORDER == BIG_ENDIAN */

#if BYTE_ORDER == LITTLE_ENDIAN
    if (head_gen.byte_order == FT_HEADER_BIG_ENDIAN)
      flip = 1;
    else
      flip = 0;
#endif /* BYTE_ORDER == LITTLE_ENDIAN */


  /* determine how many bytes to read */
  if (head_gen.s_version == 1) {

    /* v1 header size static */
    len_read = (sizeof (struct fts1header)) - sizeof head_gen;
    len_buf = sizeof (struct fts1header);

  } else if (head_gen.s_version == 3) {

    /* read the version 3 index */
    if ((n = readn(fd, (char*)&head_off_d, sizeof head_off_d)) < 0) {
      fterr_warn("read()");
      goto ftiheader_read_out;
    }

    if (n != sizeof head_off_d) {
      fterr_warnx(
        "ftiheader_read(): Error, short read while loading header data offset.");
      goto ftiheader_read_out;
    }

    /* data offset must be in host byte order */
    if (flip)
      SWAPINT32(head_off_d);

    /* v3 dynamic header size */
    len_read = head_off_d - sizeof head_gen - sizeof head_off_d;
    len_buf = len_read + sizeof head_gen + sizeof head_off_d;

  } else {
    fterr_warnx("Stream format must be 1 or 3, not %d",
      (int)head_gen.s_version);
      goto ftiheader_read_out;
  }

  /* allocate storage for decode */
  if (!(enc_buf = (char*)malloc(len_buf))) {
    fterr_warn("malloc()");
    goto ftiheader_read_out;
  }

  ihead->enc_len = len_buf;

  /* insert the generic part to the top of the buffer */
  bcopy(&head_gen, enc_buf, sizeof head_gen);
  off = sizeof head_gen;

  /* for version 3 insert the data offset */
  if (head_gen.s_version == 3) {
    bcopy(&head_off_d, enc_buf+off, sizeof head_off_d);
    off += sizeof head_off_d;
  }

  /* read the rest of the header */
  if ((n = readn(fd, (char*)enc_buf+off, len_read)) < 0) {
    fterr_warn("read()");
    goto ftiheader_read_out;
  }

  if (n != len_read) {
    fterr_warnx("Short read while loading header");
    goto ftiheader_read_out;
  }

  /* v1 header? yes, convert it directly to internal format */
  if (head_gen.s_version == 1) {

    h1 = (struct fts1header*) enc_buf;

    ihead->magic1 = h1->magic1;
    ihead->magic2 = h1->magic2;
    ihead->byte_order = h1->byte_order;
    ihead->s_version = h1->s_version;
    ihead->d_version = h1->d_version;
    ihead->cap_start = h1->start;
    ihead->cap_end = h1->end;
    ihead->flags = h1->flags;
    ihead->rotation = h1->rotation;
    ihead->flows_count = h1->nflows;
    ihead->flows_lost = h1->pdu_drops;
    ihead->flows_misordered = h1->pdu_misordered;

    /* translated from v1 */
    ihead->flags |= FT_HEADER_FLAG_XLATE;

    ihead->fields = FT_FIELD_VENDOR | FT_FIELD_EX_VER | FT_TLV_CAP_START |
      FT_TLV_CAP_END | FT_FIELD_HEADER_FLAGS | FT_FIELD_ROT_SCHEDULE |
      FT_FIELD_FLOW_COUNT;

    /* convert to host byte order */
    if (flip) {
      SWAPINT16(ihead->d_version);
      SWAPINT32(ihead->cap_start);
      SWAPINT32(ihead->cap_end);
      SWAPINT32(ihead->flags);
      SWAPINT32(ihead->rotation);
      SWAPINT32(ihead->flows_count);
      SWAPINT32(ihead->exporter_ip);
      SWAPINT32(ihead->flows_lost);
      SWAPINT32(ihead->flows_misordered);
      SWAPINT32(ihead->pkts_corrupt);
      SWAPINT32(ihead->seq_reset);
    } /* flip */

    if (h1->hostname[0]) {

      if (!(ihead->cap_hostname = (char*)malloc(FT_HEADER1_HN_LEN))) {
        fterr_warn("malloc()");
        goto ftiheader_read_out;
      }

      strcpy(ihead->cap_hostname, h1->hostname);

      ihead->fields |= FT_FIELD_CAP_HOSTNAME;

    }

    if (h1->comments[0]) {

      if (!(ihead->comments = (char*)malloc(FT_HEADER1_CMNT_LEN))) {
        fterr_warn("malloc()");
        goto ftiheader_read_out;
      }

      strcpy(ihead->comments, h1->comments);

      ihead->fields |= FT_FIELD_COMMENTS;

    }


  } else if (head_gen.s_version == 3) {

    /* set decode pointer to first tlv */
    dp = enc_buf + sizeof head_gen + sizeof head_off_d;
    left = len_read;

    /* copy generic header to internal */
    ihead->magic1 = head_gen.magic1;
    ihead->magic2 = head_gen.magic2;
    ihead->byte_order = head_gen.byte_order;
    ihead->s_version = head_gen.s_version;

    /* smallest TLV is 2+2+0 (null TLV).  Don't try to read padding added
     * for alignment.
     */
    while (left >= 4) {

      /* parse type, store in host byte order */
      bcopy(dp, &tlv.t, 2);
      if (flip)
        SWAPINT16(tlv.t);
      dp += 2;
      left -= 2;

      /* parse len, store in host byte order */
      bcopy(dp, &tlv.l, 2);
      if (flip)
        SWAPINT16(tlv.l);
      dp += 2;
      left -= 2;

      /* parse val */
      tlv.v = dp;

      /* point decode buf at next tlv */
      dp += tlv.l;
      left -= tlv.l;

      /* TLV length sane? */
      if (left < 0)
        break;

      switch (tlv.t) {

        case FT_TLV_NULL:
          break;

        case FT_TLV_VENDOR:
          bcopy(tlv.v, &ihead->vendor, 2);
          if (flip) SWAPINT16(ihead->vendor);
          ihead->fields |= FT_FIELD_VENDOR;
          break;

        case FT_TLV_EX_VER:
          bcopy(tlv.v, &ihead->d_version, 2);
          if (flip) SWAPINT16(ihead->d_version);
          ihead->fields |= FT_FIELD_EX_VER;
          break;

        case FT_TLV_AGG_VER:
          bcopy(tlv.v, &ihead->agg_version, 1);
          ihead->fields |= FT_FIELD_AGG_VER;
          break;

        case FT_TLV_AGG_METHOD:
          bcopy(tlv.v, &ihead->agg_method, 1);
          ihead->fields |= FT_FIELD_AGG_METHOD;
          break;

        case FT_TLV_EXPORTER_IP:
          bcopy(tlv.v, &ihead->exporter_ip, 4);
          if (flip) SWAPINT32(ihead->exporter_ip);
          ihead->fields |= FT_FIELD_EXPORTER_IP;
          break;

        case FT_TLV_CAP_START:
          bcopy(tlv.v, &ihead->cap_start, 4);
          if (flip) SWAPINT32(ihead->cap_start);
          ihead->fields |= FT_FIELD_CAP_START;
          break;

        case FT_TLV_CAP_END:
          bcopy(tlv.v, &ihead->cap_end, 4);
          if (flip) SWAPINT32(ihead->cap_end);
          ihead->fields |= FT_FIELD_CAP_END;
          break;

        case FT_TLV_HEADER_FLAGS:
          bcopy(tlv.v, &ihead->flags, 4);
          if (flip) SWAPINT32(ihead->flags);
          ihead->fields |= FT_FIELD_HEADER_FLAGS;
          break;

        case FT_TLV_ROT_SCHEDULE:
          bcopy(tlv.v, &ihead->rotation, 4);
          if (flip) SWAPINT32(ihead->rotation);
          ihead->fields |= FT_FIELD_ROT_SCHEDULE;
          break;

        case FT_TLV_FLOW_COUNT:
          bcopy(tlv.v, &ihead->flows_count, 4);
          if (flip) SWAPINT32(ihead->flows_count);
          ihead->fields |= FT_FIELD_FLOW_COUNT;
          break;

        case FT_TLV_FLOW_LOST:
          bcopy(tlv.v, &ihead->flows_lost, 4);
          if (flip) SWAPINT32(ihead->flows_lost);
          ihead->fields |= FT_FIELD_FLOW_LOST;
          break;

        case FT_TLV_FLOW_MISORDERED:
          bcopy(tlv.v, &ihead->flows_misordered, 4);
          if (flip) SWAPINT32(ihead->flows_misordered);
          ihead->fields |= FT_FIELD_FLOW_MISORDERED;
          break;

        case FT_TLV_PKT_CORRUPT:
          bcopy(tlv.v, &ihead->pkts_corrupt, 4);
          if (flip) SWAPINT32(ihead->pkts_corrupt);
          ihead->fields |= FT_FIELD_PKT_CORRUPT;
          break;

        case FT_TLV_SEQ_RESET:
          bcopy(tlv.v, &ihead->seq_reset, 4);
          if (flip) SWAPINT32(ihead->seq_reset);
          ihead->fields |= FT_FIELD_SEQ_RESET;
          break;

        case FT_TLV_CAP_HOSTNAME:
          if (!(ihead->cap_hostname = (char*)malloc(tlv.l))) {
            fterr_warn("malloc()");
            goto ftiheader_read_out;
          }
          strcpy(ihead->cap_hostname, tlv.v);
          ihead->fields |= FT_FIELD_CAP_HOSTNAME;
          break;

        case FT_TLV_COMMENTS:
          if (!(ihead->comments = (char*)malloc(tlv.l))) {
            fterr_warn("malloc()");
            goto ftiheader_read_out;
          }
          strcpy(ihead->comments, tlv.v);
          ihead->fields |= FT_FIELD_COMMENTS;
          break;

        case FT_TLV_IF_NAME:
          if (!ihead->ftmap) {
            if (!(ihead->ftmap = ftmap_new())) {
              fterr_warnx("ftmap_new(): failed");
              goto ftiheader_read_out;
            }
          }

          ihead->fields |= FT_FIELD_IF_NAME;

          /* decode the value */
          bcopy(tlv.v, &ip, 4);
          if (flip) SWAPINT32(ip);
          bcopy(tlv.v+4, &ifIndex, 2);
          if (flip) SWAPINT32(ifIndex);
          c = tlv.v+6;

          /* allocate space for a ifname */
          if (!(ftmin = ftmap_ifname_new(ip, ifIndex, c))) {
            fterr_warnx("ftmap_ifname_new(): failed");
            goto ftiheader_read_out;
          }

          /* and link it in */
          FT_LIST_INSERT_HEAD(&ihead->ftmap->ifname, ftmin, chain);
          break;

        case FT_TLV_IF_ALIAS:
          if (!ihead->ftmap) {
            if (!(ihead->ftmap = ftmap_new())) {
              fterr_warnx("ftmap_new(): failed");
              goto ftiheader_read_out;
            }
          }
          ihead->fields |= FT_FIELD_IF_ALIAS;

          /* decode the value */
          bcopy(tlv.v, &ip, 4);
          if (flip) SWAPINT32(ip);
          bcopy(tlv.v+4, &entries, 2);
          if (flip) SWAPINT32(entries);
          c = tlv.v+6 + (entries*2);

          if (!(ifIndex_list = (u_int16*)malloc(entries*2))) {
            fterr_warn("malloc()");
            goto ftiheader_read_out;
          }

          bcopy(tlv.v+6, ifIndex_list, entries*2);

          /* allocate space for a ifname */
          if (!(ftmia = ftmap_ifalias_new(ip, ifIndex_list, entries, c))) {
            fterr_warnx("ftmap_ifalias_new(): failed");
            goto ftiheader_read_out;
          }

          free(ifIndex_list);
          ifIndex_list = (u_int16*)0L;

          /* and link it in */
          FT_LIST_INSERT_HEAD(&ihead->ftmap->ifalias, ftmia, chain);
          break;

        default:
          break;

      } /* switch */

    } /* while */

  } /* s_version == 3 */

  ret = 0;

ftiheader_read_out:

  if (ifIndex_list)
    free(ifIndex_list);

  if (enc_buf)
    free(enc_buf);

  return ret;

} /* ftiheader_read */


/*
 * function: ftio_check_generic
 *
 * check if this io stream can be used with the ftstrec_gen
 * pseudo record.  fts3rec_gen overlays the common fields of
 * v1, v5, v6, and v7 formats
 *
 * returns: <0   error
 *          >= 0 okay
 */
int ftio_check_generic(struct ftio *ftio)
{
  struct ftver ver;

  ftio_get_ver(ftio, &ver);
 
  if ((ver.d_version != 1) &&
    (ver.d_version != 5) &&
    (ver.d_version != 6) &&
    (ver.d_version != 7)) {
    fterr_warnx("Export version %d not supported by format",
      (int)ver.d_version);
    return -1;
  }

  return 0;
} /* ftio_check_generic */

/*
 * function: ftio_check_generic5
 *
 * check if this io stream can be used with the ftstrec_gen
 * pseudo record.  fts3rec_gen overlays the common fields of
 * v5, v6, and v7 formats
 *
 * returns: <0   error
 *          >= 0 okay
 */
int ftio_check_generic5(struct ftio *ftio)
{
  struct ftver ver;

  ftio_get_ver(ftio, &ver);
 
  if ((ver.d_version != 5) &&
    (ver.d_version != 6) &&
    (ver.d_version != 7)) {
    fterr_warnx("Export version %d not supported by format",
      (int)ver.d_version);
    return -1;
  }

  return 0;
} /* ftio_check_generic5 */

/*
 * function: ftltime
 *
 * Flow exports represent time with a combination of uptime of the
 * router, real time, and offsets from the router uptime.  ftltime
 * converts from the PDU to a standard unix seconds/milliseconds
 * representation
 *
 * returns: struct fttime
 */
struct fttime ftltime(u_int32 sys, u_int32 secs, u_int32 nsecs, u_int32 t)
{

  u_int32 sys_s, sys_m;
  struct fttime ftt;

  /* sysUpTime is in milliseconds, convert to seconds/milliseconds */
  sys_s = sys / 1000;
  sys_m = sys % 1000;

  /* unix seconds/nanoseconds to seconds/milliseconds */
  ftt.secs = secs;
  ftt.msecs = nsecs / 1000000L;

  /* subtract sysUpTime from unix seconds */
  ftt.secs -= sys_s;

  /* borrow a second? */
  if (sys_m > ftt.msecs) {
    -- ftt.secs;
    ftt.msecs += 1000;
  }
  ftt.msecs -= sys_m;

  /* add offset which is in milliseconds */
  ftt.secs += t / 1000;
  ftt.msecs += t % 1000;

  /* fix if milliseconds >= 1000 */
  if (ftt.msecs >= 1000) {
    ftt.msecs -= 1000;
    ftt.secs += 1;
  }

  return ftt;

} /* ftltime */

/*
 * function: ftset_init
 *
 * initialize default settings
 *
 * returns: initialized ftset
 */
void ftset_init(struct ftset *ftset, int z_level)
{

  bzero(ftset, sizeof (struct ftset));
  ftset->z_level = z_level;

#if BYTE_ORDER == BIG_ENDIAN
  ftset->byte_order = FT_HEADER_BIG_ENDIAN;
#endif /* BYTE_ORDER == BIG_ENDIAN */
#if BYTE_ORDER == LITTLE_ENDIAN
  ftset->byte_order = FT_HEADER_LITTLE_ENDIAN;
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

} /* ftset_init */

int ftio_map_load(struct ftio *ftio, char *fname, u_int32 ip)
{

  /* load the map */
  if (!(ftio->fth.ftmap = ftmap_load(fname, ip))) {
    fterr_warnx("ftmap_load(): failed");
    return -1;
  }

  ftio->fth.fields |= FT_FIELD_IF_NAME | FT_FIELD_IF_ALIAS;

  return 0;

} /* ftio_map_load */

int ftio_interrupt(struct ftio *ftio, u_int32 fields)
{
  struct ftmap_ifname *ftmin;
  struct ftmap_ifalias *ftmia;
  u_int32 offset, oflag;
  char *enc_buf, *rec_buf;
  int len, n, ret, flip;

  enc_buf = rec_buf = (char*)0L;
  ret = -1;

  /* disable ftio_write() from swapping bytes */
  oflag = ftio->flags;
  ftio->flags |= FT_IO_FLAG_NO_SWAP;

  /* allocate space for TLV's */
  if (!(enc_buf = (char*)malloc(FT_IO_MAXHEADER))) {
    fterr_warnx("malloc()");
    goto ftio_interrupt_out;
  }

  /* allocate space for fake flow record */
  if (!(rec_buf = (char*)malloc(ftio->rec_size))) {
    fterr_warnx("malloc()");
    goto ftio_interrupt_out;
  }

#if BYTE_ORDER == BIG_ENDIAN
    if (ftio->fth.byte_order == FT_HEADER_LITTLE_ENDIAN)
      flip = 1;
    else
      flip = 0;
#endif /* BYTE_ORDER == BIG_ENDIAN */

#if BYTE_ORDER == LITTLE_ENDIAN
    if (ftio->fth.byte_order == FT_HEADER_BIG_ENDIAN)
      flip = 1;
    else
      flip = 0;
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

  offset = 0;
  len = FT_IO_MAXHEADER;

  if (fields & FT_FIELD_IF_NAME) {
    FT_LIST_FOREACH(ftmin, &ftio->fth.ftmap->ifname, chain) {
      if ((n = fttlv_enc_ifname(enc_buf+offset, len-offset,
        flip, FT_TLV_IF_NAME, ftmin->ip, ftmin->ifIndex, ftmin->name)) < 0)
        goto ftio_interrupt_out;
      else
        offset += n;
    }
  }
        
  if (fields & FT_FIELD_IF_ALIAS) {
    FT_LIST_FOREACH(ftmia, &ftio->fth.ftmap->ifalias, chain) {
      if ((n = fttlv_enc_ifalias(enc_buf+offset, len-offset,
        flip, FT_TLV_IF_ALIAS, ftmia->ip, ftmia->ifIndex_list, ftmia->entries,
          ftmia->name)) < 0)
        goto ftio_interrupt_out;
      else
        offset += n;
    }
  }

  if (ftio->fth.fields & FT_FIELD_INTERRUPT) {
    if ((n = fttlv_enc_uint8(enc_buf+offset, len-offset,
      flip, FT_TLV_INTERRUPT, (u_int8)0)) < 0)
      goto ftio_interrupt_out;
    else
      offset += n;
  }

  /* bytes 0-15 are 0xFF */
  memset(enc_buf, 0xFF, (size_t)16);

  if (flip)
    SWAPINT32(offset);

  /* bytes 16-20 of interrupt flow record are the bytes to follow */
  bcopy(enc_buf+16, &offset, 4);

  if (flip)
    SWAPINT32(offset);

  /* schedule the interrupt record for writing */
  if (ftio_write(ftio, rec_buf) < 0) {
    fterr_warnx("ftio_write(): failed");
    goto ftio_interrupt_out;
  }

  ret = 0;

ftio_interrupt_out:

  /* restore ftio->flags */
  ftio->flags = oflag;

  if (enc_buf)
    free(enc_buf);

  if (rec_buf)
    free(rec_buf);

  return ret;

} /* ftio_interrupt */

/*
 * function: ftio_check_xfield
 *
 * Check if xfield_need bits are available in stream
 *
 * returns: 0  ok
 *          != fail - a field required is not available.
 */
int ftio_check_xfield(struct ftio *ftio, u_int64 xfield_need)
{

  if ((xfield_need & ftio->xfield) != xfield_need)
    return -1;
  else
    return 0;

} /* ftio_xfields */

