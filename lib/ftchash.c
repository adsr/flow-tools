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
 *      $Id: ftchash.c,v 1.14 2003/08/12 18:04:25 maf Exp $
 */

#include "ftconfig.h"
#include "ftlib.h"

#include <stdlib.h>
#include <stddef.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

int sort_offset;
static int cmp64(const void *a, const void *b);
static int cmp40(const void *a, const void *b);
static int cmp32(const void *a, const void *b);
static int cmp16(const void *a, const void *b);
static int cmp8(const void *a, const void *b);
static int cmp_double(const void *a, const void *b);

/*
 * function: ftchash_new
 *
 *   allocate and initialize new hash structure.
 *
 *   h_size -        size of hash table (number of buckets)
 *   d_size -        size of data record (multiple of long word byte alignment)
 *   key_size -      size of key
 *   chunk_entries - number of data entries per chunk
 *  
 * returns allocated structure or 0L for error.
 *
 */
struct ftchash *ftchash_new(int h_size, int d_size, int key_size,
  int chunk_entries)
{
  struct ftchash *ftch;
  int i;

  /* allocate ftchash */
  if (!(ftch = (struct ftchash*)malloc(sizeof (struct ftchash)))) {
    fterr_warn("malloc()");
    return ftch;
  }

  /* init */
  bzero(ftch, sizeof (struct ftchash));
  ftch->h_size = h_size;
  ftch->d_size = d_size;
  ftch->key_size = key_size;
  ftch->chunk_size = chunk_entries * d_size;
  FT_SLIST_INIT(&ftch->chunk_list);

  /* allocate h_size buckets */
  if (!(ftch->buckets = (struct ftchash_bhead*)malloc(
    sizeof (struct ftchash_bhead)*h_size))) {
    fterr_warn("malloc()");
    free (ftch);
    return (struct ftchash*)0L;
  }

  /* init buckets */
  for (i = 0; i < h_size; ++i)
    FT_SLIST_INIT(&(*ftch).buckets[i]);

  return ftch;

} /* ftchash_new */

/*
 * function: ftchash_free
 *
 *   free storage allocated with ftchash_new
 */
void ftchash_free(struct ftchash *ftch)
{
  struct ftchash_chunk *chunk;

  if (ftch) {

    if (ftch->buckets)
      free (ftch->buckets);

    if (ftch->sorted_recs)
      free (ftch->sorted_recs);

    while ((chunk = FT_SLIST_FIRST(&ftch->chunk_list))) {
      FT_SLIST_REMOVE_HEAD(&ftch->chunk_list, chain);
      free (chunk->base);
      free (chunk);
    }
 
    free (ftch);
  }
} /* ftchash_free */

/*
 * function: ftchash_lookup
 *
 *   lookup record in hash table
 *
 *   returns pointer to record found or
 *           *0L if not found
 */
void *ftchash_lookup(struct ftchash *ftch, void *key, uint32_t hash)
{

  struct ftchash_rec_gen *rec;
  struct ftchash_bhead *bhead;
  int keyoff;

  /* offset to key */
  keyoff = offsetof(struct ftchash_rec_gen, data);

  /* lookup hash entry */
  bhead = &(*ftch).buckets[hash];

  /* walk down chain */
  FT_SLIST_FOREACH(rec, bhead, chain) {

    /* if found return pointer */
    if (!bcmp((char*)rec+keyoff, (char*)key, ftch->key_size))
      return rec;

  }

  return (void*)0L;

} /* ftchash_lookup */

/*
 * function: ftchash_update
 *
 *   add record to hash table.  key_size bytes will be copied from rec to
 *   the allocated hash record.  The caller must update the remaining
 *   area of rec.  hash value must be less than h_size.
 *
 *   returns 0L on error
 *           or pointer to allocated record
 */
void *ftchash_update(struct ftchash *ftch, void *newrec, uint32_t hash)
{

  struct ftchash_rec_gen *rec;
  struct ftchash_bhead *bhead;
  int keyoff;

  /* no longer sorted */
  ftch->sort_flags &= ~FT_CHASH_SORTED;

  /* offset to key */
  keyoff = offsetof(struct ftchash_rec_gen, data);

  /* lookup hash entry */
  bhead = &(*ftch).buckets[hash];

  /* walk down chain */
  FT_SLIST_FOREACH(rec, bhead, chain) {

    /* if found return pointer */
    if (!bcmp((char*)rec+keyoff, (char*)newrec+keyoff, ftch->key_size))
      return rec;

  }

  /* not found, allocate new entry */
  if (!(rec = (struct ftchash_rec_gen*) ftchash_alloc_rec(ftch))) {
    fterr_warnx("ftchash_alloc_rec(): failed");
    return (void*)0L;
  }

  /* add to chain */
  FT_SLIST_INSERT_HEAD(bhead, rec, chain);

  /* copy in key */
  bcopy((char*)newrec+keyoff, (char*)rec+keyoff, ftch->key_size);

  /* increment storage counter */
  ftch->entries ++;

  /* return new record pointer */
  return rec;

} /* ftchash_update */

/*
 * function: ftchash_alloc_rec
 *
 *   allocate a new record
 *
 *   chunk pointer is added to ftch->chunk_list when adding new chunk
 *
 *   a chunk will always contain at least 1 record
 *
 *   returns 0L on error
 *           or pointer to allocated record
 */
void *ftchash_alloc_rec(struct ftchash *ftch)
{
  void *p;
  struct ftchash_chunk *chunk;

  if ((!ftch->active_chunk) || (ftch->active_chunk->next >= ftch->chunk_size)) {

    /* allocate the chunk */
    if (!(p = malloc(ftch->chunk_size))) {
      fterr_warnx("malloc()");
      return (void*)0L;
    }

    bzero(p, ftch->chunk_size);

    /* allocate the chunk holder */
    if (!(chunk = (struct ftchash_chunk*)malloc(
      sizeof (struct ftchash_chunk)))) {
      fterr_warnx("malloc()");
      free (p);
      return (void*)0L;
    }

    bzero(chunk, sizeof (struct ftchash_chunk));
    chunk->base = p;

    ftch->active_chunk = chunk;

    FT_SLIST_INSERT_HEAD(&ftch->chunk_list, chunk, chain);

  }

  p = (char*)ftch->active_chunk->base + ftch->active_chunk->next;
  ftch->active_chunk->next += ftch->d_size;
  return p;

} /* ftchash_alloc_rec */

/*
 * function: ftchash_first
 *
 * setup ftchash_foreach to first entry;
 */
void ftchash_first(struct ftchash *ftch)
{
  struct ftchash_chunk *chunk;

  if (ftch->sort_flags & FT_CHASH_SORTED) {
    if (ftch->sort_flags & FT_CHASH_SORT_ASCENDING)
      ftch->traverse_srec = ftch->entries;
    else
      ftch->traverse_srec = 0;
  } else {

    chunk = FT_SLIST_FIRST(&ftch->chunk_list);

    if (chunk) {
      ftch->traverse_chunk = chunk;
      ftch->traverse_rec = chunk->base;
    } else {
      ftch->traverse_rec = (void*)0L;
      ftch->traverse_chunk = (void*)0L;
    }
  } /* sorted? */
} /* ftchash_first */

/*
 * function: ftchash_foreach
 *
 * returns next entry in hash table, or NULL if the last entry
 * ftchash_first() must be called first.
 *
 */
void *ftchash_foreach(struct ftchash *ftch)
{
  struct ftchash_chunk *chunk;
  void *ret;

  if (ftch->sort_flags & FT_CHASH_SORTED) {
    if (ftch->sort_flags & FT_CHASH_SORT_ASCENDING) {
      if (ftch->traverse_srec > 0)
        return (ftch->sorted_recs[--ftch->traverse_srec]);
      else
        return (void*)0L;
    } else {
      if (ftch->traverse_srec < ftch->entries)
        return (ftch->sorted_recs[ftch->traverse_srec++]);
      else
        return (void*)0L;
    }
  } else {

    /* only happens on empty hash table -- done */
    if (!ftch->traverse_chunk)
      return (void*)0L;
   
      
    /* more entries in this chunk *? */ 
    if  ((char*)ftch->traverse_rec <
      (char*)ftch->traverse_chunk->base+ftch->traverse_chunk->next) {

      ret = ftch->traverse_rec;
      ftch->traverse_rec = (char*)ftch->traverse_rec + ftch->d_size;
      
      return ret;

    } else {

        /* go to next chunk */
        chunk = FT_SLIST_NEXT(ftch->traverse_chunk, chain);

        /* if this is a valid chunk, return first record */
        if (chunk) {
          ftch->traverse_chunk = chunk;
          ftch->traverse_rec = (char*)ftch->traverse_chunk->base + ftch->d_size;
          return (chunk->base);
        } else { /* else that was the last chunk, done */
          return (void*)0L;
        }
    }
  } /* sorted? */
} /* ftchash_foreach */

/*
 * function: ftchash_sort
 *
 *   creates an array of pointers to the sorted records
 *
 *   returns -1 on error
 *            0 otherwise
 */
int ftchash_sort(struct ftchash *ftch, int offset, int flags)
{
  void *rec;
  uint64_t x;

  /* entries to sort? */
  if (!ftch->entries)
    return 0;

  /* free memory from previous call */
  if (ftch->sorted_recs)
    free(ftch->sorted_recs);

  /* allocate ftch->entries * sizeof 32 bit pointer */
  if (!(ftch->sorted_recs = (struct ftchash_rec_gen**)
    malloc(sizeof (struct ftchash_rec_gen*)*ftch->entries))) {
    fterr_warn("malloc()");
    return -1;
  }

  ftch->sort_flags = flags;

  /* copy in the unsorted entries */
  ftchash_first(ftch);
  x = 0;
  while ((rec = ftchash_foreach(ftch))) {

    ftch->sorted_recs[x++] = (struct ftchash_rec_gen*)rec;

  } /* while */

  sort_offset = offset;

  if (flags & FT_CHASH_SORT_64)
    qsort(ftch->sorted_recs, ftch->entries, sizeof (void*), cmp64);
  else if (flags & FT_CHASH_SORT_40)
    qsort(ftch->sorted_recs, ftch->entries, sizeof (void*), cmp40);
  else if (flags & FT_CHASH_SORT_32)
    qsort(ftch->sorted_recs, ftch->entries, sizeof (void*), cmp32);
  else if (flags & FT_CHASH_SORT_16)
    qsort(ftch->sorted_recs, ftch->entries, sizeof (void*), cmp16);
  else if (flags & FT_CHASH_SORT_8)
    qsort(ftch->sorted_recs, ftch->entries, sizeof (void*), cmp8);
  else if (flags & FT_CHASH_SORT_DOUBLE)
    qsort(ftch->sorted_recs, ftch->entries, sizeof (void*), cmp_double);
  else
    fterr_errx(1, "ftchash_sort(): internal error");

  ftch->sort_flags |= FT_CHASH_SORTED;

  return 0;

} /* ftchash_sort */

static int cmp64(const void *a, const void *b)
{
  uint64_t *la, *lb;
  char *d;

  d = *(char**)a;
  la = (uint64_t*)(d+sort_offset);

  d = *(char**)b;
  lb = (uint64_t*)(d+sort_offset);

  if (*la < *lb)
    return -1;
  if (*la > *lb)
    return 1;
  return 0;

} /* cmp64 */

static int cmp40(const void *a, const void *b)
{
  uint32_t *la, *lb;
  uint8_t *ca, *cb;
  char *d;

  d = *(char**)a;
  la = (uint32_t*)(d+sort_offset);

  d = *(char**)b;
  lb = (uint32_t*)(d+sort_offset);

  if (*la < *lb)
    return -1;
  if (*la > *lb)
    return 1;

  d = *(char**)a;
  ca = (uint8_t*)(d+sort_offset+4);

  d = *(char**)b;
  cb = (uint8_t*)(d+sort_offset+4);
  
  if (*ca < *cb)
    return -1;
  if (*ca > *cb)
    return 1;
  
  return 0;

} /* cmp40 */

static int cmp32(const void *a, const void *b)
{
  uint32_t *la, *lb;
  char *d;

  d = *(char**)a;
  la = (uint32_t*)(d+sort_offset);

  d = *(char**)b;
  lb = (uint32_t*)(d+sort_offset);

  if (*la < *lb)
    return -1;
  if (*la > *lb)
    return 1;
  return 0;

} /* cmp32 */

static int cmp16(const void *a, const void *b)
{
  uint16_t *la, *lb;
  char *d;

  d = *(char**)a;
  la = (uint16_t*)(d+sort_offset);

  d = *(char**)b;
  lb = (uint16_t*)(d+sort_offset);

  if (*la < *lb)
    return -1;
  if (*la > *lb)
    return 1;
  return 0;

} /* cmp16 */

static int cmp8(const void *a, const void *b)
{
  uint8_t *la, *lb;
  char *d;

  d = *(char**)a;
  la = (uint8_t*)(d+sort_offset);

  d = *(char**)b;
  lb = (uint8_t*)(d+sort_offset);

  if (*la < *lb)
    return -1;
  if (*la > *lb)
    return 1;
  return 0;

} /* cmp8 */

static int cmp_double(const void *a, const void *b)
{
  double *la, *lb;
  char *d;

  d = *(char**)a;
  la = (double*)(d+sort_offset);

  d = *(char**)b;
  lb = (double*)(d+sort_offset);

  if (*la < *lb)
    return -1;
  if (*la > *lb)
    return 1;
  return 0;

} /* cmp_double */

