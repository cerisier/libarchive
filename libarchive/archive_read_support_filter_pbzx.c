/*-
 * Copyright (c) 2026
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "archive_platform.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "archive.h"
#include "archive_endian.h"
#include "archive_private.h"
#include "archive_read_private.h"

#define PBZX_MAGIC "pbzx"
#define PBZX_MAGIC_LEN 4
#define PBZX_FLAG_MORE (1ULL << 24)
#define PBZX_XZ_MAGIC "\xFD\x37\x7A\x58\x5A\x00"
#define PBZX_XZ_MAGIC_LEN 6

struct pbzx {
	uint64_t	flags;
	uint64_t	remaining;
	unsigned char	header[PBZX_XZ_MAGIC_LEN];
	size_t		header_pos;
	unsigned char	tail[2];
	enum {
		ST_SIGNATURE,
		ST_CHUNK_HEADER,
		ST_EMIT_HEADER,
		ST_CHUNK_DATA,
		ST_DONE
	}	state;
};

static int	pbzx_bidder_bid(struct archive_read_filter_bidder *,
		    struct archive_read_filter *);
static int	pbzx_bidder_init(struct archive_read_filter *);

static ssize_t	pbzx_filter_read(struct archive_read_filter *,
		    const void **);
static int	pbzx_filter_close(struct archive_read_filter *);

static int	pbzx_read_bytes(struct archive_read_filter *,
		    unsigned char *, size_t);
static int	pbzx_read_u64_be(struct archive_read_filter *, uint64_t *);

static const struct archive_read_filter_bidder_vtable
pbzx_bidder_vtable = {
	.bid = pbzx_bidder_bid,
	.init = pbzx_bidder_init,
};

int
archive_read_support_filter_pbzx(struct archive *_a)
{
	struct archive_read *a = (struct archive_read *)_a;

	return __archive_read_register_bidder(a, NULL, "pbzx",
	    &pbzx_bidder_vtable);
}

static int
pbzx_bidder_bid(struct archive_read_filter_bidder *self,
    struct archive_read_filter *filter)
{
	const unsigned char *b;
	ssize_t avail;

	(void)self; /* UNUSED */

	b = __archive_read_filter_ahead(filter, PBZX_MAGIC_LEN, &avail);
	if (b == NULL)
		return (0);
	if (memcmp(b, PBZX_MAGIC, PBZX_MAGIC_LEN) != 0)
		return (0);
	return (PBZX_MAGIC_LEN * 8);
}

static const struct archive_read_filter_vtable
pbzx_reader_vtable = {
	.read = pbzx_filter_read,
	.close = pbzx_filter_close,
};

static int
pbzx_bidder_init(struct archive_read_filter *self)
{
	struct pbzx *pbzx;

	self->code = ARCHIVE_FILTER_PBZX;
	self->name = "pbzx";

	pbzx = calloc(1, sizeof(*pbzx));
	if (pbzx == NULL) {
		archive_set_error(&self->archive->archive, ENOMEM,
		    "Can't allocate pbzx filter data");
		return (ARCHIVE_FATAL);
	}
	pbzx->state = ST_SIGNATURE;
	self->data = pbzx;
	self->vtable = &pbzx_reader_vtable;

	return (ARCHIVE_OK);
}

static int
pbzx_read_bytes(struct archive_read_filter *self, unsigned char *out,
    size_t len)
{
	size_t remaining = len;
	while (remaining > 0) {
		ssize_t avail;
		const unsigned char *b = __archive_read_filter_ahead(
		    self->upstream, 1, &avail);
		if (b == NULL) {
			if (avail < 0)
				return (ARCHIVE_FATAL);
			archive_set_error(&self->archive->archive,
			    ARCHIVE_ERRNO_FILE_FORMAT,
			    "Truncated pbzx stream");
			return (ARCHIVE_FATAL);
		}
		if ((size_t)avail > remaining)
			avail = (ssize_t)remaining;
		memcpy(out, b, (size_t)avail);
		__archive_read_filter_consume(self->upstream, avail);
		out += (size_t)avail;
		remaining -= (size_t)avail;
	}
	return (ARCHIVE_OK);
}

static int
pbzx_read_u64_be(struct archive_read_filter *self, uint64_t *v)
{
	unsigned char buf[8];
	int r = pbzx_read_bytes(self, buf, sizeof(buf));
	if (r != ARCHIVE_OK)
		return (r);
	*v = archive_be64dec(buf);
	return (ARCHIVE_OK);
}

static ssize_t
pbzx_filter_read(struct archive_read_filter *self, const void **buff)
{
	struct pbzx *pbzx = (struct pbzx *)self->data;
	const unsigned char *b;
	ssize_t avail_in;
	size_t n;
	unsigned char magic[PBZX_MAGIC_LEN];

	*buff = NULL;

	for (;;) {
		switch (pbzx->state) {
		case ST_SIGNATURE:
			if (pbzx_read_bytes(self, magic, sizeof(magic)) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			if (memcmp(magic, PBZX_MAGIC, PBZX_MAGIC_LEN) != 0) {
				archive_set_error(&self->archive->archive,
				    ARCHIVE_ERRNO_FILE_FORMAT,
				    "Invalid pbzx signature");
				return (ARCHIVE_FATAL);
			}
			if (pbzx_read_u64_be(self, &pbzx->flags) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			if ((pbzx->flags & PBZX_FLAG_MORE) == 0) {
				pbzx->state = ST_DONE;
				return (0);
			}
			pbzx->state = ST_CHUNK_HEADER;
			break;
		case ST_CHUNK_HEADER:
			if (pbzx_read_u64_be(self, &pbzx->flags) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			if (pbzx_read_u64_be(self, &pbzx->remaining) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			if (pbzx->remaining < PBZX_XZ_MAGIC_LEN) {
				archive_set_error(&self->archive->archive,
				    ARCHIVE_ERRNO_FILE_FORMAT,
				    "pbzx chunk length too small");
				return (ARCHIVE_FATAL);
			}
			if (pbzx_read_bytes(self, pbzx->header,
			    PBZX_XZ_MAGIC_LEN) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			if (memcmp(pbzx->header, PBZX_XZ_MAGIC,
			    PBZX_XZ_MAGIC_LEN) != 0) {
				archive_set_error(&self->archive->archive,
				    ARCHIVE_ERRNO_FILE_FORMAT,
				    "pbzx chunk header is not xz");
				return (ARCHIVE_FATAL);
			}
			pbzx->remaining -= PBZX_XZ_MAGIC_LEN;
			pbzx->header_pos = 0;
			pbzx->tail[0] = 0;
			pbzx->tail[1] = 0;
			pbzx->state = ST_EMIT_HEADER;
			break;
		case ST_EMIT_HEADER:
			*buff = pbzx->header + pbzx->header_pos;
			n = PBZX_XZ_MAGIC_LEN - pbzx->header_pos;
			pbzx->header_pos = PBZX_XZ_MAGIC_LEN;
			pbzx->state = ST_CHUNK_DATA;
			return ((ssize_t)n);
		case ST_CHUNK_DATA:
			if (pbzx->remaining == 0) {
				if (!(pbzx->tail[0] == 'Y' &&
				    pbzx->tail[1] == 'Z')) {
					archive_set_error(&self->archive->archive,
					    ARCHIVE_ERRNO_FILE_FORMAT,
					    "pbzx chunk footer is not YZ");
					return (ARCHIVE_FATAL);
				}
				if (pbzx->flags & PBZX_FLAG_MORE) {
					pbzx->state = ST_CHUNK_HEADER;
					break;
				}
				pbzx->state = ST_DONE;
				return (0);
			}
			b = __archive_read_filter_ahead(self->upstream, 1,
			    &avail_in);
			if (b == NULL) {
				if (avail_in < 0)
					return (ARCHIVE_FATAL);
				archive_set_error(&self->archive->archive,
				    ARCHIVE_ERRNO_FILE_FORMAT,
				    "Truncated pbzx stream");
				return (ARCHIVE_FATAL);
			}
			n = (size_t)avail_in;
			if (n > pbzx->remaining)
				n = (size_t)pbzx->remaining;
			if (n >= 2) {
				pbzx->tail[0] = b[n - 2];
				pbzx->tail[1] = b[n - 1];
			} else if (n == 1) {
				pbzx->tail[0] = pbzx->tail[1];
				pbzx->tail[1] = b[0];
			}
			*buff = b;
			__archive_read_filter_consume(self->upstream, n);
			pbzx->remaining -= n;
			return ((ssize_t)n);
		case ST_DONE:
			return (0);
		}
	}
}

static int
pbzx_filter_close(struct archive_read_filter *self)
{
	struct pbzx *pbzx = (struct pbzx *)self->data;
	free(pbzx);
	return (ARCHIVE_OK);
}
