/*	$OpenBSD$	*/
/*
 * Copyright (c) 2008 Alexandre Ratchov <alex@caoua.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef USE_TINYALSA
#include <sys/types.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "sio_priv.h"
#include "bsd-compat.h"

#include <tinyalsa/pcm.h>
#include <stdbool.h>

int pcm_state(struct pcm *pcm);
int pcm_avail_update(struct pcm *pcm);

struct sio_tinyalsa_hdl {
	struct sio_hdl sio;
	struct {
		char *tmpbuf;
		int used, delta, partial;
		unsigned int bpf;
	} state[2];
	struct sio_par par;
	struct pcm *pcm[2];
	int nfds, card, device;
	bool running;
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/*
 * convert ALSA format to sio_par encoding
 */
static int
sio_tinyalsa_fmttopar(struct sio_tinyalsa_hdl *hdl, enum pcm_format fmt, unsigned int *bits, unsigned int *sig, unsigned int *le)
{
	switch (fmt) {
		case PCM_FORMAT_S8:
			*bits = 8;
			*sig = 1;
			break;
		case PCM_FORMAT_S16_LE:
			*bits = 16;
			*sig = 1;
			*le = 1;
			break;
		case PCM_FORMAT_S16_BE:
			*bits = 16;
			*sig = 1;
			*le = 0;
			break;
		case PCM_FORMAT_S24_LE:
			*bits = 24;
			*sig = 1;
			*le = 1;
			break;
		case PCM_FORMAT_S24_BE:
			*bits = 24;
			*sig = 1;
			*le = 0;
			break;
		case PCM_FORMAT_S32_LE:
			*bits = 32;
			*sig = 1;
			*le = 1;
			break;
		case PCM_FORMAT_S32_BE:
			*bits = 32;
			*sig = 1;
			*le = 0;
			break;
		default:
			DPRINTF("sio_tinyalsa_fmttopar: 0x%x: unsupported format\n", fmt);
			hdl->sio.eof = 1;
			return 0;
	}
	return 1;
}


/*
 * convert sio_par encoding to ALSA format
 */
static void
sio_alsa_enctofmt(struct sio_tinyalsa_hdl *hdl, enum pcm_format *rfmt, unsigned int bits, unsigned int sig, unsigned int le)
{
	if (bits == 8) {
		*rfmt = PCM_FORMAT_S8;
	} else if (bits == 16) {
		if (le == ~0U) {
			*rfmt = SIO_LE_NATIVE ? PCM_FORMAT_S16_LE : PCM_FORMAT_S16_BE;
		} else {
			*rfmt = (le ? PCM_FORMAT_S16_LE : PCM_FORMAT_S16_BE);
		}
	} else if (bits == 24) {
		if (le == ~0U) {
			*rfmt = SIO_LE_NATIVE ? PCM_FORMAT_S24_LE : PCM_FORMAT_S24_BE;
		} else {
			*rfmt = (le ? PCM_FORMAT_S24_LE : PCM_FORMAT_S24_BE);
		}
	} else if (bits == 32) {
		if (le == ~0U) {
			*rfmt = SIO_LE_NATIVE ? PCM_FORMAT_S32_LE : PCM_FORMAT_S32_BE;
		} else {
			*rfmt = (le ? PCM_FORMAT_S32_LE : PCM_FORMAT_S32_BE);
		}
	} else {
		*rfmt = SIO_LE_NATIVE ? PCM_FORMAT_S16_LE : PCM_FORMAT_S16_BE;
	}
}

/*
 * guess device capabilities
 */
static int
sio_tinyalsa_getcap(struct sio_hdl *sh, struct sio_cap *cap)
{
	struct sio_tinyalsa_hdl *hdl = (struct sio_tinyalsa_hdl *)sh;

	struct pcm_params *params;
	if (!(params = pcm_params_get(hdl->card, hdl->device, PCM_OUT | PCM_NONBLOCK))) {
		fprintf(stderr, "tinyalsa: pcm_params_get failed\n");
		hdl->sio.eof = 1;
		return 0;
	}

	const struct pcm_mask *mask = pcm_params_get_mask(params, PCM_PARAM_FORMAT);
	unsigned int m = (mask->bits[1] << 8) | mask->bits[0];

	unsigned int ofmts = 0;
	{
		static enum pcm_format cap_fmts[] = {
			PCM_FORMAT_S32_LE,	PCM_FORMAT_S32_BE,
			PCM_FORMAT_S24_LE,	PCM_FORMAT_S24_BE,
			PCM_FORMAT_S16_LE,	PCM_FORMAT_S16_BE,
			PCM_FORMAT_S8
		};

		for (int i = 0, f = 0; i < ARRAY_SIZE(cap_fmts); ++i) {
			if (!(m & (1 << cap_fmts[i])))
				continue;

			sio_tinyalsa_fmttopar(hdl, cap_fmts[i], &cap->enc[f].bits, &cap->enc[f].sig, &cap->enc[f].le);
			cap->enc[f].bps = SIO_BPS(cap->enc[f].bits);
			cap->enc[f++].msb = 1;
			ofmts |= 1 << f;
		}
	}

	unsigned int orates = 0;
	{
		static unsigned int cap_rates[] = {
			 8000, 11025, 12000, 16000, 22050, 24000,
			32000, 44100, 48000, 64000, 88200, 96000
		};

		unsigned int min = pcm_params_get_min(params, PCM_PARAM_RATE);
		unsigned int max = pcm_params_get_max(params, PCM_PARAM_RATE);
		for (int i = 0, r = 0; i < ARRAY_SIZE(cap_rates); ++i) {
			if (cap_rates[i] < min || cap_rates[i] > max)
				continue;

			cap->rate[r++] = cap_rates[i];
			orates |= 1 << r;
		}
	}

    unsigned int ochans = 0;
	{
		static unsigned int cap_chans[] = {
			1, 2, 4, 6, 8, 10, 12, 16
		};

		unsigned int min = pcm_params_get_min(params, PCM_PARAM_CHANNELS);
		unsigned int max = pcm_params_get_max(params, PCM_PARAM_CHANNELS);
		for (int i = 0, c = 0; i < ARRAY_SIZE(cap_chans); ++i) {
			if (cap_chans[i] < min || cap_chans[i] > max)
				continue;

			cap->pchan[c++] = cap_chans[i];
			ochans |= 1 << c;
		}
	}

	pcm_params_free(params);

	cap->confs[0].enc = ~0U;
	cap->confs[0].rate = ~0U;
	cap->confs[0].pchan = ~0U;
	cap->confs[0].rchan = ~0U;

	if (hdl->sio.mode & SIO_PLAY) {
		cap->confs[0].pchan &= ochans;
		cap->confs[0].enc &= ofmts;
		cap->confs[0].rate &= orates;
	}

	cap->nconf = 1;
	return 1;
}

static void
sio_tinyalsa_close(struct sio_hdl *sh)
{
	struct sio_tinyalsa_hdl *hdl = (void*)sh;

	for (int i = 0; i < ARRAY_SIZE(hdl->state); ++i)
		free(hdl->state[i].tmpbuf);

	for (int i = 0; i < ARRAY_SIZE(hdl->pcm); ++i) {
		if (hdl->pcm[i])
			pcm_close(hdl->pcm[i]);
	}

	free(hdl);
}

static int
sio_tinyalsa_start(struct sio_hdl *sh)
{
	struct sio_tinyalsa_hdl *hdl = (void*)sh;

	for (int i = 0; i < ARRAY_SIZE(hdl->state); ++i)
		free(hdl->state[i].tmpbuf);

	memset(hdl->state, 0, sizeof(hdl->state));
	hdl->state[0].bpf = hdl->par.pchan * hdl->par.bps;
	hdl->state[1].bpf = hdl->par.rchan * hdl->par.bps;
	hdl->running = 0;

	for (int i = 0; i < ARRAY_SIZE(hdl->state); ++i) {
		if (!(hdl->state[i].tmpbuf = malloc(hdl->state[i].bpf)))
			goto fail;
	}

	if (pcm_prepare(hdl->pcm[0]) != 0) {
		fprintf(stderr, "tinyalsa: pcm_prepare failed\n");
		goto fail;
	}

	return 1;

fail:
	hdl->sio.eof = 1;
	return 0;
}

static int
sio_tinyalsa_stop(struct sio_hdl *sh)
{
	struct sio_tinyalsa_hdl *hdl = (void*)sh;
	return (pcm_stop(hdl->pcm[0]) == 0);
}

static int
sio_tinyalsa_setpar(struct sio_hdl *sh, struct sio_par *par)
{
	struct sio_tinyalsa_hdl *hdl = (void*)sh;

	DPRINTF("sio_tinyalsa_setpar: bits=%d sig=%d le=%d round=%d pchan=%d rate=%d bufsz=%d appbufsz=%d\n",
	    par->bits, par->sig, par->le, par->round, par->pchan, par->rate,
	    par->bufsz, par->appbufsz);

	struct pcm_config config = {0};
	sio_alsa_enctofmt(hdl, &config.format, par->bits, par->sig, par->le);
	config.channels = 2; // par->pchan;

	unsigned int round, bufsz;
	if (par->round != ~0U && par->appbufsz != ~0U) {
		round = par->round;
		bufsz = par->appbufsz;
	} else if (par->round != ~0U) {
		round = par->round;
		bufsz = 2 * par->round;
	} else if (par->appbufsz != ~0U) {
		round = par->appbufsz / 2;
		bufsz = par->appbufsz;
	} else {
		/*
		 * even if it's not specified, we have to set the
		 * block size to ensure that both play and record
		 * direction get the same block size. Pick an
		 * arbitrary value that would work for most players at
		 * 48kHz, stereo, 16-bit.
		 */
		round = 512;
		bufsz = 1024;
	}

	config.period_size = round;
	config.period_count = bufsz / round;
	config.rate = par->rate;

	if (hdl->sio.mode & SIO_PLAY) {
		config.silence_threshold = 0;
		config.start_threshold = 0;
		config.stop_threshold = 0;
	}

	DPRINTF("sio_tinyalsa_setpar: round=%d bufsz=%d period_count=%d\n", round, bufsz, bufsz / round);

	if (pcm_set_config(hdl->pcm[0], &config) < 0) {
		fprintf(stderr, "tinyalsa: pcm_set_config failed\n");
		hdl->sio.eof = 1;
		return 0;
	}

	const struct pcm_config *oconfig;
	if (!(oconfig = pcm_get_config(hdl->pcm[0]))) {
		fprintf(stderr, "tinyalsa: pcm_get_config failed\n");
		hdl->sio.eof = 1;
		return 0;
	}

	sio_tinyalsa_fmttopar(hdl, oconfig->format, &hdl->par.bits, &hdl->par.sig, &hdl->par.le);
	hdl->par.bufsz = oconfig->period_size * oconfig->period_count;
	hdl->par.appbufsz = hdl->par.bufsz;
	hdl->par.pchan = par->rchan = oconfig->channels;
	hdl->par.rate = oconfig->rate;
	hdl->par.round = oconfig->period_size;
	/* hdl->par.xrun = SIO_IGNORE; */
	hdl->par.msb = 1;
	hdl->par.bps = SIO_BPS(par->bits);
	return 1;
}

static int
sio_tinyalsa_getpar(struct sio_hdl *sh, struct sio_par *par)
{
	struct sio_tinyalsa_hdl *hdl = (void*)sh;
	*par = hdl->par;
	return 1;
}

static int
sio_tinyalsa_xrun(struct sio_tinyalsa_hdl *hdl)
{
	/*
	 * we assume rused/wused are zero if rec/play modes are not
	 * selected. This allows us to keep the same formula for all
	 * modes, provided we set rbpf/wbpf to 1 to avoid division by
	 * zero.
	 *
	 * to understand the formula, draw a picture :)
	 */
	int rbpf = (hdl->sio.mode & SIO_REC ? hdl->sio.par.bps * hdl->sio.par.rchan : 1);
	int wbpf = (hdl->sio.mode & SIO_PLAY ? hdl->sio.par.bps * hdl->sio.par.pchan : 1);
	int rround = hdl->sio.par.round * rbpf;

	int clk = hdl->sio.cpos % hdl->sio.par.round;
	int rdrop = (clk * rbpf - hdl->sio.rused) % rround;
	rdrop += rround * (rdrop < 0);
	int cmove = (rdrop + hdl->sio.rused) / rbpf;
	int wsil = cmove * wbpf + hdl->sio.wused;

	DPRINTFN(2, "wsil = %d, cmove = %d, rdrop = %d\n", wsil, cmove, rdrop);

	if (!sio_tinyalsa_stop(&hdl->sio) || !sio_tinyalsa_start(&hdl->sio))
		return 0;

	if (hdl->sio.mode & SIO_PLAY) {
		hdl->state[0].delta -= cmove;
		hdl->sio.wsil = wsil;
	}

	if (hdl->sio.mode & SIO_REC) {
		hdl->state[1].delta -= cmove;
		hdl->sio.rdrop = rdrop;
	}

	return 1;
}


static size_t
sio_tinyalsa_read(struct sio_hdl *sh, void *buf, size_t len)
{
	return 0;
}

static size_t
sio_tinyalsa_write(struct sio_hdl *sh, const void *buf, size_t len)
{
	struct sio_tinyalsa_hdl *hdl = (void*)sh;

	size_t todo = 0;
	if (len < hdl->state[0].bpf || hdl->state[0].partial > 0) {
		todo = hdl->state[0].bpf - hdl->state[0].partial;
		if (todo > 0) {
			todo = (todo > len ? len : todo);
			memcpy(hdl->state[0].tmpbuf + hdl->state[0].partial, buf, todo);
			hdl->state[0].partial += todo;
			return todo;
		}
		len = hdl->state[0].bpf;
		buf = hdl->state[0].tmpbuf;
	}

	todo = len / hdl->state[0].bpf;
	if (todo == 0)
		return 0;

	ssize_t n;
	fprintf(stderr, "writing %zu bytes\n", todo);
	while ((n = pcm_writei(hdl->pcm[0], buf, todo)) < 0) {
		if (n == -EINTR)
			continue;
		if (n == -ESTRPIPE || n == -EPIPE) {
			sio_tinyalsa_xrun(hdl);
			return 0;
		}
		if (n != -EAGAIN) {
			fprintf(stderr, "couldn't write data");
			hdl->sio.eof = 1;
		}
		return 0;
	}
	fprintf(stderr, "wrote %zu bytes\n", n);

	hdl->state[0].delta += n;
	if (buf == hdl->state[0].tmpbuf) {
		hdl->state[0].partial = (n > 0 ? 0 : hdl->state[0].partial);
		return 0;
	}

	return n * hdl->state[0].bpf;
}

void
sio_tinyalsa_onmove(struct sio_tinyalsa_hdl *hdl)
{
	int delta = 0;

	if (hdl->running) {
		switch (hdl->sio.mode & (SIO_PLAY | SIO_REC)) {
			case SIO_PLAY:
				delta = hdl->state[0].delta;
				break;
			case SIO_REC:
				delta = hdl->state[1].delta;
				break;
			default: /* SIO_PLAY | SIO_REC */
				delta = hdl->state[0].delta > hdl->state[1].delta ? hdl->state[0].delta : hdl->state[1].delta;
		}

		fprintf(stderr, "onmove: %d\n", delta);

		if (delta <= 0)
			return;
	} else {
		hdl->running = true;
	}

	_sio_onmove_cb(&hdl->sio, delta);

	if (hdl->sio.mode & SIO_PLAY)
		hdl->state[0].delta -= delta;
	if (hdl->sio.mode & SIO_REC)
		hdl->state[1].delta -= delta;
}

static int
sio_tinyalsa_nfds(struct sio_hdl *sh)
{
	struct sio_tinyalsa_hdl *hdl = (void*)sh;
	return hdl->nfds;
}

static int
sio_tinyalsa_pollfd(struct sio_hdl *sh, struct pollfd *pfd, int events)
{
	struct sio_tinyalsa_hdl *hdl = (void*)sh;

	if (!pfd || hdl->sio.eof)
		return 0;

	events = events & (POLLOUT | POLLIN);
	if (!(hdl->sio.mode & SIO_PLAY))
		events &= ~POLLOUT;
	if (!(hdl->sio.mode & SIO_REC))
		events &= ~POLLIN;

	fprintf(stderr, "pcm_state: %d running: %d\n", pcm_state(hdl->pcm[0]), hdl->running);
	int nfds = 0;
	if (events & POLLOUT) {
		if (!hdl->running && pcm_state(hdl->pcm[0]) == PCM_STATE_RUNNING)
			sio_tinyalsa_onmove(hdl);
		pfd[nfds].fd = pcm_get_file_descriptor(hdl->pcm[0]);
		pfd[nfds++].events = POLLOUT;
		fprintf(stderr, "pollfd pollout\n");
	}

	if (events & POLLIN) {
		if (!hdl->running && pcm_state(hdl->pcm[1]) == PCM_STATE_RUNNING)
			sio_tinyalsa_onmove(hdl);
		pfd[nfds].fd = pcm_get_file_descriptor(hdl->pcm[1]);
		pfd[nfds++].events = POLLIN;
	}

	return nfds;
}

int
sio_tinyalsa_revents(struct sio_hdl *sh, struct pollfd *pfd)
{
	struct sio_tinyalsa_hdl *hdl = (void*)sh;

	if (!pfd)
		return 0;

	if (hdl->sio.eof)
		return POLLHUP;

	int revents = 0, nfds = 0;
	if (pfd[nfds].events & POLLOUT && pfd[nfds].fd == pcm_get_file_descriptor(hdl->pcm[0])) {
		revents |= pfd[nfds++].events;
		fprintf(stderr, "revents pollout\n");

		int state = pcm_state(hdl->pcm[0]);
		if (state == PCM_STATE_XRUN) {
			if (!sio_tinyalsa_xrun(hdl))
				return POLLHUP;
			return 0;
		}
		if (state == PCM_STATE_RUNNING || state == PCM_STATE_PREPARED) {
			unsigned int avail = pcm_avail_update(hdl->pcm[0]);
			if (avail < 0) {
				if (avail == -EPIPE || avail == -ESTRPIPE) {
					if (!sio_tinyalsa_xrun(hdl))
						return POLLHUP;
					return 0;
				}
				fprintf(stderr, "tinyalsa: couldn't get play buffer ptr");
				hdl->sio.eof = 1;
				return POLLHUP;
			}
			int used = hdl->par.bufsz - avail;
			hdl->state[0].delta -= used - hdl->state[0].used;
			fprintf(stderr, "avail: %u bufsz: %u used: %d oused: %d delta: %d\n", avail, hdl->par.bufsz, used, hdl->state[0].used, hdl->state[0].delta);
			hdl->state[0].used = used;
		}
	}

	if (pfd[nfds].events & POLLIN) {
		revents |= pfd[nfds++].events;
	}

	if ((revents & (POLLIN | POLLOUT)) && hdl->running)
		sio_tinyalsa_onmove(hdl);

	return revents;
}

struct sio_hdl *
_sio_tinyalsa_open(const char *str, unsigned int mode, int nbio)
{
	const char *p;
	if (!(p = _sndio_parsetype(str, "rsnd"))) {
		DPRINTF("_sio_tinyalsa_open: %s: \"rsnd\" expected\n", str);
		return NULL;
	}

	switch (*p) {
		case '/':
			p++;
			break;
		default:
			DPRINTF("_sio_tinyalsa_open: %s: '/' expected\n", str);
			return NULL;
	}

	struct sio_tinyalsa_hdl *hdl;
	if (!(hdl = calloc(1, sizeof(*hdl))))
		return NULL;

	static struct sio_ops sio_tinyalsa_ops = {
		sio_tinyalsa_close,
		sio_tinyalsa_setpar,
		sio_tinyalsa_getpar,
		sio_tinyalsa_getcap,
		sio_tinyalsa_write,
		sio_tinyalsa_read,
		sio_tinyalsa_start,
		sio_tinyalsa_stop,
		sio_tinyalsa_nfds,
		sio_tinyalsa_pollfd,
		sio_tinyalsa_revents,
		NULL, /* setvol */
		NULL, /* getvol */
	};

	mode &= ~SIO_REC;
	_sio_create(&hdl->sio, &sio_tinyalsa_ops, mode, nbio);

	if (!strcmp(p, "default"))
		p = "hw:0,0";

	if (sscanf(p, "hw:%u,%u", &hdl->card, &hdl->device) < 2) {
		fprintf(stderr, "tinyalsa: invalid device name `%s`\n", p);
		return NULL;
	}

	for (int i = 0; i < ARRAY_SIZE(hdl->pcm); ++i) {
		if (!(mode & (i ? SIO_REC : SIO_PLAY)))
			continue;

		if (!(hdl->pcm[i] = pcm_open(hdl->card, hdl->device, (i ? PCM_IN : PCM_OUT) | PCM_NONBLOCK, NULL)))
			return NULL;

		if (!pcm_is_ready(hdl->pcm[i])) {
			fprintf(stderr, "tinyalsa: pcm_is_ready: %s", pcm_get_error(hdl->pcm[i]));
			return NULL;
		}

		++hdl->nfds;
	}

	return &hdl->sio;
}

#endif /* defined USE_TINYALSA */
