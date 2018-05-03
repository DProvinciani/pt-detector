/*
 * Copyright (c) 2013-2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "..\stdafx.h"
#include "pt_cpu.h"
#include "..\pt_dump.h"

#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define PT_VERSION_MAJOR 1
#define PT_VERSION_MINOR 5
#define PT_VERSION_BUILD 0
#define PT_VERSION_EXT ""
#define CRT_SECURE_NO_WARNINGS 1
#pragma comment(lib, "libipt.lib")

ptdump_global g_pt_data;

static inline void Xtrace(LPCTSTR lpszFormat, ...) {
    va_list args;
    va_start(args, lpszFormat);
    int nBuf;
    TCHAR szBuffer[2048] = { 0 }; //fix this
    nBuf = _vsnwprintf_s(szBuffer, 2047, lpszFormat, args);
    ::OutputDebugString(szBuffer);
    va_end(args);
}

static int diag(const char *errstr, uint64_t offset, int errcode)
{
	if (errcode)
		printf("[%" PRIx64 ": %s: %s]\n", offset, errstr,
		       pt_errstr(pt_errcode(errcode)));
	else
		printf("[%" PRIx64 ": %s]\n", offset, errstr);

	return errcode;
}

static void ptdump_tracking_init(struct ptdump_tracking *tracking)
{
	if (!tracking)
		return;

	pt_last_ip_init(&tracking->last_ip);
	pt_tcal_init(&tracking->tcal);
	pt_time_init(&tracking->time);

	tracking->tsc = 0ull;
	tracking->fcr = 0ull;
	tracking->in_header = 0;
}

static void ptdump_tracking_reset(struct ptdump_tracking *tracking)
{
	if (!tracking)
		return;

	pt_last_ip_init(&tracking->last_ip);
	pt_tcal_init(&tracking->tcal);
	pt_time_init(&tracking->time);

	tracking->tsc = 0ull;
	tracking->fcr = 0ull;
	tracking->in_header = 0;
}

static void ptdump_tracking_fini(struct ptdump_tracking *tracking)
{
	(void) tracking;

	/* Nothing to do. */
}

#define print_field(field, ...)					\
	do {							\
		/* Avoid partial overwrites. */			\
		memset(field, 0, sizeof(field));		\
		snprintf(field, sizeof(field), __VA_ARGS__);	\
	} while (0)


//TODO: Modify this to print to a file
static int print_buffer(struct ptdump_buffer *buffer, uint64_t offset,
			const struct ptdump_options *options)
{
	int retCode = 0;
	const char *sep;
	CHAR lpOutStr[0x200] = { 0 };
	DWORD dwBytesIo = 0;

	if (!buffer)
		return diag("error printing buffer", offset, -pte_internal);

	if (buffer->skip || options->quiet)
		return 0;

	/* Make sure the first column starts at the beginning of the line - no
	 * matter what column is first.
	 */
	sep = "";

	if (options->show_offset) {
		sprintf_s(lpOutStr, COUNTOF(lpOutStr), "%s%-*s", lpOutStr, (int) sizeof(buffer->offset), buffer->offset);
		sep = " ";
	}

	if (buffer->raw[0]) {
		sprintf_s(lpOutStr, COUNTOF(lpOutStr), "%s%s%-*s", lpOutStr, sep, (int) sizeof(buffer->raw), buffer->raw);
		sep = " ";
	}

	if (buffer->payload.standard[0])
		sprintf_s(lpOutStr, COUNTOF(lpOutStr), "%s%s%-*s", lpOutStr, sep, (int) sizeof(buffer->opcode),
		       buffer->opcode);
	else
		sprintf_s(lpOutStr, COUNTOF(lpOutStr), "%s%s%s", lpOutStr, sep, buffer->opcode);

	/* We printed at least one column.  From this point on, we don't need
	 * the separator any longer.
	 */

	if (buffer->use_ext_payload)
		sprintf_s(lpOutStr, COUNTOF(lpOutStr), " %s%s", lpOutStr, buffer->payload.extended);
	else if (buffer->tracking.id[0]) {
		sprintf_s(lpOutStr, COUNTOF(lpOutStr), "%s %-*s", lpOutStr, (int) sizeof(buffer->payload.standard),
		       buffer->payload.standard);

		sprintf_s(lpOutStr, COUNTOF(lpOutStr), "%s %-*s", lpOutStr, (int) sizeof(buffer->tracking.id),
		       buffer->tracking.id);
		sprintf_s(lpOutStr, COUNTOF(lpOutStr), "%s%s", lpOutStr, buffer->tracking.payload);
	} else if (buffer->payload.standard[0])
		sprintf_s(lpOutStr, COUNTOF(lpOutStr), "%s%s", lpOutStr, buffer->payload.standard);

	strcat_s(lpOutStr, COUNTOF(lpOutStr), "\r\n");

	if (options->hTargetFile) {
		retCode = WriteFile(options->hTargetFile, lpOutStr, (DWORD)strlen(lpOutStr), &dwBytesIo, NULL);
		// Translate the Win32 returned code in PT return code
		if (retCode == 0) retCode = -1;
	}
	else
		printf(lpOutStr);

	return retCode;
}

static int print_raw(struct ptdump_buffer *buffer, uint64_t offset,
		     const struct pt_packet *packet,
		     const struct pt_config *config)
{
	const uint8_t *begin, *end;
	char *bbegin, *bend;

	if (!buffer || !packet)
		return diag("error printing packet", offset, -pte_internal);

	begin = config->begin + offset;
	end = begin + packet->size;

	if (config->end < end)
		return diag("bad packet size", offset, -pte_bad_packet);

	bbegin = buffer->raw;
	bend = bbegin + sizeof(buffer->raw);

	for (; begin < end; ++begin) {
		char *pos;

		pos = bbegin;
		bbegin += 2;

		if (bend <= bbegin)
			return diag("truncating raw packet", offset, 0);

		sprintf_s(pos, sizeof(buffer->raw), "%02x", *begin);
	}

	return 0;
}

static int track_last_ip(struct ptdump_buffer *buffer,
			 struct pt_last_ip *last_ip, uint64_t offset,
			 const struct pt_packet_ip *packet,
			 const struct ptdump_options *options,
			 const struct pt_config *config)
{
	uint64_t ip;
	int errcode;

	if (!buffer || !options)
		return diag("error tracking last-ip", offset, -pte_internal);

	print_field(buffer->tracking.id, "ip");

	errcode = pt_last_ip_update_ip(last_ip, packet, config);
	if (errcode < 0) {
		print_field(buffer->tracking.payload, "<unavailable>");

		return diag("error tracking last-ip", offset, errcode);
	}

	errcode = pt_last_ip_query(&ip, last_ip);
	if (errcode < 0) {
		if (errcode == -pte_ip_suppressed)
			print_field(buffer->tracking.payload, "<suppressed>");
		else {
			print_field(buffer->tracking.payload, "<unavailable>");

			return diag("error tracking last-ip", offset, errcode);
		}
	} else
		print_field(buffer->tracking.payload, "%016" PRIx64, ip);

	return 0;
}


static int print_time(struct ptdump_buffer *buffer,
		      struct ptdump_tracking *tracking, uint64_t offset,
		      const struct ptdump_options *options)
{
	uint64_t tsc;
	int errcode;

	if (!tracking || !options)
		return diag("error printing time", offset, -pte_internal);

	print_field(buffer->tracking.id, "tsc");

	errcode = pt_time_query_tsc(&tsc, NULL, NULL, &tracking->time);
	if (errcode < 0) {
		switch (-errcode) {
		case pte_no_time:
			if (options->no_wall_clock)
				break;

			/* Fall through. */
		default:
			diag("error printing time", offset, errcode);
			print_field(buffer->tracking.payload, "<unavailable>");
			return errcode;
		}
	}

	if (options->show_time_as_delta) {
		uint64_t old_tsc;

		old_tsc = tracking->tsc;
		if (old_tsc <= tsc)
			print_field(buffer->tracking.payload, "+%" PRIx64,
				    tsc - old_tsc);
		else
			print_field(buffer->tracking.payload, "-%" PRIx64,
				    old_tsc - tsc);

		tracking->tsc = tsc;
	} else
		print_field(buffer->tracking.payload, "%016" PRIx64, tsc);

	return 0;
}

static int print_tcal(struct ptdump_buffer *buffer,
		      struct ptdump_tracking *tracking, uint64_t offset,
		      const struct ptdump_options *options)
{
	uint64_t fcr;
	double dfcr;
	int errcode;

	if (!tracking || !options)
		return diag("error printing time", offset, -pte_internal);

	print_field(buffer->tracking.id, "fcr");

	errcode = pt_tcal_fcr(&fcr, &tracking->tcal);
	if (errcode < 0) {
		print_field(buffer->tracking.payload, "<unavailable>");
		return diag("error printing time", offset, errcode);
	}

	/* We print fcr as double to account for the shift. */
	dfcr = (double) fcr;
	dfcr /= (double) (1ull << pt_tcal_fcr_shr);

	if (options->show_time_as_delta) {
		uint64_t old_fcr;
		double dold_fcr;

		old_fcr = tracking->fcr;

		/* We print fcr as double to account for the shift. */
		dold_fcr = (double) old_fcr;
		dold_fcr /= (double) (1ull << pt_tcal_fcr_shr);

		if (old_fcr <= fcr)
			print_field(buffer->tracking.payload, "+%.3f",
				    dfcr - dold_fcr);
		else
			print_field(buffer->tracking.payload, "-%.3f",
				    dold_fcr - dfcr);

		tracking->fcr = fcr;
	} else
		print_field(buffer->tracking.payload, "%.3f", dfcr);

	return 0;
}

static int track_time(struct ptdump_buffer *buffer,
		      struct ptdump_tracking *tracking,  uint64_t offset,
		      const struct ptdump_options *options)
{
	if (!tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (options->show_tcal && !buffer->skip_tcal)
		print_tcal(buffer, tracking, offset, options);

	if (options->show_time && !buffer->skip_time)
		print_time(buffer, tracking, offset, options);

	return 0;
}

static int track_tsc(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_tsc *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (!options->no_tcal) {
		errcode = tracking->in_header ?
			pt_tcal_header_tsc(&tracking->tcal, packet, config) :
			pt_tcal_update_tsc(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_tsc(&tracking->time, packet, config);
	if (errcode < 0)
		diag("error updating time", offset, errcode);

	return track_time(buffer, tracking, offset, options);
}

static int track_cbr(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_cbr *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (!options->no_tcal) {
		errcode = tracking->in_header ?
			pt_tcal_header_cbr(&tracking->tcal, packet, config) :
			pt_tcal_update_cbr(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_cbr(&tracking->time, packet, config);
	if (errcode < 0)
		diag("error updating time", offset, errcode);

	/* There is no timing update at this packet. */
	buffer->skip_time = 1;

	return track_time(buffer, tracking, offset, options);
}

static int track_tma(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_tma *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (!options->no_tcal) {
		errcode = pt_tcal_update_tma(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_tma(&tracking->time, packet, config);
	if (errcode < 0)
		diag("error updating time", offset, errcode);

	/* There is no calibration update at this packet. */
	buffer->skip_tcal = 1;

	return track_time(buffer, tracking, offset, options);
}

static int track_mtc(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_mtc *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (!options->no_tcal) {
		errcode = pt_tcal_update_mtc(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_mtc(&tracking->time, packet, config);
	if (errcode < 0)
		diag("error updating time", offset, errcode);

	return track_time(buffer, tracking, offset, options);
}

static int track_cyc(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_cyc *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	uint64_t fcr;
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	/* Initialize to zero in case of calibration errors. */
	fcr = 0ull;

	if (!options->no_tcal) {
		errcode = pt_tcal_fcr(&fcr, &tracking->tcal);
		if (errcode < 0)
			diag("calibration error", offset, errcode);

		errcode = pt_tcal_update_cyc(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_cyc(&tracking->time, packet, config, fcr);
	if (errcode < 0)
		diag("error updating time", offset, errcode);
	else if (!fcr)
		diag("error updating time: no calibration", offset, 0);

	/* There is no calibration update at this packet. */
	buffer->skip_tcal = 1;

	return track_time(buffer, tracking, offset, options);
}

static uint64_t sext(uint64_t val, uint8_t sign)
{
	uint64_t signbit, mask;

	signbit = 1ull << (sign - 1);
	mask = ~0ull << sign;

	return val & signbit ? val | mask : val & ~mask;
}

static UINT32 print_ip_payload(struct ptdump_buffer *buffer, uint64_t offset,
			    const struct pt_packet_ip *packet)
{
	if (!buffer || !packet)
		return diag("error printing payload", offset, -pte_internal);

	switch (packet->ipc) {
	case pt_ipc_suppressed:
		print_field(buffer->payload.standard, "%x: ????????????????",
			    pt_ipc_suppressed);
		return 0;

	case pt_ipc_update_16:
		print_field(buffer->payload.standard, "%x: ????????????%04"
			    PRIx64, pt_ipc_update_16, packet->ip);
		return (UINT32)(packet->ip & 0x0000FFFF);

	case pt_ipc_update_32:
		print_field(buffer->payload.standard, "%x: ????????%08"
			    PRIx64, pt_ipc_update_32, packet->ip);
		return (UINT32)(packet->ip & 0xFFFFFFFF);

	case pt_ipc_update_48:
		print_field(buffer->payload.standard, "%x: ????%012"
			    PRIx64, pt_ipc_update_48, packet->ip);
		return 0;

	case pt_ipc_sext_48:
		print_field(buffer->payload.standard, "%x: %016" PRIx64,
			    pt_ipc_sext_48, sext(packet->ip, 48));
		return 0;

	case pt_ipc_full:
		print_field(buffer->payload.standard, "%x: %016" PRIx64,
			    pt_ipc_full, packet->ip);
		return 0;
	}

	print_field(buffer->payload.standard, "%x: %016" PRIx64,
		    packet->ipc, packet->ip);
	return diag("bad ipc", offset, -pte_bad_packet);
}

static int print_tnt_payload(struct ptdump_buffer *buffer, uint64_t offset,
			     const struct pt_packet_tnt *packet)
{
	uint64_t tnt;
	uint8_t bits;
	char *begin, *end;

	if (!buffer || !packet)
		return diag("error printing payload", offset, -pte_internal);

	bits = packet->bit_size;
	tnt = packet->payload;

	begin = buffer->payload.extended;
	end = begin + bits;

	if (sizeof(buffer->payload.extended) < bits) {
		diag("truncating tnt payload", offset, 0);

		end = begin + sizeof(buffer->payload.extended);
	}

	for (; begin < end; ++begin, --bits)
		*begin = tnt & (1ull << (bits - 1)) ? '!' : '.';

	return 0;
}

static const char *print_exec_mode(const struct pt_packet_mode_exec *packet,
				   uint64_t offset)
{
	enum pt_exec_mode mode;

	mode = pt_get_exec_mode(packet);
	switch (mode) {
	case ptem_64bit:
		return "64-bit";

	case ptem_32bit:
		return "32-bit";

	case ptem_16bit:
		return "16-bit";

	case ptem_unknown:
		return "unknown";
	}

	diag("bad exec mode", offset, -pte_bad_packet);
	return "invalid";
}

static int print_packet(struct ptdump_buffer *buffer, uint64_t offset,
			const struct pt_packet *packet,
			struct ptdump_tracking *tracking,
			const struct ptdump_options *options,
			const struct pt_config *config,
            VPACKETS* chain)
{
	if (!buffer || !packet || !tracking || !options)
		return diag("error printing packet", offset, -pte_internal);

    UINT32 packetIP = 0;

	switch (packet->type) {
	case ppt_unknown:
		print_field(buffer->opcode, "<unknown>");
		return 0;

	case ppt_invalid:
		print_field(buffer->opcode, "<invalid>");
		return 0;

	case ppt_psb:
		print_field(buffer->opcode, "psb");

		tracking->in_header = 1;
		return 0;

	case ppt_psbend:
		print_field(buffer->opcode, "psbend");

		tracking->in_header = 0;
		return 0;

	case ppt_pad:
		print_field(buffer->opcode, "pad");

		if (options->no_pad)
			buffer->skip = 1;
		return 0;

	case ppt_ovf:
		print_field(buffer->opcode, "ovf");
		return 0;

	case ppt_stop:
		print_field(buffer->opcode, "stop");
		return 0;

	case ppt_fup:
		print_field(buffer->opcode, "fup");
		packetIP = print_ip_payload(buffer, offset, &packet->payload.ip);

        if (chain != NULL)
            chain->push_back(std::pair <pt_packet_type, UINT32>(ppt_fup, packetIP));

		if (options->show_last_ip)
			track_last_ip(buffer, &tracking->last_ip, offset,
				      &packet->payload.ip, options, config);
		return 0;

	case ppt_tip:
		print_field(buffer->opcode, "tip");
        packetIP = print_ip_payload(buffer, offset, &packet->payload.ip);

        if (chain != NULL)
            chain->push_back(std::pair <pt_packet_type, UINT32>(ppt_fup, packetIP));

		if (options->show_last_ip)
			track_last_ip(buffer, &tracking->last_ip, offset,
				      &packet->payload.ip, options, config);
		return 0;

	case ppt_tip_pge:
		print_field(buffer->opcode, "tip.pge");
		print_ip_payload(buffer, offset, &packet->payload.ip);

		if (options->show_last_ip)
			track_last_ip(buffer, &tracking->last_ip, offset,
				      &packet->payload.ip, options, config);
		if (options->no_pge_pgd)
			buffer->skip = 1;
		return 0;

	case ppt_tip_pgd:
		print_field(buffer->opcode, "tip.pgd");
		print_ip_payload(buffer, offset, &packet->payload.ip);

		if (options->show_last_ip)
			track_last_ip(buffer, &tracking->last_ip, offset,
				      &packet->payload.ip, options, config);
		if (options->no_pge_pgd)
			buffer->skip = 1;
		return 0;

	case ppt_pip:
		print_field(buffer->opcode, "pip");
		print_field(buffer->payload.standard, "%" PRIx64 "%s",
			    packet->payload.pip.cr3,
			    packet->payload.pip.nr ? ", nr" : "");

		print_field(buffer->tracking.id, "cr3");
		print_field(buffer->tracking.payload, "%016" PRIx64,
			    packet->payload.pip.cr3);
		if (options->no_pip)
			buffer->skip = 1;
		return 0;

	case ppt_vmcs:
		print_field(buffer->opcode, "vmcs");
		print_field(buffer->payload.standard, "%" PRIx64,
			    packet->payload.vmcs.base);

		print_field(buffer->tracking.id, "vmcs");
		print_field(buffer->tracking.payload, "%016" PRIx64,
			    packet->payload.vmcs.base);
		return 0;

	case ppt_tnt_8:
		print_field(buffer->opcode, "tnt.8");
		return print_tnt_payload(buffer, offset, &packet->payload.tnt);

	case ppt_tnt_64:
		print_field(buffer->opcode, "tnt.64");
		return print_tnt_payload(buffer, offset, &packet->payload.tnt);

	case ppt_mode: {
		const struct pt_packet_mode *mode;

		mode = &packet->payload.mode;
		switch (mode->leaf) {
		case pt_mol_exec: {
			const char *csd, *csl, *sep;

			csd = mode->bits.exec.csd ? "cs.d" : "";
			csl = mode->bits.exec.csl ? "cs.l" : "";

			sep = csd[0] && csl[0] ? ", " : "";

			print_field(buffer->opcode, "mode.exec");
			print_field(buffer->payload.standard, "%s%s%s",
				    csd, sep, csl);

			if (options->show_exec_mode) {
				const char *em;

				em = print_exec_mode(&mode->bits.exec, offset);
				print_field(buffer->tracking.id, "em");
				print_field(buffer->tracking.payload, "%s", em);
			}
		}
			return 0;

		case pt_mol_tsx: {
			const char *intx, *abrt, *sep;

			intx = mode->bits.tsx.intx ? "intx" : "";
			abrt = mode->bits.tsx.abrt ? "abrt" : "";

			sep = intx[0] && abrt[0] ? ", " : "";

			print_field(buffer->opcode, "mode.tsx");
			print_field(buffer->payload.standard, "%s%s%s",
				    intx, sep, abrt);
		}
			return 0;
		}

		print_field(buffer->opcode, "mode");
		print_field(buffer->payload.standard, "leaf: %x", mode->leaf);

		return diag("unknown mode leaf", offset, 0);
	}

	case ppt_tsc:
		print_field(buffer->opcode, "tsc");
		print_field(buffer->payload.standard, "%" PRIx64,
			    packet->payload.tsc.tsc);

		if (options->track_time)
			track_tsc(buffer, tracking, offset,
				  &packet->payload.tsc, options, config);

		if (options->no_timing)
			buffer->skip = 1;

		return 0;

	case ppt_cbr:
		print_field(buffer->opcode, "cbr");
		print_field(buffer->payload.standard, "%x",
			    packet->payload.cbr.ratio);

		if (options->track_time)
			track_cbr(buffer, tracking, offset,
				  &packet->payload.cbr, options, config);

		if (options->no_timing)
			buffer->skip = 1;

		return 0;

	case ppt_tma:
		print_field(buffer->opcode, "tma");
		print_field(buffer->payload.standard, "%x, %x",
			    packet->payload.tma.ctc, packet->payload.tma.fc);

		if (options->track_time)
			track_tma(buffer, tracking, offset,
				  &packet->payload.tma, options, config);

		if (options->no_timing)
			buffer->skip = 1;

		return 0;

	case ppt_mtc:
		print_field(buffer->opcode, "mtc");
		print_field(buffer->payload.standard, "%x",
			    packet->payload.mtc.ctc);

		if (options->track_time)
			track_mtc(buffer, tracking, offset,
				  &packet->payload.mtc, options, config);

		if (options->no_timing)
			buffer->skip = 1;

		return 0;

	case ppt_cyc:
		print_field(buffer->opcode, "cyc");
		print_field(buffer->payload.standard, "%" PRIx64,
			    packet->payload.cyc.value);

		if (options->track_time && !options->no_cyc)
			track_cyc(buffer, tracking, offset,
				  &packet->payload.cyc, options, config);

		if (options->no_timing || options->no_cyc)
			buffer->skip = 1;

		return 0;

	case ppt_mnt:
		print_field(buffer->opcode, "mnt");
		print_field(buffer->payload.standard, "%" PRIx64,
			    packet->payload.mnt.payload);
		return 0;
	}

	return diag("unknown packet", offset, -pte_bad_opc);
}

static int dump_one_packet(uint64_t offset, const struct pt_packet *packet,
    struct ptdump_tracking *tracking,
    const struct ptdump_options *options,
    const struct pt_config *config,
    VPACKETS* chain)
{
    struct ptdump_buffer buffer = { 0 };
    int errcode = 0;

    memset(&buffer, 0, sizeof(buffer));

    print_field(buffer.offset, "0x%08" PRIx32, (DWORD)(offset + options->offset_delta));

    if (options->show_raw_bytes) {
        errcode = print_raw(&buffer, offset, packet, config);
        if (errcode < 0)
            return errcode;
    }

    errcode = print_packet(&buffer, offset, packet, tracking, options, config, chain);

    if (errcode < 0)
        return errcode;
    else
        errcode = print_buffer(&buffer, offset, options);

    return errcode;
}

static int dump_packets(struct pt_packet_decoder *decoder,
    struct ptdump_tracking *tracking,
    const struct ptdump_options *options,
    const struct pt_config *config,
    VPACKETS* chain)
{
    uint64_t offset = 0ull;
    
    unsigned status = 0;
    unsigned FUPs = 0;
    std::vector<pt_packet> packets;
    std::vector<uint64_t> offsets;

    for (;;) {
        struct pt_packet packet;
        int errcode = 0;

        errcode = pt_pkt_get_offset(decoder, &offset);
        if (errcode < 0)
            return diag("error getting offset", offset, errcode);

        errcode = pt_pkt_next(decoder, &packet, sizeof(packet));
        if (errcode < 0) {
            if (errcode == -pte_eos)
                return 0;

            // Return the error code and restart the scan
            if (pt_errcode(errcode) != pte_bad_packet)
                return diag("error decoding packet", offset, errcode);
            else
                return errcode;
        }

        if ((chain != NULL) &&
            ((packet.type == pt_packet_type::ppt_tip)   ||
             (packet.type == pt_packet_type::ppt_fup)   ||
             (packet.type == pt_packet_type::ppt_tnt_8) ||
             (packet.type == pt_packet_type::ppt_tnt_64)||
             (packet.type == pt_packet_type::ppt_mode))) {
            if (status == 0) {
                if (packet.type == pt_packet_type::ppt_tip) {
                    packets.push_back(packet);
                    offsets.push_back(offset);
                    status = 1;
                }
            }
            else if (status == 1) {
                if (packet.type == pt_packet_type::ppt_tip) {
                    packets.push_back(packet);
                    offsets.push_back(offset);
                    status = 1;
                }
                else if (packet.type == pt_packet_type::ppt_fup) {
                    packets.push_back(packet);
                    offsets.push_back(offset);
                    ++FUPs;
                    status = 2;
                }
                else {
                    packets.clear();
                    offsets.clear();
                    status = 0;
                    FUPs = 0;
                }
            }
            else if (status == 2) {
                if (packet.type == pt_packet_type::ppt_tip) {
                    packets.push_back(packet);
                    offsets.push_back(offset);
                    status = 3;
                }
                else {
                    if ((FUPs > 2) || ((FUPs == 1) && (packets.size() > 9))) {
                        std::string text = "\n\nChain size: ";
                        text.append(std::to_string(packets.size()));
                        text.append("\n");
                        DWORD dwBytesIo = 0;
                        WriteFile(options->hTargetFile, text.c_str(), text.length(), &dwBytesIo, NULL);

                        for (unsigned index = 0; index < packets.size(); ++index) {
                            errcode = dump_one_packet(offsets[index], &packets[index], tracking, options, config, chain);

                            if (errcode < 0)
                                return diag("error printing packet", offset, errcode);
                        }
                    }
                    packets.clear();
                    offsets.clear();
                    status = 0;
                    FUPs = 0;
                }
            }
            else if (status == 3) {
                if (packet.type == pt_packet_type::ppt_fup) {
                    packets.push_back(packet);
                    offsets.push_back(offset);
                    ++FUPs;
                    status = 2;
                }
                else {
                    if (FUPs > 2) {
                        std::string text = "\n\nChain size: ";
                        text.append(std::to_string(packets.size()));
                        text.append("\n");
                        DWORD dwBytesIo = 0;
                        WriteFile(options->hTargetFile, text.c_str(), text.length(), &dwBytesIo, NULL);

                        for (unsigned index = 0; index < packets.size(); ++index) {
                            errcode = dump_one_packet(offsets[index], &packets[index], tracking, options, config, chain);

                            if (errcode < 0)
                                return diag("error printing the packet", offset, errcode);
                        }
                    }
                    packets.clear();
                    offsets.clear();
                    status = 0;
                    FUPs = 0;
                }
            }
        }
        else if (chain == NULL) { // We are asking for the packet dump into a human readable file
            errcode = dump_one_packet(offset, &packet, tracking, options, config, chain);

            if (errcode < 0)
                return diag("error printing the packet", offset, errcode);
        }
    }
    return 0;
}

static int dump_sync(struct pt_packet_decoder *decoder,
    struct ptdump_tracking *tracking,
    const struct ptdump_options *options,
    const struct pt_config *config,
    VPACKETS* chain)
{
    int errcode;

    if (!options)
        return diag("setup error", 0ull, -pte_internal);

    if (options->no_sync) {
        errcode = pt_pkt_sync_set(decoder, 0ull);
        if (errcode < 0)
            return diag("sync error", 0ull, errcode);
    }
    else {
        errcode = pt_pkt_sync_forward(decoder);
        if (errcode < 0)
            return diag("sync error", 0ull, errcode);
    }

    for (;;) {
        errcode = dump_packets(decoder, tracking, options, config, chain);
        if (!errcode)
            break;

        errcode = pt_pkt_sync_forward(decoder);
        if (errcode < 0)
            return diag("sync error", 0ull, errcode);

        ptdump_tracking_reset(tracking);
    }

    return errcode;
}

// Dump all the PT packets
static int pt_dump(const struct pt_config *config,
    const struct ptdump_options *options,
    VPACKETS* chain)
{
    struct pt_packet_decoder *decoder;
    struct ptdump_tracking tracking;
    int errcode;

    decoder = pt_pkt_alloc_decoder(config);
    if (!decoder)
        return diag("failed to allocate decoder", 0ull, 0);

    ptdump_tracking_init(&tracking);

    errcode = dump_sync(decoder, &tracking, options, config, chain);

    ptdump_tracking_fini(&tracking);
    pt_pkt_free_decoder(decoder);
    return errcode;
}

int pt_dump_config(LPBYTE lpBuff, DWORD dwBuffSize, HANDLE hOutFile, ptdump_options* options, pt_config* config, QWORD qwDelta) {
    int errcode = 0;
    
    config->size = sizeof(pt_config);
	config->begin = lpBuff;
	config->end = lpBuff + dwBuffSize;

	options->no_sync = 1;
	options->no_pad = 1;
	options->no_timing = 1;
	options->show_offset = 0;
	options->show_time_as_delta = 0;
	options->no_pge_pgd = 1;
	options->no_pip = 1;
    options->show_exec_mode = 1;
	options->offset_delta = qwDelta;
	if (hOutFile)
		options->hTargetFile = hOutFile;

	errcode = pt_cpu_errata(&config->errata, &config->cpu);
	if (errcode < 0)
		wprintf(L"failed to determine errata (error %i)", errcode);
	
	return errcode;
}

static int parse_range(const char *arg, uint64_t *begin, uint64_t *end)
{
    char *rest;

    if (!arg || !*arg)
        return 0;

    errno = 0;
    *begin = strtoull(arg, &rest, 0);
    if (errno)
        return -1;

    if (!*rest)
        return 1;

    if (*rest != '-')
        return -1;

    *end = strtoull(rest + 1, &rest, 0);
    if (errno || *rest)
        return -1;

    return 2;
}

// Load the PT binary file:
static int load_file(uint8_t **buffer, size_t *size, char *arg, const char *prog)
{
    uint64_t begin_arg, end_arg;
    uint8_t *content;
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    long fsize, begin, end;
    int range_parts;
    char *range;

    if (!buffer || !size || !arg || !prog) {
        fprintf(stderr, "%s: internal error.\n", prog ? prog : "");
        return -1;
    }

    range_parts = 0;
    begin_arg = 0ull;
    end_arg = UINT64_MAX;

    range = strrchr(arg, ':');
    if (range) {
        /* Let's try to parse an optional range suffix.
        *
        * If we can, remove it from the filename argument.
        * If we can not, assume that the ':' is part of the filename,
        * e.g. a drive letter on Windows.
        */
        range_parts = parse_range(range + 1, &begin_arg, &end_arg);
        if (range_parts <= 0) {
            begin_arg = 0ull;
            end_arg = UINT64_MAX;

            range_parts = 0;
        }
        else
            *range = 0;
    }

    errno = 0;
    hFile = CreateFileA(arg, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    //fopen_s(&file, arg, "rb");
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "%s: failed to open %s: %d.\n", prog, arg, errno);
        return -1;
    }

    fsize = SetFilePointer(hFile, 0, 0, FILE_END);
    if (fsize < 0) {
        fprintf(stderr, "%s: failed to determine size of %s: %d.\n", prog, arg, errno);
        goto err_file;
    }

    /* Truncate the range to fit into the file unless an explicit range end
    * was provided.
    */
    if (range_parts < 2)
        end_arg = (uint64_t)fsize;

    begin = (long)begin_arg;
    end = (long)end_arg;
    if ((uint64_t)begin != begin_arg || (uint64_t)end != end_arg) {
        fprintf(stderr, "%s: invalid offset/range argument.\n", prog);
        goto err_file;
    }

    if (fsize <= begin) {
        fprintf(stderr, "%s: offset 0x%lx outside of %s.\n", prog, begin, arg);
        goto err_file;
    }

    if (fsize < end) {
        fprintf(stderr, "%s: range 0x%lx outside of %s.\n", prog, end, arg);
        goto err_file;
    }

    if (end <= begin) {
        fprintf(stderr, "%s: bad range.\n", prog);
        goto err_file;
    }

    fsize = end - begin;
    SetFilePointer(hFile, begin, 0, FILE_BEGIN);

    // Use memory mapped file
    hSection = CreateFileMapping((HANDLE)hFile, NULL, PAGE_READONLY, NULL, NULL, NULL);
    content = (uint8_t*)MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, fsize);
    if (!content) {
        fprintf(stderr, "%s: failed to map the input file %s.\n", prog, arg);
        goto err_file;
    }

    __try {
        BYTE test = content[0];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        UnmapViewOfFile((LPCVOID)content);
        goto err_file;
    }

    *buffer = content;
    *size = fsize;

    // Update global data on success
    g_pt_data.hInFile = hFile;
    g_pt_data.hInSection = hSection;
    g_pt_data.lpFileContent = (LPCVOID)content;

    return 0;

err_file:
    if (hSection) CloseHandle(hSection);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return -1;
}

// Unload and free the resource of the current loaded input file
static int unload_file() {
    if (g_pt_data.lpFileContent)
        UnmapViewOfFile(g_pt_data.lpFileContent);
    if (g_pt_data.hInSection)
        CloseHandle(g_pt_data.hInSection);
    if (g_pt_data.hInFile)
        CloseHandle(g_pt_data.hInFile);
    return 0;
}

// Load the binary PT file 
static int load_pt(struct pt_config *config, char *arg, const char *prog)
{
    uint8_t *buffer;
    size_t size;
    int errcode;

    errcode = load_file(&buffer, &size, arg, prog);
    if (errcode < 0)
        return errcode;

    config->begin = buffer;
    config->end = buffer + size;

    return 0;
}

BOOL pt_dump_packets(LPBYTE lpBuff, DWORD dwBuffSize, HANDLE hOutFile, QWORD qwDelta, VPACKETS* chain) {
    int errcode = 0;
    ptdump_options options = { 0 };
    pt_config config = { 0 };

    errcode = pt_dump_config(lpBuff, dwBuffSize, hOutFile, &options, &config, qwDelta);
    
    if (errcode == 0)
        errcode = pt_dump(&config, &options, chain);
    
    return (errcode == 0);
}

BOOL pt_dump_packets(LPCWSTR lpInputFile, VPACKETS* chain, DWORD dwMaxSize) {
    HANDLE hTarget = NULL;
    CHAR binaryFileAStr[MAX_PATH] = { 0 };
    CHAR myPath[MAX_PATH] = { 0 };
    ptdump_options options = { 0 };
    pt_config config = { 0 };
    int errcode = 0;
    
    if (!lpInputFile)
        return FALSE;

    sprintf_s((char* const)binaryFileAStr, MAX_PATH, "%S", lpInputFile);
    GetModuleFileNameA(GetModuleHandle(NULL), myPath, MAX_PATH);

    errcode = load_pt(&config, binaryFileAStr, myPath);
    if (errcode < 0)
        return FALSE;

    std::wstring outFile = lpInputFile;
    outFile.append(L".log");

    if (!outFile.empty()) {
        hTarget = CreateFile(outFile.c_str(), FILE_GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTarget == INVALID_HANDLE_VALUE)
            return FALSE;
        else
            SetFilePointer(hTarget, 0, 0, FILE_END);
    }

    if (dwMaxSize == 0)
        dwMaxSize = (DWORD)(config.end - config.begin);

    errcode = pt_dump_config(config.begin, dwMaxSize, hTarget, &options, &config);

    if (errcode == 0)
        errcode = pt_dump(&config, &options, chain);

    unload_file();
    return (errcode == 0);
}