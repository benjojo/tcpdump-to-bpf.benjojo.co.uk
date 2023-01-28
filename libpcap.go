/*
 * Network packet analysis framework.
 *
 * Copyright (c) 2014, Alessandro Ghedini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

// #include <stdlib.h>
// #include "bpf_filter.h"
import "C"

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

type Filter struct {
	program C.struct_bpf_program
}

type FullFilter struct {
	OriginalFilter string
	OriginalMedia  string
	Data           *Filter
}

type Code uint16

const (
	LD   Code = syscall.BPF_LD
	LDX       = syscall.BPF_LDX
	ST        = syscall.BPF_ST
	STX       = syscall.BPF_STX
	ALU       = syscall.BPF_ALU
	JMP       = syscall.BPF_JMP
	RET       = syscall.BPF_RET
	MISC      = syscall.BPF_MISC
)

type Size uint16

const (
	Word Size = syscall.BPF_W
	Half      = syscall.BPF_H
	Byte      = syscall.BPF_B
)

type Mode uint16

const (
	IMM Mode = syscall.BPF_IMM
	ABS      = syscall.BPF_ABS
	IND      = syscall.BPF_IND
	MEM      = syscall.BPF_MEM
	LEN      = syscall.BPF_LEN
	MSH      = syscall.BPF_MSH
)

type Src uint16

const (
	Const Src = syscall.BPF_K
	Index     = syscall.BPF_X
	Acc       = syscall.BPF_A
)

// Try to match the given buffer against the filter.
func (f *Filter) Match(buf []byte) bool {
	cbuf := (*C.char)(unsafe.Pointer(&buf[0]))
	blen := C.uint(len(buf))

	if C.bpf_filter(f.program.bf_insns, cbuf, blen, blen) > 0 {
		return true
	}

	return false
}

// Run filter on the given buffer and return its result.
func (f *Filter) Filter(buf []byte) uint {
	cbuf := (*C.char)(unsafe.Pointer(&buf[0]))
	blen := C.uint(len(buf))

	rc := C.bpf_filter(f.program.bf_insns, cbuf, blen, blen)
	return uint(rc)
}

// Validate the filter. The constraints are that each jump be forward and to a
// valid code. The code must terminate with either an accept or reject.
func (f *Filter) Validate() bool {
	return C.bpf_validate(f.program.bf_insns, C.int(f.program.bf_len)) > 0
}

// Deallocate the filter.
func (f *Filter) Cleanup() {
	f.program.bf_len = 0

	if f.program.bf_insns != nil {
		C.free(unsafe.Pointer(f.program.bf_insns))
		f.program.bf_insns = nil
	}
}

// Return the number of instructions in the filter.
func (f *Filter) Len() int {
	prog := (*C.struct_bpf_program)(f.Program())
	flen := C.bpf_get_len(prog)
	return int(flen)
}

// Return the compiled BPF program.
func (f *Filter) Program() unsafe.Pointer {
	return unsafe.Pointer(&f.program)
}

func (f *Filter) String() string {
	var insns []string

	prog := (*C.struct_bpf_program)(f.Program())
	flen := C.bpf_get_len(prog)

	for i := C.int(0); i < flen; i++ {
		insn := C.bpf_get_insn(prog, i)

		str := fmt.Sprintf(
			"{ 0x%.2x, %3d, %3d, 0x%.8x },",
			insn.code, insn.jt, insn.jf, insn.k,
		)

		insns = append(insns, str)
	}

	return strings.Join(insns, "\n")
}

func (f *Filter) append_insn(code Code, jt, jf uint8, k uint32) {
	prog := (*C.struct_bpf_program)(f.Program())
	C.bpf_append_insn(
		prog, C.ushort(code), C.uchar(jt), C.uchar(jf), C.uint(k),
	)
}

func (f *Filter) Export() SaneBPFOpcodes {
	output := make([]BPFopcode, 0)

	prog := (*C.struct_bpf_program)(f.Program())
	flen := C.bpf_get_len(prog)

	for i := C.int(0); i < flen; i++ {
		insn := C.bpf_get_insn(prog, i)

		output = append(output, BPFopcode{
			Code: uint16(insn.code),
			JT:   uint8(insn.jt),
			JF:   uint8(insn.jf),
			K:    uint32(insn.k),
		})

	}

	return output
}

type SaneBPFOpcodes []BPFopcode

func (f FullFilter) ToIptables() string {
	d := f.Data.Export()

	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("%d, ", len(d)))

	for _, v := range d {
		sb.WriteString(fmt.Sprintf("%d %d %d %d,", v.Code, v.JT, v.JF, v.K))
	}

	trimedFilter := LimitStringSize(f.OriginalFilter)
	command := ""

	switch f.OriginalMedia {
	case "IPv4":
		command = "iptables -I INPUT"
	case "IPv6":
		command = "ip6tables -I INPUT"
	}

	return fmt.Sprintf("# %v -m bpf --bytecode \"%v\" -j DROP -m comment --comment \"%v\"", command, sb.String(), trimedFilter)
}

/*

type _Ctype_struct_bpf_insn struct {
	code	_Ctype_ushort
	jt	_Ctype_uchar
	jf	_Ctype_uchar
	k	_Ctype_uint
}

*/
type BPFopcode struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

// Type represents the protocol of a packet.
type Type uint16

const (
	None Type = iota
	ARP
	Bluetooth /* TODO */
	Eth
	GRE /* TODO */
	ICMPv4
	ICMPv6
	IGMP  /* TODO */
	IPSec /* TODO */
	IPv4
	IPv6
	ISIS /* TODO */
	L2TP /* TODO */
	LLC
	LLDP     /* TODO */
	OSPF     /* TODO */
	RadioTap /* TODO */
	Raw
	SCTP /* TODO */
	SLL
	SNAP
	TCP
	TRILL /* TODO */
	UDP
	UDPLite /* TODO */
	VLAN
	WiFi /* TODO */
	WoL  /* TODO */
)

func LimitStringSize(in string) string {
	in = strings.Trim(in, "\r\n\t ")

	if len(in) < 250 {
		return in
	}

	dotted := make([]rune, 0)

	_ = strings.Map(
		func(r rune) rune {
			if len(string(dotted)) < 250 {
				dotted = append(dotted, r)
			}
			return r
		},
		in)

	return string(dotted) + "..."
}
