// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

#define Neg2p11 0xC000E147AE147AE1
#define Pos15   0x402E

// Minimax polynomial coefficients and other constants
DATA ·erfcrodataL38<> + 0(SB)/8, $.234875460637085087E-01
DATA ·erfcrodataL38<> + 8(SB)/8, $.234469449299256284E-01
DATA ·erfcrodataL38<> + 16(SB)/8, $-.606918710392844955E-04
DATA ·erfcrodataL38<> + 24(SB)/8, $-.198827088077636213E-04
DATA ·erfcrodataL38<> + 32(SB)/8, $.257805645845475331E-06
DATA ·erfcrodataL38<> + 40(SB)/8, $-.184427218110620284E-09
DATA ·erfcrodataL38<> + 48(SB)/8, $.122408098288933181E-10
DATA ·erfcrodataL38<> + 56(SB)/8, $.484691106751495392E-07
DATA ·erfcrodataL38<> + 64(SB)/8, $-.150147637632890281E-08
DATA ·erfcrodataL38<> + 72(SB)/8, $23.999999999973521625
DATA ·erfcrodataL38<> + 80(SB)/8, $27.226017111108365754
DATA ·erfcrodataL38<> + 88(SB)/8, $-2.0
DATA ·erfcrodataL38<> + 96(SB)/8, $0.100108802034478228E+00
DATA ·erfcrodataL38<> + 104(SB)/8, $0.244588413746558125E+00
DATA ·erfcrodataL38<> + 112(SB)/8, $-.669188879646637174E-01
DATA ·erfcrodataL38<> + 120(SB)/8, $0.151311447000953551E-01
DATA ·erfcrodataL38<> + 128(SB)/8, $-.284720833493302061E-02
DATA ·erfcrodataL38<> + 136(SB)/8, $0.455491239358743212E-03
DATA ·erfcrodataL38<> + 144(SB)/8, $-.631850539280720949E-04
DATA ·erfcrodataL38<> + 152(SB)/8, $0.772532660726086679E-05
DATA ·erfcrodataL38<> + 160(SB)/8, $-.843706007150936940E-06
DATA ·erfcrodataL38<> + 168(SB)/8, $-.735330214904227472E-08
DATA ·erfcrodataL38<> + 176(SB)/8, $0.753002008837084967E-09
DATA ·erfcrodataL38<> + 184(SB)/8, $0.832482036660624637E-07
DATA ·erfcrodataL38<> + 192(SB)/8, $-0.75
DATA ·erfcrodataL38<> + 200(SB)/8, $.927765678007128609E-01
DATA ·erfcrodataL38<> + 208(SB)/8, $.903621209344751506E-01
DATA ·erfcrodataL38<> + 216(SB)/8, $-.344203375025257265E-02
DATA ·erfcrodataL38<> + 224(SB)/8, $-.869243428221791329E-03
DATA ·erfcrodataL38<> + 232(SB)/8, $.174699813107105603E-03
DATA ·erfcrodataL38<> + 240(SB)/8, $.649481036316130000E-05
DATA ·erfcrodataL38<> + 248(SB)/8, $-.895265844897118382E-05
DATA ·erfcrodataL38<> + 256(SB)/8, $.135970046909529513E-05
DATA ·erfcrodataL38<> + 264(SB)/8, $.277617717014748015E-06
DATA ·erfcrodataL38<> + 272(SB)/8, $.810628018408232910E-08
DATA ·erfcrodataL38<> + 280(SB)/8, $.210430084693497985E-07
DATA ·erfcrodataL38<> + 288(SB)/8, $-.342138077525615091E-08
DATA ·erfcrodataL38<> + 296(SB)/8, $-.165467946798610800E-06
DATA ·erfcrodataL38<> + 304(SB)/8, $5.999999999988412824
DATA ·erfcrodataL38<> + 312(SB)/8, $.468542210149072159E-01
DATA ·erfcrodataL38<> + 320(SB)/8, $.465343528567604256E-01
DATA ·erfcrodataL38<> + 328(SB)/8, $-.473338083650201733E-03
DATA ·erfcrodataL38<> + 336(SB)/8, $-.147220659069079156E-03
DATA ·erfcrodataL38<> + 344(SB)/8, $.755284723554388339E-05
DATA ·erfcrodataL38<> + 352(SB)/8, $.116158570631428789E-05
DATA ·erfcrodataL38<> + 360(SB)/8, $-.155445501551602389E-06
DATA ·erfcrodataL38<> + 368(SB)/8, $-.616940119847805046E-10
DATA ·erfcrodataL38<> + 376(SB)/8, $-.728705590727563158E-10
DATA ·erfcrodataL38<> + 384(SB)/8, $-.983452460354586779E-08
DATA ·erfcrodataL38<> + 392(SB)/8, $.365156164194346316E-08
DATA ·erfcrodataL38<> + 400(SB)/8, $11.999999999996530775
DATA ·erfcrodataL38<> + 408(SB)/8, $0.467773498104726584E-02
DATA ·erfcrodataL38<> + 416(SB)/8, $0.206669853540920535E-01
DATA ·erfcrodataL38<> + 424(SB)/8, $0.413339707081841473E-01
DATA ·erfcrodataL38<> + 432(SB)/8, $0.482229658262131320E-01
DATA ·erfcrodataL38<> + 440(SB)/8, $0.344449755901841897E-01
DATA ·erfcrodataL38<> + 448(SB)/8, $0.130890907240765465E-01
DATA ·erfcrodataL38<> + 456(SB)/8, $-.459266344100642687E-03
DATA ·erfcrodataL38<> + 464(SB)/8, $-.337888800856913728E-02
DATA ·erfcrodataL38<> + 472(SB)/8, $-.159103061687062373E-02
DATA ·erfcrodataL38<> + 480(SB)/8, $-.501128905515922644E-04
DATA ·erfcrodataL38<> + 488(SB)/8, $0.262775855852903132E-03
DATA ·erfcrodataL38<> + 496(SB)/8, $0.103860982197462436E-03
DATA ·erfcrodataL38<> + 504(SB)/8, $-.548835785414200775E-05
DATA ·erfcrodataL38<> + 512(SB)/8, $-.157075054646618214E-04
DATA ·erfcrodataL38<> + 520(SB)/8, $-.480056366276045110E-05
DATA ·erfcrodataL38<> + 528(SB)/8, $0.198263013759701555E-05
DATA ·erfcrodataL38<> + 536(SB)/8, $-.224394262958888780E-06
DATA ·erfcrodataL38<> + 544(SB)/8, $-.321853693146683428E-06
DATA ·erfcrodataL38<> + 552(SB)/8, $0.445073894984683537E-07
DATA ·erfcrodataL38<> + 560(SB)/8, $0.660425940000555729E-06
DATA ·erfcrodataL38<> + 568(SB)/8, $2.0
DATA ·erfcrodataL38<> + 576(SB)/8, $8.63616855509444462538e-78
DATA ·erfcrodataL38<> + 584(SB)/8, $1.00000000000000222044
DATA ·erfcrodataL38<> + 592(SB)/8, $0.500000000000004237e+00
DATA ·erfcrodataL38<> + 600(SB)/8, $0.416666664838056960e-01
DATA ·erfcrodataL38<> + 608(SB)/8, $0.166666666630345592e+00
DATA ·erfcrodataL38<> + 616(SB)/8, $0.138926439368309441e-02
DATA ·erfcrodataL38<> + 624(SB)/8, $0.833349307718286047e-02
DATA ·erfcrodataL38<> + 632(SB)/8, $-.693147180558298714e+00
DATA ·erfcrodataL38<> + 640(SB)/8, $-.164659495826017651e-11
DATA ·erfcrodataL38<> + 648(SB)/8, $.179001151181866548E+00
DATA ·erfcrodataL38<> + 656(SB)/8, $-.144269504088896339e+01
DATA ·erfcrodataL38<> + 664(SB)/8, $+281475245147134.9375
DATA ·erfcrodataL38<> + 672(SB)/8, $.163116780021877404E+00
DATA ·erfcrodataL38<> + 680(SB)/8, $-.201574395828120710E-01
DATA ·erfcrodataL38<> + 688(SB)/8, $-.185726336009394125E-02
DATA ·erfcrodataL38<> + 696(SB)/8, $.199349204957273749E-02
DATA ·erfcrodataL38<> + 704(SB)/8, $-.554902415532606242E-03
DATA ·erfcrodataL38<> + 712(SB)/8, $-.638914789660242846E-05
DATA ·erfcrodataL38<> + 720(SB)/8, $-.424441522653742898E-04
DATA ·erfcrodataL38<> + 728(SB)/8, $.827967511921486190E-04
DATA ·erfcrodataL38<> + 736(SB)/8, $.913965446284062654E-05
DATA ·erfcrodataL38<> + 744(SB)/8, $.277344791076320853E-05
DATA ·erfcrodataL38<> + 752(SB)/8, $-.467239678927239526E-06
DATA ·erfcrodataL38<> + 760(SB)/8, $.344814065920419986E-07
DATA ·erfcrodataL38<> + 768(SB)/8, $-.366013491552527132E-05
DATA ·erfcrodataL38<> + 776(SB)/8, $.181242810023783439E-05
DATA ·erfcrodataL38<> + 784(SB)/8, $2.999999999991234567
DATA ·erfcrodataL38<> + 792(SB)/8, $1.0
GLOBL ·erfcrodataL38<> + 0(SB), RODATA, $800

// Table of log correction terms
DATA ·erfctab2069<> + 0(SB)/8, $0.442737824274138381e-01
DATA ·erfctab2069<> + 8(SB)/8, $0.263602189790660309e-01
DATA ·erfctab2069<> + 16(SB)/8, $0.122565642281703586e-01
DATA ·erfctab2069<> + 24(SB)/8, $0.143757052860721398e-02
DATA ·erfctab2069<> + 32(SB)/8, $-.651375034121276075e-02
DATA ·erfctab2069<> + 40(SB)/8, $-.119317678849450159e-01
DATA ·erfctab2069<> + 48(SB)/8, $-.150868749549871069e-01
DATA ·erfctab2069<> + 56(SB)/8, $-.161992609578469234e-01
DATA ·erfctab2069<> + 64(SB)/8, $-.154492360403337917e-01
DATA ·erfctab2069<> + 72(SB)/8, $-.129850717389178721e-01
DATA ·erfctab2069<> + 80(SB)/8, $-.892902649276657891e-02
DATA ·erfctab2069<> + 88(SB)/8, $-.338202636596794887e-02
DATA ·erfctab2069<> + 96(SB)/8, $0.357266307045684762e-02
DATA ·erfctab2069<> + 104(SB)/8, $0.118665304327406698e-01
DATA ·erfctab2069<> + 112(SB)/8, $0.214434994118118914e-01
DATA ·erfctab2069<> + 120(SB)/8, $0.322580645161290314e-01
GLOBL ·erfctab2069<> + 0(SB), RODATA, $128

// Erfc returns the complementary error function of the argument.
//
// Special cases are:
//      Erfc(+Inf) = 0
//      Erfc(-Inf) = 2
//      Erfc(NaN) = NaN
// The algorithm used is minimax polynomial approximation
// with coefficients determined with a Remez exchange algorithm.
// This assembly implementation handles inputs in the range [-2.11, +15].
// For all other inputs we call the generic Go implementation.

TEXT	·erfcAsm(SB), NOSPLIT|NOFRAME, $0-16
	MOVD	x+0(FP), R1
	MOVD	$Neg2p11, R2
	CMPUBGT	R1, R2, usego

	FMOVD	x+0(FP), F0
	MOVD	$·erfcrodataL38<>+0(SB), R9
	FMOVD	F0, F2
	SRAD	$48, R1
	MOVH	R1, R2
	ANDW	$0x7FFF, R1
	MOVH	$Pos15, R3
	CMPW	R1, R3
	BGT	usego
	MOVH	$0x3FFF, R3
	MOVW	R1, R6
	MOVW	R3, R7
	CMPBGT	R6, R7, L2
	MOVH	$0x3FEF, R3
	MOVW	R3, R7
	CMPBGT	R6, R7, L3
	MOVH	$0x2FFF, R2
	MOVW	R2, R7
	CMPBGT	R6, R7, L4
	FMOVD	792(R9), F0
	WFSDB	V2, V0, V2
	FMOVD	F2, ret+8(FP)
	RET

L2:
	LTDBR	F0, F0
	MOVH	$0x0, R4
	BLTU	L3
	FMOVD	F0, F1
L9:
	MOVH	$0x400F, R3
	MOVW	R1, R6
	MOVW	R3, R7
	CMPBGT	R6, R7, L10
	FMOVD	784(R9), F3
	FSUB	F1, F3
	VLEG	$0, 776(R9), V20
	WFDDB	V1, V3, V6
	VLEG	$0, 768(R9), V18
	FMOVD	760(R9), F7
	FMOVD	752(R9), F5
	VLEG	$0, 744(R9), V16
	FMOVD	736(R9), F3
	FMOVD	728(R9), F2
	FMOVD	720(R9), F4
	WFMDB	V6, V6, V1
	FMUL	F0, F0
	MOVH	$0x0, R3
	WFMADB	V1, V7, V20, V7
	WFMADB	V1, V5, V18, V5
	WFMADB	V1, V7, V16, V7
	WFMADB	V1, V5, V3, V5
	WFMADB	V1, V7, V4, V7
	WFMADB	V1, V5, V2, V5
	FMOVD	712(R9), F2
	WFMADB	V1, V7, V2, V7
	FMOVD	704(R9), F2
	WFMADB	V1, V5, V2, V5
	FMOVD	696(R9), F2
	WFMADB	V1, V7, V2, V7
	FMOVD	688(R9), F2
	MOVH	$0x0, R1
	WFMADB	V1, V5, V2, V5
	FMOVD	680(R9), F2
	WFMADB	V1, V7, V2, V7
	FMOVD	672(R9), F2
	WFMADB	V1, V5, V2, V1
	FMOVD	664(R9), F3
	WFMADB	V6, V7, V1, V7
	FMOVD	656(R9), F5
	FMOVD	648(R9), F2
	WFMADB	V0, V5, V3, V5
	WFMADB	V6, V7, V2, V7
L11:
	LGDR	F5, R6
	WFSDB	V0, V0, V2
	WORD	$0xED509298	//sdb	%f5,.L55-.L38(%r9)
	BYTE	$0x00
	BYTE	$0x1B
	FMOVD	640(R9), F6
	FMOVD	632(R9), F4
	WFMSDB	V5, V6, V2, V6
	WFMSDB	V5, V4, V0, V4
	FMOVD	624(R9), F2
	FADD	F6, F4
	FMOVD	616(R9), F0
	FMOVD	608(R9), F6
	WFMADB	V4, V0, V2, V0
	FMOVD	600(R9), F3
	WFMDB	V4, V4, V2
	MOVH	R6,R6
	ADD	R6, R3
	WFMADB	V4, V3, V6, V3
	FMOVD	592(R9), F6
	WFMADB	V0, V2, V3, V0
	FMOVD	584(R9), F3
	WFMADB	V4, V6, V3, V6
	RISBGZ	$57, $60, $3, R3, R12
	WFMADB	V2, V0, V6, V0
	MOVD	$·erfctab2069<>+0(SB), R5
	WORD	$0x682C5000	//ld	%f2,0(%r12,%r5)
	FMADD	F2, F4, F4
	RISBGN	$0, $15, $48, R3, R4
	WFMADB	V4, V0, V2, V4
	LDGR	R4, F2
	FMADD	F4, F2, F2
	MOVW	R2, R6
	CMPBLE	R6, $0, L20
	MOVW	R1, R6
	CMPBEQ	R6, $0, L21
	WORD	$0xED709240	//mdb	%f7,.L66-.L38(%r9)
	BYTE	$0x00
	BYTE	$0x1C
L21:
	FMUL	F7, F2
L1:
	FMOVD	F2, ret+8(FP)
	RET
L3:
	LTDBR	F0, F0
	BLTU	L30
	FMOVD	568(R9), F2
	WFSDB	V0, V2, V0
L8:
	WFMDB	V0, V0, V4
	FMOVD	560(R9), F2
	FMOVD	552(R9), F6
	FMOVD	544(R9), F1
	WFMADB	V4, V6, V2, V6
	FMOVD	536(R9), F2
	WFMADB	V4, V1, V2, V1
	FMOVD	528(R9), F3
	FMOVD	520(R9), F2
	WFMADB	V4, V6, V3, V6
	WFMADB	V4, V1, V2, V1
	FMOVD	512(R9), F3
	FMOVD	504(R9), F2
	WFMADB	V4, V6, V3, V6
	WFMADB	V4, V1, V2, V1
	FMOVD	496(R9), F3
	FMOVD	488(R9), F2
	WFMADB	V4, V6, V3, V6
	WFMADB	V4, V1, V2, V1
	FMOVD	480(R9), F3
	FMOVD	472(R9), F2
	WFMADB	V4, V6, V3, V6
	WFMADB	V4, V1, V2, V1
	FMOVD	464(R9), F3
	FMOVD	456(R9), F2
	WFMADB	V4, V6, V3, V6
	WFMADB	V4, V1, V2, V1
	FMOVD	448(R9), F3
	FMOVD	440(R9), F2
	WFMADB	V4, V6, V3, V6
	WFMADB	V4, V1, V2, V1
	FMOVD	432(R9), F3
	FMOVD	424(R9), F2
	WFMADB	V4, V6, V3, V6
	WFMADB	V4, V1, V2, V1
	FMOVD	416(R9), F3
	FMOVD	408(R9), F2
	WFMADB	V4, V6, V3, V6
	FMADD	F1, F4, F2
	FMADD	F6, F0, F2
	MOVW	R2, R6
	CMPBGE	R6, $0, L1
	FMOVD	568(R9), F0
	WFSDB	V2, V0, V2
	BR	L1
L10:
	MOVH	$0x401F, R3
	MOVW	R1, R6
	MOVW	R3, R7
	CMPBLE	R6, R7, L36
	MOVH	$0x402F, R3
	MOVW	R3, R7
	CMPBGT	R6, R7, L13
	FMOVD	400(R9), F3
	FSUB	F1, F3
	VLEG	$0, 392(R9), V20
	WFDDB	V1, V3, V6
	VLEG	$0, 384(R9), V18
	FMOVD	376(R9), F2
	FMOVD	368(R9), F4
	VLEG	$0, 360(R9), V16
	FMOVD	352(R9), F7
	FMOVD	344(R9), F3
	FMUL	F0, F0
	WFMDB	V6, V6, V1
	FMOVD	656(R9), F5
	MOVH	$0x0, R3
	WFMADB	V1, V2, V20, V2
	WFMADB	V1, V4, V18, V4
	WFMADB	V1, V2, V16, V2
	WFMADB	V1, V4, V7, V4
	WFMADB	V1, V2, V3, V2
	FMOVD	336(R9), F3
	WFMADB	V1, V4, V3, V4
	FMOVD	328(R9), F3
	WFMADB	V1, V2, V3, V2
	FMOVD	320(R9), F3
	WFMADB	V1, V4, V3, V1
	FMOVD	312(R9), F7
	WFMADB	V6, V2, V1, V2
	MOVH	$0x0, R1
	FMOVD	664(R9), F3
	FMADD	F2, F6, F7
	WFMADB	V0, V5, V3, V5
	BR	L11
L35:
	WORD	$0xB3130010	//lcdbr	%f1,%f0
	BR	L9
L36:
	FMOVD	304(R9), F3
	FSUB	F1, F3
	VLEG	$0, 296(R9), V20
	WFDDB	V1, V3, V6
	FMOVD	288(R9), F5
	FMOVD	280(R9), F1
	FMOVD	272(R9), F2
	VLEG	$0, 264(R9), V18
	VLEG	$0, 256(R9), V16
	FMOVD	248(R9), F3
	FMOVD	240(R9), F4
	WFMDB	V6, V6, V7
	FMUL	F0, F0
	MOVH	$0x0, R3
	FMADD	F5, F7, F1
	WFMADB	V7, V2, V20, V2
	WFMADB	V7, V1, V18, V1
	WFMADB	V7, V2, V16, V2
	WFMADB	V7, V1, V3, V1
	WFMADB	V7, V2, V4, V2
	FMOVD	232(R9), F4
	WFMADB	V7, V1, V4, V1
	FMOVD	224(R9), F4
	WFMADB	V7, V2, V4, V2
	FMOVD	216(R9), F4
	WFMADB	V7, V1, V4, V1
	FMOVD	208(R9), F4
	MOVH	$0x0, R1
	WFMADB	V7, V2, V4, V7
	FMOVD	656(R9), F5
	WFMADB	V6, V1, V7, V1
	FMOVD	664(R9), F3
	FMOVD	200(R9), F7
	WFMADB	V0, V5, V3, V5
	FMADD	F1, F6, F7
	BR	L11
L4:
	FMOVD	192(R9), F1
	FMADD	F0, F0, F1
	FMOVD	184(R9), F3
	WFMDB	V1, V1, V0
	FMOVD	176(R9), F4
	FMOVD	168(R9), F6
	WFMADB	V0, V4, V3, V4
	FMOVD	160(R9), F3
	WFMADB	V0, V6, V3, V6
	FMOVD	152(R9), F5
	FMOVD	144(R9), F3
	WFMADB	V0, V4, V5, V4
	WFMADB	V0, V6, V3, V6
	FMOVD	136(R9), F5
	FMOVD	128(R9), F3
	WFMADB	V0, V4, V5, V4
	WFMADB	V0, V6, V3, V6
	FMOVD	120(R9), F5
	FMOVD	112(R9), F3
	WFMADB	V0, V4, V5, V4
	WFMADB	V0, V6, V3, V6
	FMOVD	104(R9), F5
	FMOVD	96(R9), F3
	WFMADB	V0, V4, V5, V4
	WFMADB	V0, V6, V3, V0
	FMOVD	F2, F6
	FMADD	F4, F1, F0
	WORD	$0xED609318	//sdb	%f6,.L39-.L38(%r9)
	BYTE	$0x00
	BYTE	$0x1B
	WFMSDB	V2, V0, V6, V2
	FMOVD	F2, ret+8(FP)
	RET
L30:
	WORD	$0xED009238	//adb	%f0,.L67-.L38(%r9)
	BYTE	$0x00
	BYTE	$0x1A
	BR	L8
L20:
	FMOVD	88(R9), F0
	WFMADB	V7, V2, V0, V2
	WORD	$0xB3130022	//lcdbr	%f2,%f2
	FMOVD	F2, ret+8(FP)
	RET
L13:
	MOVH	$0x403A, R3
	MOVW	R1, R6
	MOVW	R3, R7
	CMPBLE	R6, R7, L4
	WORD	$0xED109050	//cdb	%f1,.L128-.L38(%r9)
	BYTE	$0x00
	BYTE	$0x19
	BGE	L37
	BVS	L37
	FMOVD	72(R9), F6
	FSUB	F1, F6
	MOVH	$0x1000, R3
	FDIV	F1, F6
	MOVH	$0x1000, R1
L17:
	WFMDB	V6, V6, V1
	FMOVD	64(R9), F2
	FMOVD	56(R9), F4
	FMOVD	48(R9), F3
	WFMADB	V1, V3, V2, V3
	FMOVD	40(R9), F2
	WFMADB	V1, V2, V4, V2
	FMOVD	32(R9), F4
	WFMADB	V1, V3, V4, V3
	FMOVD	24(R9), F4
	WFMADB	V1, V2, V4, V2
	FMOVD	16(R9), F4
	WFMADB	V1, V3, V4, V3
	FMOVD	8(R9), F4
	WFMADB	V1, V2, V4, V1
	FMUL	F0, F0
	WFMADB	V3, V6, V1, V3
	FMOVD	656(R9), F5
	FMOVD	664(R9), F4
	FMOVD	0(R9), F7
	WFMADB	V0, V5, V4, V5
	FMADD	F6, F3, F7
	BR	L11
L14:
	FMOVD	72(R9), F6
	FSUB	F1, F6
	MOVH	$0x403A, R3
	FDIV	F1, F6
	MOVW	R1, R6
	MOVW	R3, R7
	CMPBEQ	R6, R7, L23
	MOVH	$0x0, R3
	MOVH	$0x0, R1
	BR	L17
L37:
	WFCEDBS	V0, V0, V0
	BVS	L1
	MOVW	R2, R6
	CMPBLE	R6, $0, L18
	MOVH	$0x7FEF, R2
	MOVW	R1, R6
	MOVW	R2, R7
	CMPBGT	R6, R7, L24

	WORD	$0xA5400010	//iihh	%r4,16
	LDGR	R4, F2
	FMUL	F2, F2
	BR	L1
L23:
	MOVH	$0x1000, R3
	MOVH	$0x1000, R1
	BR	L17
L24:
	FMOVD	$0, F2
	BR	L1
L18:
	MOVH	$0x7FEF, R2
	MOVW	R1, R6
	MOVW	R2, R7
	CMPBGT	R6, R7, L25
	WORD	$0xA5408010	//iihh	%r4,32784
	FMOVD	568(R9), F2
	LDGR	R4, F0
	FMADD	F2, F0, F2
	BR	L1
L25:
	FMOVD	568(R9), F2
	BR	L1
usego:
	BR	·erfc(SB)
