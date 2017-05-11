
#include "sgx_tsgxssl_t.h"

// Following enum is copied from /usr/include/ctype.h.
// It is used to populate the ascii_ctype table below.
// We need to match this enum since we build the openssl with this header
#define _ISbit(bit)	((bit) < 8 ? ((1 << (bit)) << 8) : ((1 << (bit)) >> 8))

enum
{
  _ISupper = _ISbit (0),	/* UPPERCASE.  */
  _ISlower = _ISbit (1),	/* lowercase.  */
  _ISalpha = _ISbit (2),	/* Alphabetic.  */
  _ISdigit = _ISbit (3),	/* Numeric.  */
  _ISxdigit = _ISbit (4),	/* Hexadecimal numeric.  */
  _ISspace = _ISbit (5),	/* Whitespace.  */
  _ISprint = _ISbit (6),	/* Printing.  */
  _ISgraph = _ISbit (7),	/* Graphical.  */
  _ISblank = _ISbit (8),	/* Blank (usually SPC and TAB).  */
  _IScntrl = _ISbit (9),	/* Control character.  */
  _ISpunct = _ISbit (10),	/* Punctuation.  */
  _ISalnum = _ISbit (11)	/* Alphanumeric.  */
};

#define ___ISupper (_ISalnum | _ISalpha | _ISupper)
#define ___ISlower (_ISalnum | _ISalpha | _ISlower)
#define ___ISdigit (_ISalnum | _ISdigit | _ISxdigit)

#define ASCII_CHARS_NUM 384

// The table below defines the "C" type of character for each ascii character
// see table at http://www.cplusplus.com/reference/cctype/ for details
const unsigned short int ascii_ctype[ASCII_CHARS_NUM] = {
		0, 0, 0, 0, 0, 0, 0, 0, 			// -128
        0, 0, 0, 0, 0, 0, 0, 0, 			// -120
        0, 0, 0, 0, 0, 0, 0, 0, 			// -112
        0, 0, 0, 0, 0, 0, 0, 0, 			// -104
        0, 0, 0, 0, 0, 0, 0, 0, 			// -96
        0, 0, 0, 0, 0, 0, 0, 0, 			// -88
        0, 0, 0, 0, 0, 0, 0, 0, 			// -80
        0, 0, 0, 0, 0, 0, 0, 0, 			// -72
        0, 0, 0, 0, 0, 0, 0, 0, 			// -64
        0, 0, 0, 0, 0, 0, 0, 0, 			// -56
        0, 0, 0, 0, 0, 0, 0, 0, 			// -48
        0, 0, 0, 0, 0, 0, 0, 0, 			// -40
        0, 0, 0, 0, 0, 0, 0, 0, 			// -32
        0, 0, 0, 0, 0, 0, 0, 0, 			// -24
        0, 0, 0, 0, 0, 0, 0, 0, 			// -16
        0, 0, 0, 0, 0, 0, 0, 0, 			// -8
        _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, // 0x0-0x7
        _IScntrl, _IScntrl|_ISblank|_ISspace, _IScntrl|_ISspace, _IScntrl|_ISspace, _IScntrl|_ISspace, _IScntrl|_ISspace, _IScntrl, _IScntrl, // 0x8-0xf
        _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, // 0x10 - 0x17
        _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, _IScntrl, // 0x18 - 0x1f
		_ISspace|_ISblank, _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, // 0x20 - 0x27
        _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, // 0x28 - 0x2f
        ___ISdigit, ___ISdigit, ___ISdigit, ___ISdigit, ___ISdigit, ___ISdigit, ___ISdigit, ___ISdigit, // 0x30 - 0x37
        ___ISdigit, ___ISdigit,  _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, // 0x38 - 0x3f
        _ISpunct, ___ISupper|_ISxdigit, ___ISupper|_ISxdigit, ___ISupper|_ISxdigit, ___ISupper|_ISxdigit, ___ISupper|_ISxdigit, ___ISupper|_ISxdigit, ___ISupper, // 0x40 - 0x47
        ___ISupper, ___ISupper, ___ISupper, ___ISupper, ___ISupper, ___ISupper, ___ISupper, ___ISupper, // 0x48 - 0x4f
        ___ISupper, ___ISupper, ___ISupper, ___ISupper, ___ISupper, ___ISupper, ___ISupper, ___ISupper, // 0x50 - 0x57
        ___ISupper, ___ISupper, ___ISupper, _ISpunct, _ISpunct, _ISpunct, _ISpunct, _ISpunct, // 0x58 - 0x5f
        _ISpunct, ___ISlower|_ISxdigit, ___ISlower|_ISxdigit, ___ISlower|_ISxdigit, ___ISlower|_ISxdigit, ___ISlower|_ISxdigit, ___ISlower|_ISxdigit, ___ISlower, // 0x60 - 0x67
        ___ISlower, ___ISlower, ___ISlower, ___ISlower, ___ISlower, ___ISlower, ___ISlower, ___ISlower, // 0x68 - 0x6f
        ___ISlower, ___ISlower, ___ISlower, ___ISlower, ___ISlower, ___ISlower, ___ISlower, ___ISlower, // 0x70 - 0x77
        ___ISlower, ___ISlower, ___ISlower, _ISpunct, _ISpunct, _ISpunct, _ISpunct, _IScntrl, // 0x78 - 0x7f
        0, 0, 0, 0, 0, 0, 0, 0, 			// 128
        0, 0, 0, 0, 0, 0, 0, 0, 			// 136
        0, 0, 0, 0, 0, 0, 0, 0, 			// 144
        0, 0, 0, 0, 0, 0, 0, 0, 			// 152
        0, 0, 0, 0, 0, 0, 0, 0, 			// 160
        0, 0, 0, 0, 0, 0, 0, 0, 			// 168
        0, 0, 0, 0, 0, 0, 0, 0, 			// 176
        0, 0, 0, 0, 0, 0, 0, 0, 			// 184
        0, 0, 0, 0, 0, 0, 0, 0, 			// 192
        0, 0, 0, 0, 0, 0, 0, 0, 			// 200
        0, 0, 0, 0, 0, 0, 0, 0, 			// 208
        0, 0, 0, 0, 0, 0, 0, 0, 			// 216
        0, 0, 0, 0, 0, 0, 0, 0, 			// 224
        0, 0, 0, 0, 0, 0, 0, 0, 			// 232
        0, 0, 0, 0, 0, 0, 0, 0, 			// 240
        0, 0, 0, 0, 0, 0, 0, 0, 			// 248
};

static const int32_t ascii_to_lower[ASCII_CHARS_NUM] = {
		0, 0, 0, 0, 0, 0, 0, 0, 			// -128
        0, 0, 0, 0, 0, 0, 0, 0, 			// -120
        0, 0, 0, 0, 0, 0, 0, 0, 			// -112
        0, 0, 0, 0, 0, 0, 0, 0, 			// -104
        0, 0, 0, 0, 0, 0, 0, 0, 			// -96
        0, 0, 0, 0, 0, 0, 0, 0, 			// -88
        0, 0, 0, 0, 0, 0, 0, 0, 			// -80
        0, 0, 0, 0, 0, 0, 0, 0, 			// -72
        0, 0, 0, 0, 0, 0, 0, 0, 			// -64
        0, 0, 0, 0, 0, 0, 0, 0, 			// -56
        0, 0, 0, 0, 0, 0, 0, 0, 			// -48
        0, 0, 0, 0, 0, 0, 0, 0, 			// -40
        0, 0, 0, 0, 0, 0, 0, 0, 			// -32
        0, 0, 0, 0, 0, 0, 0, 0, 			// -24
        0, 0, 0, 0, 0, 0, 0, 0, 			// -16
        0, 0, 0, 0, 0, 0, 0, 0, 			// -8
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15,
		16 , 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31,
		32, 33, 34, 35, 36, 37, 38, 39,
		40, 41, 42, 43, 44, 45, 46, 47,
		48, 49, 50, 51, 52, 53, 54, 55,
		56, 57, 58, 59, 60, 61, 62, 63,
		64, 'a','b','c','d','e','f','g',
		'h','i','j','k','l','m','n','o',
		'p','q','r','s','t','u','v','w',
		'x','y','z', 91, 92, 93, 94, 95,
		96, 'a','b','c','d','e','f','g',
		'h','i','j','k','l','m', 'n','o',
		'p','q','r','s','t','u','v','w',
		'x','y','z', 123,124,125,126,127,
        0, 0, 0, 0, 0, 0, 0, 0, 			// 128
        0, 0, 0, 0, 0, 0, 0, 0, 			// 136
        0, 0, 0, 0, 0, 0, 0, 0, 			// 144
        0, 0, 0, 0, 0, 0, 0, 0, 			// 152
        0, 0, 0, 0, 0, 0, 0, 0, 			// 160
        0, 0, 0, 0, 0, 0, 0, 0, 			// 168
        0, 0, 0, 0, 0, 0, 0, 0, 			// 176
        0, 0, 0, 0, 0, 0, 0, 0, 			// 184
        0, 0, 0, 0, 0, 0, 0, 0, 			// 192
        0, 0, 0, 0, 0, 0, 0, 0, 			// 200
        0, 0, 0, 0, 0, 0, 0, 0, 			// 208
        0, 0, 0, 0, 0, 0, 0, 0, 			// 216
        0, 0, 0, 0, 0, 0, 0, 0, 			// 224
        0, 0, 0, 0, 0, 0, 0, 0, 			// 232
        0, 0, 0, 0, 0, 0, 0, 0, 			// 240
        0, 0, 0, 0, 0, 0, 0, 0, 			// 248
};


extern "C" {

const unsigned short int * ascii_ctype_tb = &ascii_ctype[128];
const int32_t * ascii_to_lower_tb = &ascii_to_lower[128];

const unsigned short int ** sgxssl___ctype_b_loc (void)
{
	return &ascii_ctype_tb;
}

const int32_t **sgxssl___ctype_tolower_loc (void)
{
	return &ascii_to_lower_tb;
}

}

