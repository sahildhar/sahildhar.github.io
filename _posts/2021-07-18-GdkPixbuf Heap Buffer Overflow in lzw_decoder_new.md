---
layout: post
title:  "GdkPixbuf - Heap Buffer Overflow in lzw_decoder_new"
tag: advisory
excerpt_separator: <!--more-->

---

The GdkPixbuf library is vulnerable to heap-buffer overflow vulnerability when decoding the lzw compressed stream of image data in GIF files with lzw minimum code size equals to 12.  
<!--more-->


### **Affected versions**
 - 2.42.6 (latest)

### **Gitlab Advisory URL**
 - https://gitlab.gnome.org/GNOME/gdk-pixbuf/-/issues/136

### **Technical details**
When parsing the Image Data section of GIF files with lzw minimum code size equals to 12, the library miscalculates the maximum indexes the `LZWDecoder->code_table`  can have, overwriting the `LZWDecoder->code_table_size` in `_LZWDecoder` structure.

In the following code snippets, we can observe that the LZW_CODE_MAX is set to 12 at line:28 in gdk-pixbuf/lzw.h which when left shifted at line:22 in gdk-pixbuf/lzw.c will yield MAX_CODES value to 4096. This means that the LZW decoding operations ideally should always write to maximum 4096 indexes of LZWDecoder->code_table. 

file gdk-pixbif/lzw.h
```C
27:/* Maximum code size in bits */
28:#define LZW_CODE_MAX 12
```

file: gdk-pixbuf/lzw.c
```c
21: /* Maximum number of codes */
22:#define MAX_CODES (1 << LZW_CODE_MAX)
23:
24:typedef struct
25:{
26:        /* Last index this code represents */
27:        guint8 index;
28:
29:        /* Codeword of previous index or the EOI code if doesn't extend */
30:        guint16 extends;
31:} LZWCode;
32:
33:struct _LZWDecoder
34:{
35:        GObject parent_instance;
36:
37:        /* Initial code size */
38:        int min_code_size;
39:
40:        /* Current code size */
41:        int code_size;
42:
43:        /* Code table and special codes */
44:        int clear_code;
45:        int eoi_code;
46:        LZWCode code_table[MAX_CODES];
47:        int code_table_size;
48:
49:        /* Current code being assembled */
50:        int code;
51:        int code_bits;
52:
53:        /* Last code processed */
54:        int last_code;
55:};
```

The following code snippets shows that the library first initializes the `lzw_decoder` object by calling `lzw_decoder_new` function wih the user controlled `frame->lzw_code_size` value at line:339 in gdk-pixbuf/io-gif-animation.c. 

When the value of `frame->lzw_code_size` is set to 12 (0xc), the `lzw_decoder_new` gets called with the code_size value equals to 13, which ultimately sets the value of `self->eoi_code` (end of information) to 4097 at line:131 in gdk-pixbuf/lzw.c, thus writing the values to overall 4098 indexes instead of predefined 4096 at line:133-137 in gdk-pixbuf/lzw.c.

file: gdk-pixbuf/io-gif-animation.c
```c
317:static void
318:composite_frame (GdkPixbufGifAnim *anim, GdkPixbufFrame *frame)
319:{
320:        LZWDecoder *lzw_decoder = NULL;
.
.
.
338:
339:        lzw_decoder = lzw_decoder_new (frame->lzw_code_size + 1);
340:        index_buffer = g_new (guint8, frame->width * frame->height);
``` 


file: gdk-pixbuf/lzw.c
```c
118:LZWDecoder *
119:lzw_decoder_new (guint8 code_size)
120:{
121:        LZWDecoder *self;
122:        int i;
123:
124:        self = g_object_new (lzw_decoder_get_type (), NULL);
125:
126:        self->min_code_size = code_size;
127:        self->code_size = code_size;
128:
129:        /* Add special clear and end of information codes */
130:        self->clear_code = 1 << (code_size - 1);
131:        self->eoi_code = self->clear_code + 1;
132:
133:        for (i = 0; i <= self->eoi_code; i++) {
134:                self->code_table[i].index = i;
135:                self->code_table[i].extends = self->eoi_code;
136:                self->code_table_size++;
137:        }
138:
139:        /* Start with an empty codeword following an implicit clear codeword */
140:        self->code = 0;
141:        self->last_code = self->clear_code;
142:
143:        return self;
144:}
``` 

### **Dynamic Analysis**

With the following gdb output, we can confirm that the `lzw_decoder_new` function writes to two more indexes than predefined 4096 indexes of `LZWDecoder->code_table` and thus overwrites the value of `LZWDecoder->code_table_size` from 4096 to 268505089.

```sh
$43 = 4096
$44 = (int *) 0x629000018228
0x629000018228:	0x0000000000001000
$45 = 4096

Breakpoint 4, lzw_decoder_new (code_size=13 '\r') at ../gdk-pixbuf/lzw.c:134
134	                self->code_table[i].index = i;
(gdb) c
Continuing.
$46 = 4097
$47 = (int *) 0x629000018228
0x629000018228:	0x0000000010011001
$48 = 268505089

Breakpoint 4, lzw_decoder_new (code_size=13 '\r') at ../gdk-pixbuf/lzw.c:134
134	                self->code_table[i].index = i;
(gdb) c
Continuing.
$49 = 4098
$50 = (int *) 0x629000018228
0x629000018228:	0x1001000110011002
$51 = 268505090

Breakpoint 7, lzw_decoder_new (code_size=13 '\r') at ../gdk-pixbuf/lzw.c:140
140	        self->code = 0;
```


### **Steps to reproduce**

1. Compile the gdk-pixbuf with address sanitizer.
2. Execute the gdk-pixbuf/gdk-pixbuf-pixdata binary with the accompanied heap-buffer-overflow.gif file as follows and observed the ASAN dump:

command:

```bash
./gdk-pixbuf/gdk-pixbuf-pixdata ../../gdk-pixbuf/poc/heap_buffer_overflow.gif /tmp/bbbb
```

ASAN Dump:
```
==5565==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x62900001336a at pc 0x00000053b142 bp 0x7fffc5dd1200 sp 0x7fffc5dd11f8
READ of size 2 at 0x62900001336a thread T0
    #0 0x53b141 in write_indexes /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/lzw.c:88:36
    #1 0x53a8d9 in lzw_decoder_feed /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/lzw.c:212:46
    #2 0x5374c1 in composite_frame /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/io-gif-animation.c:364:21
    #3 0x5351ed in gdk_pixbuf_gif_anim_iter_get_pixbuf /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/io-gif-animation.c:421:17
    #4 0x5347bf in gdk_pixbuf_gif_anim_get_static_image /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/io-gif-animation.c:117:16
    #5 0x58e217 in gdk_pixbuf_animation_get_static_image /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/gdk-pixbuf-animation.c:586:16
    #6 0x532d08 in gif_get_lzw /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/io-gif.c:522:24
    #7 0x52caf7 in gif_main_loop /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/io-gif.c:821:13
    #8 0x52b370 in gdk_pixbuf__gif_image_load_increment /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/io-gif.c:1013:11
    #9 0x503404 in gdk_pixbuf_loader_load_module /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/gdk-pixbuf-loader.c:467:16
    #10 0x502127 in gdk_pixbuf_loader_close /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/gdk-pixbuf-loader.c:835:25
    #11 0x581dbb in gdk_pixbuf__qtif_image_load /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/io-qtif.c:217:21
    #12 0x4f47ec in _gdk_pixbuf_generic_image_load /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/gdk-pixbuf-io.c:1064:26
    #13 0x4f502b in gdk_pixbuf_new_from_file /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/gdk-pixbuf-io.c:1135:18
    #14 0x4efee7 in main /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/gdk-pixbuf-pixdata.c:77:12
    #15 0x7fe6f0e7582f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #16 0x41e518 in _start (/root/gdk-pixbuf-poc/_build/gdk-pixbuf/gdk-pixbuf-pixdata+0x41e518)

0x62900001336a is located 306 bytes to the right of 16440-byte region [0x62900000f200,0x629000013238)
allocated by thread T0 here:
    #0 0x4be648 in malloc (/root/gdk-pixbuf-poc/_build/gdk-pixbuf/gdk-pixbuf-pixdata+0x4be648)
    #1 0x7fe6f297e7b8 in g_malloc (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x4f7b8)

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/gdk-pixbuf-poc/_build/../gdk-pixbuf/lzw.c:88:36 in write_indexes
Shadow bytes around the buggy address:
  0x0c527fffa610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c527fffa620: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c527fffa630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c527fffa640: 00 00 00 00 00 00 00 fa fa fa fa fa fa fa fa fa
  0x0c527fffa650: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0c527fffa660: fa fa fa fa fa fa fa fa fa fa fa fa fa[fa]fa fa
  0x0c527fffa670: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c527fffa680: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c527fffa690: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c527fffa6a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c527fffa6b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==5565==ABORTING
```
