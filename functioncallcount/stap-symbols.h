static struct _stp_symbol _stp_module_0_symbols_0[] = {
};
static struct _stp_section _stp_module_0_sections[] = {
{
.name = "_stext",
.size = 0x13c0000,
.symbols = _stp_module_0_symbols_0,
.num_symbols = 0,
.debug_hdr = NULL,
.debug_hdr_len = 0,
.sec_load_offset = 0
},
};
static struct _stp_module _stp_module_0 = {
.name = "kernel",
.path = "/usr/lib/debug/usr/lib/modules/3.10.0-514.el7.x86_64/vmlinux",
.eh_frame_addr = 0x0, 
.unwind_hdr_addr = 0x0, 
.debug_frame = NULL,
.debug_frame_len = 0,
.eh_frame = NULL,
.eh_frame_len = 0,
.unwind_hdr = NULL,
.unwind_hdr_len = 0,
.debug_line = NULL,
.debug_line_len = 0,
.sections = _stp_module_0_sections,
.num_sections = sizeof(_stp_module_0_sections)/sizeof(struct _stp_section),
.build_id_bits = (unsigned char *)"\xd7\x2f\x51\xbe\xe5\x5e\xe4\xa6\xea\x6b\xdc\x37\xf3\xfa\xea\xa7\x39\x3d\x0\x6c",
.build_id_len = 20,
.build_id_offset = 0x69aec4,
.notes_sect = 0,
};


static uint8_t _stp_module_self_eh_frame [] = {0,};
static struct _stp_symbol _stp_module_self_symbols_0[] = {{0},};
static struct _stp_symbol _stp_module_self_symbols_1[] = {{0},};
static struct _stp_section _stp_module_self_sections[] = {
{.name = ".symtab", .symbols = _stp_module_self_symbols_0, .num_symbols = 0},
{.name = ".text", .symbols = _stp_module_self_symbols_1, .num_symbols = 0},
};
static struct _stp_module _stp_module_self = {
.name = "stap_self_tmp_value",
.path = "stap_self_tmp_value",
.num_sections = 2,
.sections = _stp_module_self_sections,
.eh_frame = _stp_module_self_eh_frame,
.eh_frame_len = 0,
.unwind_hdr_addr = 0x0,
.unwind_hdr = NULL,
.unwind_hdr_len = 0,
.debug_frame = NULL,
.debug_frame_len = 0,
.debug_line = NULL,
.debug_line_len = 0,
};
static struct _stp_module *_stp_modules [] = {
& _stp_module_0,
& _stp_module_self,
};
static const unsigned _stp_num_modules = ARRAY_SIZE(_stp_modules);
static unsigned long _stp_kretprobe_trampoline = -1;
